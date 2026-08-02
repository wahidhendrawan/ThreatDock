const express = require('express');
const settingsStore = require('../services/settingsStore');
const dbUtil = require('../services/db');
const { requireRole } = require('../services/identity');
const { auditLog } = require('../services/audit');

module.exports = function(db) {
  const router = express.Router();

  // GET /api/settings
  router.get('/', requireRole('viewer'), async (req, res) => {
    try {
            res.json(settingsStore.maskSecrets(await settingsStore.getSettings(db)));
    } catch {
      res.status(500).json({ error: 'Database error' });
    }
  });

  // PUT /api/settings
  router.put('/', requireRole('admin'), async (req, res) => {
    const tenantId = req.tenant_id;
    const settings = req.body;
    if (!settings || Array.isArray(settings) || typeof settings !== 'object') {
      return res.status(400).json({ error: 'Invalid settings format' });
    }

    try {
      const rows = await dbUtil.all(db, 'SELECT key, value FROM settings');
      const before = {};
      const existingKeys = new Set();
      rows.forEach(row => {
        existingKeys.add(row.key);
        before[row.key] = settingsStore.decryptValue(row.value);
      });
      const actor = req.user ? req.user.name || req.user.email || 'Admin' : 'Admin';
      const changedEntries = Object.entries(settings).filter(([key, value]) => {
        // Skip [redacted] placeholder — frontend sends this for unchanged secrets
        if (String(value ?? '') === '[redacted]') return false;
        return !existingKeys.has(key) || String(value ?? '') !== String(before[key] ?? '');
      });

      if (changedEntries.length === 0) {
        return res.json({ message: 'No settings changed' });
      }

      const beforeChanged = {};
      const afterChanged = {};
      changedEntries.forEach(([key, value]) => {
        beforeChanged[key] = before[key] ?? '';
        afterChanged[key] = value ?? '';
      });

      await dbUtil.transaction(db, async (txDb) => {
        const stmt = await dbUtil.prepare(txDb, `
          INSERT INTO settings (key, value, updated_at)
          VALUES (?, ?, CURRENT_TIMESTAMP)
          ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = CURRENT_TIMESTAMP
        `);
        try {
          for (const [key, value] of changedEntries) {
            await dbUtil.runStatement(stmt, [key, settingsStore.prepareSettingValue(key, value)]);
          }
        } finally {
          await dbUtil.finalize(stmt);
        }

        await auditLog(txDb, {
          tenant_id: tenantId,
          actor: req.user,
          event_name: 'settings_updated',
          status: 'success',
          metadata: {
            before: settingsStore.maskSecrets(beforeChanged),
            after: settingsStore.maskSecrets(afterChanged)
          }
        });
      });

      res.json({ message: 'Settings updated successfully' });
    } catch (err) {
      console.error('Failed to save settings:', err.message);
      const locked = String(err.message || '').includes('SQLITE_BUSY');
      res.status(locked ? 503 : 500).json({
        error: locked ? 'Database is busy, try again shortly' : 'Failed to save settings'
      });
    }
  });

  return router;
};
