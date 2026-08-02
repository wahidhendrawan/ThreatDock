const express = require('express');
const { requireRole } = require('../services/identity');
const { auditLog } = require('../services/audit');

module.exports = function createIngestionRouter(db, options = {}) {
  const { fetchAllSources } = options;
  const router = express.Router();

  // Source health and ingestion runs are global operational data, but require
  // an authenticated viewer role to prevent unauthorised operational insight.
  router.get('/health', requireRole('viewer'), (req, res) => {
    db.all('SELECT * FROM source_health ORDER BY source ASC', [], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      return res.json(rows || []);
    });
  });

  router.get('/runs', requireRole('viewer'), (req, res) => {
    const limit = Math.min(Math.max(1, parseInt(req.query.limit || '100', 10) || 100), 500);
    db.all('SELECT * FROM ingestion_runs ORDER BY started_at DESC LIMIT ?', [limit], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      return res.json(rows || []);
    });
  });

  router.get('/audit', requireRole('admin'), (req, res) => {
    const limit = Math.min(Math.max(1, parseInt(req.query.limit || '100', 10) || 100), 500);
    db.all(
      'SELECT * FROM audit_logs WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?',
      [req.tenant_id, limit],
      (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        return res.json(rows || []);
      }
    );
  });

  // POST /fetch — manually trigger a global source fetch. The resulting alerts
  // are persisted to the application default tenant by the background worker.
  router.post('/fetch', requireRole('admin'), (req, res) => {
    if (!fetchAllSources) return res.status(500).json({ error: 'Fetch function not available' });
    fetchAllSources().catch(err => console.error('Manual fetch error:', err));
    auditLog(db, {
      tenant_id: req.tenant_id,
      actor: req.user,
      event_name: 'ingestion_fetch_requested',
      status: 'success'
    }).catch(() => {});
    return res.json({ message: 'Source fetch started' });
  });

  return router;
};
