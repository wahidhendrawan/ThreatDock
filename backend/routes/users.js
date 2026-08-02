const express = require('express');
const bcrypt = require('bcryptjs');
const { generateSecret, generateURI, verifySync } = require('otplib');
const qrcode = require('qrcode');
const { requireRole, normalizeRole, normalizeRoles } = require('../services/identity');
const { auditLog } = require('../services/audit');

const dbGet = (db, sql, params = []) => new Promise((resolve, reject) => {
  db.get(sql, params, (err, row) => err ? reject(err) : resolve(row || null));
});
const dbRun = (db, sql, params = []) => new Promise((resolve, reject) => {
  db.run(sql, params, function onRun(err) {
    if (err) return reject(err);
    resolve({ lastID: this.lastID, changes: this.changes });
  });
});

const verifyMfaCode = (code, secret) => {
  if (!/^\d{6}$/.test(String(code || ''))) return false;
  const result = verifySync({ token: String(code), secret, window: 0 });
  return Boolean(result && result.valid === true);
};

function legacyRole(role) {
  return role === 'admin' ? 'Admin' : role === 'analyst' ? 'Analyst' : 'Viewer';
}

module.exports = function createUsersRouter(db) {
  const router = express.Router();

  router.get('/list/simple', requireRole('viewer'), (req, res) => {
    db.all('SELECT username FROM users WHERE tenant_id = ? ORDER BY username ASC', [req.tenant_id], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      return res.json((rows || []).map(row => row.username));
    });
  });

  router.get('/', requireRole('admin'), (req, res) => {
    db.all(
      `SELECT id, username, email, role, roles, auth_provider, mfa_enabled, created_at
       FROM users WHERE tenant_id = ? ORDER BY username`,
      [req.tenant_id],
      (err, rows) => err ? res.status(500).json({ error: 'Database error' }) : res.json(rows || [])
    );
  });

  router.post('/', requireRole('admin'), async (req, res) => {
    const { username, password, email } = req.body || {};
    const canonicalRole = normalizeRole(req.body && req.body.role) || normalizeRoles(req.body && req.body.roles)[0] || 'viewer';
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    try {
      const hash = bcrypt.hashSync(password, 10);
      const roles = JSON.stringify([canonicalRole]);
      const result = await dbRun(
        db,
        `INSERT INTO users (tenant_id, username, password_hash, email, role, roles, auth_provider)
         VALUES (?, ?, ?, ?, ?, ?, 'local')`,
        [req.tenant_id, String(username).trim(), hash, email || null, legacyRole(canonicalRole), roles]
      );
      await auditLog(db, {
        tenant_id: req.tenant_id,
        actor: req.user,
        event_name: 'user_created',
        status: 'success',
        metadata: { target_user_id: result.lastID, username, roles: [canonicalRole] }
      });
      return res.status(201).json({ id: result.lastID, username, email: email || null, role: legacyRole(canonicalRole), roles: [canonicalRole] });
    } catch (err) {
      if (String(err.message).includes('UNIQUE')) return res.status(400).json({ error: 'Username already exists' });
      return res.status(500).json({ error: 'Database error' });
    }
  });

  router.patch('/:id', requireRole('admin'), async (req, res) => {
    const id = Number.parseInt(req.params.id, 10);
    const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
    const canonicalRole = normalizeRole(req.body.role) || normalizeRoles(req.body.roles)[0];
    if (!username) return res.status(400).json({ error: 'Username is required' });
    if (!canonicalRole) return res.status(400).json({ error: 'Invalid role' });
    try {
      const before = await dbGet(db, 'SELECT id, username, email, role, roles FROM users WHERE id = ? AND tenant_id = ?', [id, req.tenant_id]);
      if (!before) return res.status(404).json({ error: 'User not found' });
      await dbRun(
        db,
        'UPDATE users SET username = ?, email = ?, role = ?, roles = ? WHERE id = ? AND tenant_id = ?',
        [username, req.body.email || null, legacyRole(canonicalRole), JSON.stringify([canonicalRole]), id, req.tenant_id]
      );
      await auditLog(db, {
        tenant_id: req.tenant_id,
        actor: req.user,
        event_name: 'user_updated',
        status: 'success',
        metadata: { target_user_id: id, before, after: { username, email: req.body.email || null, roles: [canonicalRole] } }
      });
      return res.json({ success: true, id, username, email: req.body.email || null, role: legacyRole(canonicalRole), roles: [canonicalRole] });
    } catch (err) {
      if (String(err.message).includes('UNIQUE')) return res.status(400).json({ error: 'Username already exists' });
      return res.status(500).json({ error: 'Database error' });
    }
  });

  router.patch('/:id/role', requireRole('admin'), async (req, res) => {
    const id = Number.parseInt(req.params.id, 10);
    const canonicalRole = normalizeRole(req.body && req.body.role) || normalizeRoles(req.body && req.body.roles)[0];
    if (!canonicalRole) return res.status(400).json({ error: 'Invalid role' });
    try {
      const user = await dbGet(db, 'SELECT id, role, roles FROM users WHERE id = ? AND tenant_id = ?', [id, req.tenant_id]);
      if (!user) return res.status(404).json({ error: 'User not found' });
      await dbRun(db, 'UPDATE users SET role = ?, roles = ? WHERE id = ? AND tenant_id = ?', [legacyRole(canonicalRole), JSON.stringify([canonicalRole]), id, req.tenant_id]);
      await auditLog(db, { tenant_id: req.tenant_id, actor: req.user, event_name: 'user_roles_updated', status: 'success', metadata: { target_user_id: id, roles: [canonicalRole] } });
      return res.json({ success: true, id, role: legacyRole(canonicalRole), roles: [canonicalRole] });
    } catch {
      return res.status(500).json({ error: 'Database error' });
    }
  });

  router.delete('/:id', requireRole('admin'), async (req, res) => {
    const id = Number.parseInt(req.params.id, 10);
    if (id === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account' });
    try {
      const result = await dbRun(db, 'DELETE FROM users WHERE id = ? AND tenant_id = ?', [id, req.tenant_id]);
      if (!result.changes) return res.status(404).json({ error: 'User not found' });
      await auditLog(db, { tenant_id: req.tenant_id, actor: req.user, event_name: 'user_deleted', status: 'success', metadata: { target_user_id: id } });
      return res.json({ success: true, deleted: result.changes });
    } catch {
      return res.status(500).json({ error: 'Database error' });
    }
  });

  router.post('/:id/mfa/setup', requireRole('viewer'), async (req, res) => {
    const id = Number.parseInt(req.params.id, 10);
    const isAdmin = normalizeRoles(req.user.roles).includes('admin');
    if (req.user.id !== id && !isAdmin) return res.status(403).json({ error: 'Unauthorized' });
    try {
      const user = await dbGet(db, 'SELECT id, username FROM users WHERE id = ? AND tenant_id = ?', [id, req.tenant_id]);
      if (!user) return res.status(404).json({ error: 'User not found' });
      const secret = generateSecret();
      const qrCodeUrl = await qrcode.toDataURL(generateURI({ accountName: user.username, issuer: 'ThreatDock', secret }));
      await dbRun(db, 'UPDATE users SET mfa_secret = ?, mfa_enabled = 0 WHERE id = ? AND tenant_id = ?', [secret, id, req.tenant_id]);
      await auditLog(db, { tenant_id: req.tenant_id, actor: req.user, event_name: 'mfa_setup', status: 'success', metadata: { target_user_id: id } });
      return res.json({ secret, qrCodeUrl });
    } catch {
      return res.status(500).json({ error: 'Failed to configure MFA' });
    }
  });

  router.post('/:id/mfa/enable', requireRole('viewer'), async (req, res) => {
    const id = Number.parseInt(req.params.id, 10);
    const isAdmin = normalizeRoles(req.user.roles).includes('admin');
    if (req.user.id !== id && !isAdmin) return res.status(403).json({ error: 'Unauthorized' });
    try {
      const user = await dbGet(db, 'SELECT id, mfa_secret FROM users WHERE id = ? AND tenant_id = ?', [id, req.tenant_id]);
      if (!user || !user.mfa_secret) return res.status(400).json({ error: 'MFA not configured' });
      if (!verifyMfaCode(req.body && req.body.code, user.mfa_secret)) {
        await auditLog(db, { tenant_id: req.tenant_id, actor: req.user, event_name: 'mfa_enable', status: 'failure', metadata: { target_user_id: id } });
        return res.status(400).json({ error: 'Invalid verification code' });
      }
      await dbRun(db, 'UPDATE users SET mfa_enabled = 1 WHERE id = ? AND tenant_id = ?', [id, req.tenant_id]);
      await auditLog(db, { tenant_id: req.tenant_id, actor: req.user, event_name: 'mfa_enable', status: 'success', metadata: { target_user_id: id } });
      return res.json({ success: true, message: 'MFA successfully enabled' });
    } catch {
      return res.status(500).json({ error: 'Database error' });
    }
  });

  router.delete('/:id/mfa', requireRole('admin'), async (req, res) => {
    const id = Number.parseInt(req.params.id, 10);
    try {
      const result = await dbRun(db, 'UPDATE users SET mfa_secret = NULL, mfa_enabled = 0 WHERE id = ? AND tenant_id = ?', [id, req.tenant_id]);
      if (!result.changes) return res.status(404).json({ error: 'User not found' });
      await auditLog(db, { tenant_id: req.tenant_id, actor: req.user, event_name: 'mfa_disabled', status: 'success', metadata: { target_user_id: id } });
      return res.json({ success: true, id, mfa_enabled: 0 });
    } catch {
      return res.status(500).json({ error: 'Database error' });
    }
  });

  return router;
};
