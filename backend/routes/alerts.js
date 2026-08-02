const express = require('express');
const { requireRole } = require('../services/identity');
const { auditLog, actorName } = require('../services/audit');

/** Tenant-isolated alert triage and discussion routes. */
module.exports = function createAlertsRouter(db) {
  const router = express.Router();

  router.get('/', requireRole('viewer'), (req, res) => {
    const { severity, source, start, end, status, search: rawSearch, page: rawPage, limit: rawLimit } = req.query;
    const conditions = ['tenant_id = ?'];
    const params = [req.tenant_id];
    if (severity) { conditions.push('severity = ?'); params.push(severity); }
    if (source) { conditions.push('source = ?'); params.push(source); }
    if (start) { conditions.push('date >= ?'); params.push(start); }
    if (end) { conditions.push('date <= ?'); params.push(end); }
    if (status) { conditions.push('status = ?'); params.push(status); }
    if (rawSearch) {
      conditions.push('(title LIKE ? OR "externalId" LIKE ? OR source LIKE ?)');
      const value = `%${rawSearch}%`;
      params.push(value, value, value);
    }
    const where = ` WHERE ${conditions.join(' AND ')}`;
    const order = ` ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END, date DESC`;
    const hasPagination = rawPage !== undefined || rawLimit !== undefined;
    if (!hasPagination) {
      return db.all(`SELECT * FROM alerts${where}${order}`, params, (err, rows) => {
        if (err) return res.status(500).json({ error: 'Internal server error' });
        return res.json(rows || []);
      });
    }
    const page = Math.max(1, Number.parseInt(rawPage, 10) || 1);
    const limit = Math.min(500, Math.max(1, Number.parseInt(rawLimit, 10) || 100));
    const offset = (page - 1) * limit;
    return db.get(`SELECT COUNT(*) AS count FROM alerts${where}`, params, (countErr, countRow) => {
      if (countErr) return res.status(500).json({ error: 'Internal server error' });
      db.all(`SELECT * FROM alerts${where}${order} LIMIT ? OFFSET ?`, [...params, limit, offset], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Internal server error' });
        return res.json({ data: rows || [], total: Number(countRow && countRow.count) || 0, page, limit });
      });
    });
  });

  router.patch('/:id', requireRole('editor'), (req, res) => {
    const allowed = ['status', 'assignee', 'priority', 'sla_due', 'tags', 'case_summary', 'attack_phase'];
    const updates = [];
    const params = [];
    for (const field of allowed) {
      if (req.body[field] !== undefined) {
        updates.push(`${field} = ?`);
        params.push(field === 'tags' && Array.isArray(req.body[field]) ? JSON.stringify(req.body[field]) : req.body[field]);
      }
    }
    if (!updates.length) return res.status(400).json({ error: 'No supported alert fields provided' });
    db.get('SELECT * FROM alerts WHERE id = ? AND tenant_id = ?', [req.params.id, req.tenant_id], (findErr, before) => {
      if (findErr) return res.status(500).json({ error: findErr.message });
      if (!before) return res.status(404).json({ error: 'Alert not found' });
      updates.push('updated_at = CURRENT_TIMESTAMP');
      db.run(`UPDATE alerts SET ${updates.join(', ')} WHERE id = ? AND tenant_id = ?`, [...params, req.params.id, req.tenant_id], err => {
        if (err) return res.status(500).json({ error: 'Internal server error' });
        db.get('SELECT * FROM alerts WHERE id = ? AND tenant_id = ?', [req.params.id, req.tenant_id], async (loadErr, after) => {
          if (loadErr) return res.status(500).json({ error: loadErr.message });
          await auditLog(db, { tenant_id: req.tenant_id, actor: req.user, event_name: 'alert_updated', status: 'success', metadata: { alert_id: req.params.id, before, after } });
          return res.json(after);
        });
      });
    });
  });

  router.get('/:id/comments', requireRole('viewer'), (req, res) => {
    const sql = `SELECT c.* FROM alert_comments c JOIN alerts a ON a.id = c.alert_id
                 WHERE c.alert_id = ? AND a.tenant_id = ? ORDER BY c.created_at ASC`;
    db.all(sql, [req.params.id, req.tenant_id], (err, rows) => err ? res.status(500).json({ error: err.message }) : res.json(rows || []));
  });

  router.post('/:id/comments', requireRole('editor'), (req, res) => {
    const body = String(req.body.body || '').trim();
    if (!body) return res.status(400).json({ error: 'Comment body is required' });
    db.get('SELECT id FROM alerts WHERE id = ? AND tenant_id = ?', [req.params.id, req.tenant_id], (findErr, alert) => {
      if (findErr) return res.status(500).json({ error: findErr.message });
      if (!alert) return res.status(404).json({ error: 'Alert not found' });
      db.run('INSERT INTO alert_comments (alert_id, "user", body) VALUES (?, ?, ?)', [alert.id, actorName(req.user), body], async function onInsert(err) {
        if (err) return res.status(500).json({ error: err.message });
        await auditLog(db, { tenant_id: req.tenant_id, actor: req.user, event_name: 'alert_comment_created', status: 'success', metadata: { alert_id: alert.id, comment_id: this.lastID } });
        return res.status(201).json({ id: this.lastID, alert_id: alert.id, user: actorName(req.user), body });
      });
    });
  });

  router.get('/:id/history', requireRole('viewer'), (req, res) => {
    db.all(`SELECT * FROM audit_logs WHERE tenant_id = ? AND entity_type = 'alert' AND entity_id = ? ORDER BY created_at DESC LIMIT 100`, [req.tenant_id, String(req.params.id)], (err, rows) => err ? res.status(500).json({ error: err.message }) : res.json(rows || []));
  });

  router.delete('/:id/comments/:commentId', requireRole('editor'), (req, res) => {
    const sql = `DELETE FROM alert_comments WHERE id = ? AND alert_id = ?
                 AND EXISTS (SELECT 1 FROM alerts WHERE id = ? AND tenant_id = ?)`;
    db.run(sql, [req.params.commentId, req.params.id, req.params.id, req.tenant_id], async function onDelete(err) {
      if (err) return res.status(500).json({ error: err.message });
      if (!this.changes) return res.status(404).json({ error: 'Comment not found' });
      await auditLog(db, { tenant_id: req.tenant_id, actor: req.user, event_name: 'alert_comment_deleted', status: 'success', metadata: { alert_id: req.params.id, comment_id: req.params.commentId } });
      return res.json({ success: true });
    });
  });

  return router;
};
