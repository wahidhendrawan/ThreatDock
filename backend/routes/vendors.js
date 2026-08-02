const express = require('express');
const { requireRole } = require('../services/identity');
const { auditLog } = require('../services/audit');

module.exports = function createVendorsRouter(db) {
  const router = express.Router();

  router.get('/', requireRole('viewer'), (req, res) => {
    db.all('SELECT * FROM vendors WHERE tenant_id = ? ORDER BY risk_score DESC', [req.tenant_id], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      return res.json(rows || []);
    });
  });

  router.post('/', requireRole('editor'), (req, res) => {
    const { name, category, risk_score, contact, notes } = req.body || {};
    if (!name || !String(name).trim()) return res.status(400).json({ error: 'Vendor name is required' });
    db.run(
      `INSERT INTO vendors (tenant_id, name, category, risk_score, contact, notes)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [req.tenant_id, String(name).trim(), category || null, risk_score || 0, contact || null, notes || null],
      async function onInsert(err) {
        if (err) return res.status(400).json({ error: err.message });
        await auditLog(db, { tenant_id: req.tenant_id, actor: req.user, event_name: 'vendor_created', status: 'success', metadata: { vendor_id: this.lastID, name } });
        return res.status(201).json({ id: this.lastID });
      }
    );
  });

  router.post('/:id/assess', requireRole('editor'), (req, res) => {
    db.get('SELECT * FROM vendors WHERE id = ? AND tenant_id = ?', [req.params.id, req.tenant_id], (findErr, vendor) => {
      if (findErr) return res.status(500).json({ error: findErr.message });
      if (!vendor) return res.status(404).json({ error: 'Vendor not found' });
      const keyword = `%${vendor.name}%`;
      db.all(
        `SELECT id, source, "externalId", title, severity, date, url FROM alerts
         WHERE tenant_id = ? AND (lower(title) LIKE lower(?) OR lower("externalId") LIKE lower(?) OR lower(source) LIKE lower(?))
         ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END, date DESC
         LIMIT 100`,
        [req.tenant_id, keyword, keyword, keyword],
        (alertErr, alerts) => {
          if (alertErr) return res.status(500).json({ error: alertErr.message });
          const matches = alerts || [];
          const score = Math.min(100, matches.reduce((acc, alert) => acc + (alert.severity === 'Critical' ? 20 : alert.severity === 'High' ? 12 : alert.severity === 'Medium' ? 6 : alert.severity === 'Low' ? 2 : 1), 0));
          const notes = `Assessment found ${matches.length} direct intelligence matches for "${vendor.name}" across security feeds.`;
          db.run(
            'UPDATE vendors SET risk_score = ?, last_assessment = CURRENT_TIMESTAMP, notes = ? WHERE id = ? AND tenant_id = ?',
            [score, notes, vendor.id, req.tenant_id],
            async updateErr => {
              if (updateErr) return res.status(500).json({ error: updateErr.message });
              await auditLog(db, { tenant_id: req.tenant_id, actor: req.user, event_name: 'vendor_assessed', status: 'success', metadata: { vendor_id: vendor.id, matches: matches.length, score } });
              return res.json({ id: vendor.id, risk_score: score, notes, matches: matches.map(alert => ({ ...alert, tprm_context: `Intelligence match: ${alert.source} reported risk matching ${vendor.name}` })) });
            }
          );
        }
      );
    });
  });

  router.patch('/:id', requireRole('editor'), (req, res) => {
    const { status, risk_score, last_assessment, notes } = req.body || {};
    const updates = [];
    const params = [];
    if (status !== undefined) { updates.push('status = ?'); params.push(status); }
    if (risk_score !== undefined) { updates.push('risk_score = ?'); params.push(risk_score); }
    if (last_assessment !== undefined) { updates.push('last_assessment = ?'); params.push(last_assessment); }
    if (notes !== undefined) { updates.push('notes = ?'); params.push(notes); }
    if (!updates.length) return res.json({ success: true });
    params.push(req.params.id, req.tenant_id);
    db.run(`UPDATE vendors SET ${updates.join(', ')} WHERE id = ? AND tenant_id = ?`, params, async function onUpdate(err) {
      if (err) return res.status(500).json({ error: err.message });
      if (!this.changes) return res.status(404).json({ error: 'Vendor not found' });
      await auditLog(db, { tenant_id: req.tenant_id, actor: req.user, event_name: 'vendor_updated', status: 'success', metadata: { vendor_id: req.params.id } });
      return res.json({ updated: this.changes });
    });
  });

  router.delete('/:id', requireRole('admin'), (req, res) => {
    db.run('DELETE FROM vendors WHERE id = ? AND tenant_id = ?', [req.params.id, req.tenant_id], async function onDelete(err) {
      if (err) return res.status(500).json({ error: err.message });
      if (!this.changes) return res.status(404).json({ error: 'Vendor not found' });
      await auditLog(db, { tenant_id: req.tenant_id, actor: req.user, event_name: 'vendor_deleted', status: 'success', metadata: { vendor_id: req.params.id } });
      return res.json({ deleted: this.changes });
    });
  });

  return router;
};
