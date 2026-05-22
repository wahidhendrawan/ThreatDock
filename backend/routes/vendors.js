const express = require('express');

module.exports = function createVendorsRouter(db) {
  const router = express.Router();

  // GET /api/vendors
  router.get('/', (req, res) => {
    db.all('SELECT * FROM vendors ORDER BY risk_score DESC', (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  });

  // POST /api/vendors
  router.post('/', (req, res) => {
    const { name, category, risk_score, contact, notes } = req.body;
    const stmt = db.prepare(`INSERT INTO vendors (name, category, risk_score, contact, notes) VALUES (?, ?, ?, ?, ?)`);
    stmt.run([name, category, risk_score || 0, contact, notes], function(err) {
      if (err) return res.status(400).json({ error: err.message });
      res.status(201).json({ id: this.lastID });
    });
    stmt.finalize();
  });

  // POST /api/vendors/:id/assess
  router.post('/:id/assess', (req, res) => {
    db.get('SELECT * FROM vendors WHERE id = ?', [req.params.id], (findErr, vendor) => {
      if (findErr) return res.status(500).json({ error: findErr.message });
      if (!vendor) return res.status(404).json({ error: 'Vendor not found' });

      const keyword = `%${vendor.name}%`;
      db.all(
        `SELECT id, source, externalId, title, severity, date, url
         FROM alerts
         WHERE lower(title) LIKE lower(?) OR lower(externalId) LIKE lower(?) OR lower(source) LIKE lower(?)
         ORDER BY CASE severity
           WHEN 'Critical' THEN 1
           WHEN 'High' THEN 2
           WHEN 'Medium' THEN 3
           WHEN 'Low' THEN 4
           ELSE 5 END, date DESC
         LIMIT 100`,
        [keyword, keyword, keyword],
        (alertErr, alerts) => {
          if (alertErr) return res.status(500).json({ error: alertErr.message });

          const score = Math.min(100, alerts.reduce((acc, alert) => {
            if (alert.severity === 'Critical') return acc + 20;
            if (alert.severity === 'High') return acc + 12;
            if (alert.severity === 'Medium') return acc + 6;
            if (alert.severity === 'Low') return acc + 2;
            return acc + 1;
          }, 0));
          const notes = `Automated assessment found ${alerts.length} related alert(s) for "${vendor.name}".`;

          db.run(
            `UPDATE vendors SET risk_score = ?, last_assessment = datetime('now'), notes = ? WHERE id = ?`,
            [score, notes, vendor.id],
            (updateErr) => {
              if (updateErr) return res.status(500).json({ error: updateErr.message });
              res.json({ id: vendor.id, risk_score: score, notes, matches: alerts });
            }
          );
        }
      );
    });
  });

  // PATCH /api/vendors/:id
  router.patch('/:id', (req, res) => {
    const { status, risk_score, last_assessment, notes } = req.body;
    const updates = [];
    const params = [];
    if (status !== undefined) { updates.push('status = ?'); params.push(status); }
    if (risk_score !== undefined) { updates.push('risk_score = ?'); params.push(risk_score); }
    if (last_assessment !== undefined) { updates.push('last_assessment = ?'); params.push(last_assessment); }
    if (notes !== undefined) { updates.push('notes = ?'); params.push(notes); }
    
    if (updates.length === 0) return res.json({ success: true });
    
    params.push(req.params.id);
    db.run(`UPDATE vendors SET ${updates.join(', ')} WHERE id = ?`, params, function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ updated: this.changes });
    });
  });

  // DELETE /api/vendors/:id
  router.delete('/:id', (req, res) => {
    db.run('DELETE FROM vendors WHERE id = ?', [req.params.id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ deleted: this.changes });
    });
  });

  return router;
};
