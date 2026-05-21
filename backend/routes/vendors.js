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
