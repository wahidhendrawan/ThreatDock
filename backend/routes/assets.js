const express = require('express');

module.exports = function createAssetsRouter(db) {
  const router = express.Router();

  // GET /api/assets
  router.get('/', (req, res) => {
    db.all('SELECT * FROM assets ORDER BY created_at DESC', (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  });

  // POST /api/assets
  router.post('/', (req, res) => {
    const { domain, ip, port, service, tech_stack, notes } = req.body;
    const stmt = db.prepare(`INSERT INTO assets (domain, ip, port, service, tech_stack, notes) VALUES (?, ?, ?, ?, ?, ?)`);
    stmt.run([domain, ip, port, service, tech_stack, notes], function(err) {
      if (err) return res.status(400).json({ error: err.message });
      res.status(201).json({ id: this.lastID });
    });
    stmt.finalize();
  });

  // PATCH /api/assets/:id
  router.patch('/:id', (req, res) => {
    const { status, risk_score, notes } = req.body;
    const updates = [];
    const params = [];
    if (status !== undefined) { updates.push('status = ?'); params.push(status); }
    if (risk_score !== undefined) { updates.push('risk_score = ?'); params.push(risk_score); }
    if (notes !== undefined) { updates.push('notes = ?'); params.push(notes); }
    
    if (updates.length === 0) return res.json({ success: true });
    
    params.push(req.params.id);
    db.run(`UPDATE assets SET ${updates.join(', ')} WHERE id = ?`, params, function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ updated: this.changes });
    });
  });

  // DELETE /api/assets/:id
  router.delete('/:id', (req, res) => {
    db.run('DELETE FROM assets WHERE id = ?', [req.params.id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ deleted: this.changes });
    });
  });

  return router;
};
