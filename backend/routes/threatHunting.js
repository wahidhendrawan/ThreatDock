const express = require('express');

module.exports = function createHuntRouter(db) {
  const router = express.Router();

  // POST /api/hunt - Execute a new hunt query
  router.post('/', (req, res) => {
    const { query_type, query_value } = req.body;
    const user = req.user ? req.user.preferred_username || req.user.name || 'Anonymous' : 'Anonymous';
    
    // In a real app, this would query external APIs (VirusTotal, ThreatFox, etc)
    // For now, we simulate a response
    const mockResults = JSON.stringify({
      status: 'success',
      hits: Math.floor(Math.random() * 10),
      message: 'Simulated hunt results'
    });

    const stmt = db.prepare(`INSERT INTO hunt_queries (query_type, query_value, results, user) VALUES (?, ?, ?, ?)`);
    stmt.run([query_type, query_value, mockResults, user], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ id: this.lastID, results: JSON.parse(mockResults) });
    });
    stmt.finalize();
  });

  // GET /api/hunt/history - Get past hunt queries
  router.get('/history', (req, res) => {
    db.all('SELECT id, query_type, query_value, created_at, user FROM hunt_queries ORDER BY created_at DESC LIMIT 50', (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  });

  return router;
};
