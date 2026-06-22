const express = require('express');

module.exports = function createIngestionRouter(db, options = {}) {
  const { fetchAllSources } = options;
  const router = express.Router();

  router.get('/health', (req, res) => {
    db.all('SELECT * FROM source_health ORDER BY source ASC', [], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows || []);
    });
  });

  router.get('/runs', (req, res) => {
    const limit = Math.min(parseInt(req.query.limit || '100', 10), 500);
    db.all('SELECT * FROM ingestion_runs ORDER BY started_at DESC LIMIT ?', [limit], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows || []);
    });
  });

  router.get('/audit', (req, res) => {
    const limit = Math.min(parseInt(req.query.limit || '100', 10), 500);
    db.all('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?', [limit], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows || []);
    });
  });

  // POST /fetch — manually trigger source fetching
  router.post('/fetch', (req, res) => {
    if (!fetchAllSources) return res.status(500).json({ error: 'Fetch function not available' });
    fetchAllSources().catch(err => console.error('Manual fetch error:', err));
    res.json({ message: 'Source fetch started' });
  });

  return router;
};
