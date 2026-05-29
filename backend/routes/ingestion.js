const express = require('express');

module.exports = function createIngestionRouter(db) {
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

  return router;
};
