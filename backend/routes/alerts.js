const express = require('express');

/**
 * Factory function to create an Express router for querying alerts.
 * @param {sqlite3.Database} db - SQLite database instance
 * @returns {express.Router}
 */
module.exports = function createAlertsRouter(db) {
  const router = express.Router();

  // GET /alerts - return all alerts with optional filters
  router.get('/', (req, res) => {
    const { severity, source, start, end } = req.query;
    let query = 'SELECT * FROM alerts';
    const conditions = [];
    const params = [];

    if (severity) {
      conditions.push('severity = ?');
      params.push(severity);
    }
    if (source) {
      conditions.push('source = ?');
      params.push(source);
    }
    if (start) {
      conditions.push('date >= ?');
      params.push(start);
    }
    if (end) {
      conditions.push('date <= ?');
      params.push(end);
    }
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    // Order results: severity priority then date descending
    query += ` ORDER BY CASE severity
      WHEN 'Critical' THEN 1
      WHEN 'High' THEN 2
      WHEN 'Medium' THEN 3
      WHEN 'Low' THEN 4
      ELSE 5 END, date DESC`;

    db.all(query, params, (err, rows) => {
      if (err) {
        console.error('Database query error:', err);
        return res.status(500).send('Internal server error');
      }
      res.json(rows);
    });
  });

  return router;
};