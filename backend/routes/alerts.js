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
    const { severity, source, start, end, status } = req.query;
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
    if (status) {
      conditions.push('status = ?');
      params.push(status);
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

  // PATCH /alerts/:id - update the status of an alert
  router.patch('/:id', (req, res) => {
    const id = req.params.id;
    const { status } = req.body;
    if (!status) {
      return res.status(400).send('Missing status');
    }
    db.run('UPDATE alerts SET status = ? WHERE id = ?', [status, id], function(err) {
      if (err) {
        console.error('Database update error:', err);
        return res.status(500).send('Internal server error');
      }
      if (this.changes === 0) {
        return res.status(404).send('Alert not found');
      }
      res.json({ id, status });
    });
  });

  return router;
};