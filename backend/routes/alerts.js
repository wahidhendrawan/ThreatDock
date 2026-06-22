const express = require('express');

/**
 * Factory function to create an Express router for querying alerts.
 * @param {object} db - database adapter instance
 * @returns {express.Router}
 */
module.exports = function createAlertsRouter(db) {
  const router = express.Router();

  const actorName = (req) => {
    if (!req.user) return 'Anonymous';
    return req.user.name || req.user.preferred_username || req.user.email || 'Anonymous';
  };

  const audit = (req, entityId, action, beforeValue, afterValue) => {
    db.run(
      `INSERT INTO audit_logs (entity_type, entity_id, user, action, before_value, after_value)
       VALUES ('alert', ?, ?, ?, ?, ?)`,
      [
        String(entityId),
        actorName(req),
        action,
        beforeValue === undefined ? '' : JSON.stringify(beforeValue),
        afterValue === undefined ? '' : JSON.stringify(afterValue)
      ]
    );
  };

  // GET /alerts - return alerts with optional server-side pagination and filters
  router.get('/', (req, res) => {
    const { severity, source, start, end, status, search: rawSearch, page: rawPage, limit: rawLimit } = req.query;
    const search = typeof rawSearch === 'string' ? rawSearch : '';
    const hasPagination = rawPage !== undefined || rawLimit !== undefined;
    const page = Math.max(1, parseInt(rawPage) || 1);
    const limit = Math.min(500, Math.max(1, parseInt(rawLimit) || 100));
    const offset = (page - 1) * limit;
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
    if (search) {
      conditions.push('(title LIKE ? OR externalId LIKE ? OR source LIKE ?)');
      const value = `%${search}%`;
      params.push(value, value, value);
    }
    const whereClause = conditions.length > 0 ? ' WHERE ' + conditions.join(' AND ') : '';

    const orderClause = ` ORDER BY CASE severity
      WHEN 'Critical' THEN 1
      WHEN 'High' THEN 2
      WHEN 'Medium' THEN 3
      WHEN 'Low' THEN 4
      ELSE 5 END, date DESC`;

    if (hasPagination) {
      // Get total count
      db.get(`SELECT COUNT(*) as count FROM alerts${whereClause}`, params, (countErr, countRow) => {
        if (countErr) {
          console.error('Database count error:', countErr);
          return res.status(500).send('Internal server error');
        }
        const total = countRow ? countRow.count : 0;
        const paginatedParams = [...params, limit, offset];

        db.all(`SELECT * FROM alerts${whereClause}${orderClause} LIMIT ? OFFSET ?`, paginatedParams, (err, rows) => {
          if (err) {
            console.error('Database query error:', err);
            return res.status(500).send('Internal server error');
          }
          res.json({ data: rows, total, page, limit });
        });
      });
    } else {
      // No pagination — return all results (backward-compatible)
      db.all(`SELECT * FROM alerts${whereClause}${orderClause}`, params, (err, rows) => {
        if (err) {
          console.error('Database query error:', err);
          return res.status(500).send('Internal server error');
        }
        res.json(rows);
      });
    }
  });

  // PATCH /alerts/:id - update alert triage/case fields
  router.patch('/:id', (req, res) => {
    const id = req.params.id;
    const allowed = ['status', 'assignee', 'priority', 'sla_due', 'tags', 'case_summary', 'attack_phase'];
    const updates = [];
    const params = [];

    allowed.forEach(field => {
      if (req.body[field] !== undefined) {
        updates.push(`${field} = ?`);
        const value = field === 'tags' && Array.isArray(req.body[field])
          ? JSON.stringify(req.body[field])
          : req.body[field];
        params.push(value);
      }
    });

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No supported alert fields provided' });
    }

    db.get('SELECT * FROM alerts WHERE id = ?', [id], (findErr, before) => {
      if (findErr) return res.status(500).json({ error: findErr.message });
      if (!before) return res.status(404).json({ error: 'Alert not found' });

      updates.push("updated_at = CURRENT_TIMESTAMP");
      params.push(id);
      db.run(`UPDATE alerts SET ${updates.join(', ')} WHERE id = ?`, params, function(err) {
        if (err) {
          console.error('Database update error:', err);
          return res.status(500).send('Internal server error');
        }
        db.get('SELECT * FROM alerts WHERE id = ?', [id], (loadErr, after) => {
          if (loadErr) return res.status(500).json({ error: loadErr.message });
          audit(req, id, 'update', before, after);
          res.json(after);
        });
      });
    });
  });

  router.get('/:id/comments', (req, res) => {
    db.all('SELECT * FROM alert_comments WHERE alert_id = ? ORDER BY created_at ASC', [req.params.id], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows || []);
    });
  });

  router.post('/:id/comments', (req, res) => {
    const body = String(req.body.body || '').trim();
    if (!body) return res.status(400).json({ error: 'Comment body is required' });
    db.run(
      `INSERT INTO alert_comments (alert_id, user, body) VALUES (?, ?, ?)`,
      [req.params.id, actorName(req), body],
      function(err) {
        if (err) return res.status(500).json({ error: err.message });
        audit(req, req.params.id, 'comment', '', body);
        res.status(201).json({ id: this.lastID, alert_id: req.params.id, user: actorName(req), body });
      }
    );
  });

  router.get('/:id/history', (req, res) => {
    db.all(
      "SELECT * FROM audit_logs WHERE entity_type = 'alert' AND entity_id = ? ORDER BY created_at DESC LIMIT 100",
      [String(req.params.id)],
      (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
      }
    );
  });

  router.delete('/:id/comments/:commentId', (req, res) => {
    db.run(
      'DELETE FROM alert_comments WHERE id = ? AND alert_id = ?',
      [req.params.commentId, req.params.id],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
      }
    );
  });

  return router;
};
