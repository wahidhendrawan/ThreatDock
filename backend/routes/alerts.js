const express = require('express');
const { requireRole } = require('../services/identity');
const { auditLog, actorName } = require('../services/audit');

/**
 * Simple schema validation for advanced filter queries.
 * Supports operators: eq, ne, gte, lte, in, nin, contains
 * Returns { valid: boolean, errors: string[], parsed: object }
 */
function validateAdvancedFilter(filter) {
  const errors = [];
  const parsed = {};
  
  if (!filter || typeof filter !== 'object') {
    return { valid: true, errors: [], parsed: {} };
  }
  
  const allowedFields = ['severity', 'source', 'status', 'priority', 'attack_phase', 'assignee', 'date'];
  const allowedOperators = ['eq', 'ne', 'gte', 'lte', 'in', 'nin', 'contains'];
  
  for (const [field, conditions] of Object.entries(filter)) {
    if (!allowedFields.includes(field)) {
      errors.push(`Unknown field: ${field}`);
      continue;
    }
    if (typeof conditions !== 'object' || conditions === null) {
      parsed[field] = { eq: conditions };
      continue;
    }
    parsed[field] = {};
    for (const [op, value] of Object.entries(conditions)) {
      if (!allowedOperators.includes(op)) {
        errors.push(`Unknown operator: ${op} for field ${field}`);
        continue;
      }
      // Validate value types
      if (op === 'in' || op === 'nin') {
        if (!Array.isArray(value)) {
          errors.push(`Operator ${op} requires an array value for field ${field}`);
          continue;
        }
        parsed[field][op] = value.map(v => String(v).slice(0, 200));
      } else if (op === 'contains') {
        parsed[field][op] = String(value).slice(0, 200);
      } else {
        parsed[field][op] = String(value).slice(0, 200);
      }
    }
  }
  
  return { valid: errors.length === 0, errors, parsed };
}

/**
 * Build SQL WHERE conditions from parsed filter object.
 */
function buildFilterConditions(parsed, tenantId) {
  const conditions = ['tenant_id = ?'];
  const params = [tenantId];
  
  for (const [field, ops] of Object.entries(parsed)) {
    const dbField = field === 'date' ? 'date' : field;
    
    if (ops.eq !== undefined) {
      conditions.push(`${dbField} = ?`);
      params.push(ops.eq);
    }
    if (ops.ne !== undefined) {
      conditions.push(`${dbField} != ?`);
      params.push(ops.ne);
    }
    if (ops.gte !== undefined) {
      conditions.push(`${dbField} >= ?`);
      params.push(ops.gte);
    }
    if (ops.lte !== undefined) {
      conditions.push(`${dbField} <= ?`);
      params.push(ops.lte);
    }
    if (ops.in !== undefined && Array.isArray(ops.in) && ops.in.length > 0) {
      const placeholders = ops.in.map(() => '?').join(', ');
      conditions.push(`${dbField} IN (${placeholders})`);
      params.push(...ops.in);
    }
    if (ops.nin !== undefined && Array.isArray(ops.nin) && ops.nin.length > 0) {
      const placeholders = ops.nin.map(() => '?').join(', ');
      conditions.push(`${dbField} NOT IN (${placeholders})`);
      params.push(...ops.nin);
    }
    if (ops.contains !== undefined) {
      conditions.push(`${dbField} LIKE ?`);
      params.push(`%${ops.contains}%`);
    }
  }
  
  return { where: `WHERE ${conditions.join(' AND ')}`, params };
}

/** Tenant-isolated alert triage and discussion routes. */
module.exports = function createAlertsRouter(db) {
  const router = express.Router();

  router.get('/', requireRole('viewer'), (req, res) => {
    const { severity, source, start, end, status, search: rawSearch, page: rawPage, limit: rawLimit } = req.query;
    const conditions = ['tenant_id = ?'];
    const params = [req.tenant_id];
    if (severity) { conditions.push('severity = ?'); params.push(severity); }
    if (source) { conditions.push('source = ?'); params.push(source); }
    if (start) { conditions.push('date >= ?'); params.push(start); }
    if (end) { conditions.push('date <= ?'); params.push(end); }
    if (status) { conditions.push('status = ?'); params.push(status); }
    if (rawSearch) {
      conditions.push('(title LIKE ? OR "externalId" LIKE ? OR source LIKE ?)');
      const value = `%${rawSearch}%`;
      params.push(value, value, value);
    }
    const where = ` WHERE ${conditions.join(' AND ')}`;
    const order = ` ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END, date DESC`;
    const hasPagination = rawPage !== undefined || rawLimit !== undefined;
    if (!hasPagination) {
      return db.all(`SELECT * FROM alerts${where}${order}`, params, (err, rows) => {
        if (err) return res.status(500).json({ error: 'Internal server error' });
        return res.json(rows || []);
      });
    }
    const page = Math.max(1, Number.parseInt(rawPage, 10) || 1);
    const limit = Math.min(500, Math.max(1, Number.parseInt(rawLimit, 10) || 100));
    const offset = (page - 1) * limit;
    return db.get(`SELECT COUNT(*) AS count FROM alerts${where}`, params, (countErr, countRow) => {
      if (countErr) return res.status(500).json({ error: 'Internal server error' });
      db.all(`SELECT * FROM alerts${where}${order} LIMIT ? OFFSET ?`, [...params, limit, offset], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Internal server error' });
        return res.json({ data: rows || [], total: Number(countRow && countRow.count) || 0, page, limit });
      });
    });
  });

  /**
   * POST /filter applies a validated, tenant-scoped advanced filter.
   * The filter structure is `{ field: { operator: value } }`; supported
   * fields and operators are allow-listed by validateAdvancedFilter above.
   */
  router.post('/filter', requireRole('viewer'), (req, res) => {
    const validation = validateAdvancedFilter(req.body?.filter);
    if (!validation.valid) {
      return res.status(400).json({ error: 'Invalid advanced filter', details: validation.errors });
    }

    const page = Math.max(1, Number.parseInt(req.body?.page, 10) || 1);
    const limit = Math.min(500, Math.max(1, Number.parseInt(req.body?.limit, 10) || 100));
    const offset = (page - 1) * limit;
    const { where, params } = buildFilterConditions(validation.parsed, req.tenant_id);
    const order = " ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END, date DESC";

    return db.get(`SELECT COUNT(*) AS count FROM alerts ${where}`, params, (countErr, countRow) => {
      if (countErr) return res.status(500).json({ error: 'Internal server error' });
      return db.all(
        `SELECT * FROM alerts ${where}${order} LIMIT ? OFFSET ?`,
        [...params, limit, offset],
        (err, rows) => {
          if (err) return res.status(500).json({ error: 'Internal server error' });
          return res.json({
            data: rows || [],
            total: Number(countRow?.count) || 0,
            page,
            limit,
            filter: validation.parsed
          });
        }
      );
    });
  });

  router.patch('/:id', requireRole('editor'), (req, res) => {
    const allowed = ['status', 'assignee', 'priority', 'sla_due', 'tags', 'case_summary', 'attack_phase'];
    const updates = [];
    const params = [];
    for (const field of allowed) {
      if (req.body[field] !== undefined) {
        updates.push(`${field} = ?`);
        params.push(field === 'tags' && Array.isArray(req.body[field]) ? JSON.stringify(req.body[field]) : req.body[field]);
      }
    }
    if (!updates.length) return res.status(400).json({ error: 'No supported alert fields provided' });
    db.get('SELECT * FROM alerts WHERE id = ? AND tenant_id = ?', [req.params.id, req.tenant_id], (findErr, before) => {
      if (findErr) return res.status(500).json({ error: findErr.message });
      if (!before) return res.status(404).json({ error: 'Alert not found' });
      updates.push('updated_at = CURRENT_TIMESTAMP');
      db.run(`UPDATE alerts SET ${updates.join(', ')} WHERE id = ? AND tenant_id = ?`, [...params, req.params.id, req.tenant_id], err => {
        if (err) return res.status(500).json({ error: 'Internal server error' });
        db.get('SELECT * FROM alerts WHERE id = ? AND tenant_id = ?', [req.params.id, req.tenant_id], async (loadErr, after) => {
          if (loadErr) return res.status(500).json({ error: loadErr.message });
          await auditLog(db, { tenant_id: req.tenant_id, actor: req.user, event_name: 'alert_updated', status: 'success', metadata: { alert_id: req.params.id, before, after } });
          return res.json(after);
        });
      });
    });
  });

  router.get('/:id/comments', requireRole('viewer'), (req, res) => {
    const sql = `SELECT c.* FROM alert_comments c JOIN alerts a ON a.id = c.alert_id
                 WHERE c.alert_id = ? AND a.tenant_id = ? ORDER BY c.created_at ASC`;
    db.all(sql, [req.params.id, req.tenant_id], (err, rows) => err ? res.status(500).json({ error: err.message }) : res.json(rows || []));
  });

  router.post('/:id/comments', requireRole('editor'), (req, res) => {
    const body = String(req.body.body || '').trim();
    if (!body) return res.status(400).json({ error: 'Comment body is required' });
    db.get('SELECT id FROM alerts WHERE id = ? AND tenant_id = ?', [req.params.id, req.tenant_id], (findErr, alert) => {
      if (findErr) return res.status(500).json({ error: findErr.message });
      if (!alert) return res.status(404).json({ error: 'Alert not found' });
      db.run('INSERT INTO alert_comments (alert_id, "user", body) VALUES (?, ?, ?)', [alert.id, actorName(req.user), body], async function onInsert(err) {
        if (err) return res.status(500).json({ error: err.message });
        await auditLog(db, { tenant_id: req.tenant_id, actor: req.user, event_name: 'alert_comment_created', status: 'success', metadata: { alert_id: alert.id, comment_id: this.lastID } });
        return res.status(201).json({ id: this.lastID, alert_id: alert.id, user: actorName(req.user), body });
      });
    });
  });

  router.get('/:id/history', requireRole('viewer'), (req, res) => {
    db.all(`SELECT * FROM audit_logs WHERE tenant_id = ? AND entity_type = 'alert' AND entity_id = ? ORDER BY created_at DESC LIMIT 100`, [req.tenant_id, String(req.params.id)], (err, rows) => err ? res.status(500).json({ error: err.message }) : res.json(rows || []));
  });

  router.delete('/:id/comments/:commentId', requireRole('editor'), (req, res) => {
    const sql = `DELETE FROM alert_comments WHERE id = ? AND alert_id = ?
                 AND EXISTS (SELECT 1 FROM alerts WHERE id = ? AND tenant_id = ?)`;
    db.run(sql, [req.params.commentId, req.params.id, req.params.id, req.tenant_id], async function onDelete(err) {
      if (err) return res.status(500).json({ error: err.message });
      if (!this.changes) return res.status(404).json({ error: 'Comment not found' });
      await auditLog(db, { tenant_id: req.tenant_id, actor: req.user, event_name: 'alert_comment_deleted', status: 'success', metadata: { alert_id: req.params.id, comment_id: req.params.commentId } });
      return res.json({ success: true });
    });
  });

  return router;
};
