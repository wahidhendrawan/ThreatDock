const express = require('express');
const { requireRole } = require('../services/identity');
const { auditLog } = require('../services/audit');
const { circuitBreaker } = require('../services/circuitBreaker');

module.exports = function createIngestionRouter(db, options = {}) {
  const { fetchAllSources, deadLetterQueue: dlq } = options;
  const router = express.Router();

  // Source health and ingestion runs are global operational data, but require
  // an authenticated viewer role to prevent unauthorised operational insight.
  router.get('/health', requireRole('viewer'), (req, res) => {
    db.all('SELECT * FROM source_health ORDER BY source ASC', [], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      return res.json(rows || []);
    });
  });

  router.get('/runs', requireRole('viewer'), (req, res) => {
    const limit = Math.min(Math.max(1, parseInt(req.query.limit || '100', 10) || 100), 500);
    db.all('SELECT * FROM ingestion_runs ORDER BY started_at DESC LIMIT ?', [limit], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      return res.json(rows || []);
    });
  });

  router.get('/audit', requireRole('admin'), (req, res) => {
    const limit = Math.min(Math.max(1, parseInt(req.query.limit || '100', 10) || 100), 500);
    db.all(
      'SELECT * FROM audit_logs WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?',
      [req.tenant_id, limit],
      (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        return res.json(rows || []);
      }
    );
  });

  // POST /fetch — manually trigger a global source fetch. The resulting alerts
  // are persisted to the application default tenant by the background worker.
  router.post('/fetch', requireRole('admin'), (req, res) => {
    if (!fetchAllSources) return res.status(500).json({ error: 'Fetch function not available' });
    fetchAllSources().catch(err => console.error('Manual fetch error:', err));
    auditLog(db, {
      tenant_id: req.tenant_id,
      actor: req.user,
      event_name: 'ingestion_fetch_requested',
      status: 'success'
    }).catch(() => {});
    return res.json({ message: 'Source fetch started' });
  });

  // Circuit breaker observability endpoints (admin only)
  router.get('/circuit-breaker', requireRole('admin'), (req, res) => {
    const status = circuitBreaker.getStatus();
    return res.json(status);
  });

  router.post('/circuit-breaker/reset', requireRole('admin'), (req, res) => {
    const { source } = req.query;
    if (!source) {
      return res.status(400).json({ error: 'source query parameter is required' });
    }
    circuitBreaker.reset(source);
    auditLog(db, {
      tenant_id: req.tenant_id,
      actor: req.user,
      event_name: 'circuit_breaker_reset',
      entity_type: 'source',
      entity_id: source,
      status: 'success'
    }).catch(() => {});
    return res.json({ message: `Circuit breaker reset for ${source}` });
  });

  // Dead-letter queue observability endpoints (admin only)
  router.get('/dlq', requireRole('admin'), async (req, res) => {
    try {
      const { source, status, limit } = req.query;
      const filters = {};
      if (source) filters.source = source;
      if (status) filters.status = status;
      if (limit) filters.limit = Math.min(parseInt(limit, 10) || 100, 500);

      const result = await db.all(
        `SELECT * FROM dead_letter_queue
         WHERE ($1::text IS NULL OR source = $1)
           AND ($2::text IS NULL OR status = $2)
         ORDER BY last_attempt DESC
         LIMIT $3`,
        [filters.source || null, filters.status || null, filters.limit || 100]
      );
      return res.json(result);
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  });

  router.get('/dlq/stats', requireRole('admin'), async (req, res) => {
    try {
      const result = await db.all(
        `SELECT source, status, COUNT(*) as count
         FROM dead_letter_queue
         GROUP BY source, status
         ORDER BY source, status`
      );
      return res.json(result);
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  });

  router.post('/dlq/:id/resolve', requireRole('admin'), async (req, res) => {
    const { id } = req.params;
    const { notes } = req.body || {};
    try {
      await db.run(
        `UPDATE dead_letter_queue
         SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP, resolved_by = $1, notes = $2
         WHERE id = $3`,
        [req.user?.email || req.user?.sub || 'admin', notes || '', id]
      );
      auditLog(db, {
        tenant_id: req.tenant_id,
        actor: req.user,
        event_name: 'dlq_item_resolved',
        entity_type: 'dlq',
        entity_id: id,
        status: 'success'
      }).catch(() => {});
      return res.json({ message: `DLQ item ${id} resolved` });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  });

  router.post('/dlq/:id/retry', requireRole('admin'), async (req, res) => {
    const { id } = req.params;
    if (!dlq || !fetchAllSources) {
      return res.status(503).json({ error: 'DLQ or fetch service not available.' });
    }

    try {
      const item = await dlq.claimById(id);
      if (!item) {
        return res.status(404).json({ error: 'DLQ item not found, already resolved, or currently being processed.' });
      }

      auditLog(db, {
        tenant_id: req.tenant_id, actor: req.user, event_name: 'dlq_item_retry_started',
        entity_type: 'dlq', entity_id: id, status: 'success'
      }).catch(() => {});

      // Asynchronously trigger the fetch for the specific source.
      // This provides immediate feedback to the UI. The actual success/failure
      // will be handled by the background worker.
      fetchAllSources({ specificSource: item.source })
        .then(() => {
          console.log(`[DLQ] Manual retry for item ${id} (source: ${item.source}) completed.`);
          // The worker is responsible for resolving the item now.
        })
        .catch(err => {
          console.error(`[DLQ] Manual retry for item ${id} failed unexpectedly:`, err);
          // If the worker fails, we must release the claim so it can be picked up again.
          dlq.releaseClaim(id, `Manual retry failed: ${err.message}`).catch(() => {});
        });

      return res.json({ message: `DLQ item ${id} (source: ${item.source}) replay started.` });
    } catch (err) {
      console.error(`[DLQ] Retry logic for item ${id} failed:`, err);
      return res.status(500).json({ error: 'Failed to initiate DLQ retry.' });
    }
  });

  return router;
};
