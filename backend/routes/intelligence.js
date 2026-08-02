const express = require('express');
const intelligenceService = require('../services/intelligence');
const settingsStore = require('../services/settingsStore');
const { requireRole } = require('../services/identity');
const { auditLog } = require('../services/audit');
const cache = require('../services/cache');

// Cache TTLs (in milliseconds)
const CACHE_TTL = {
  stats: 30_000,       // 30 seconds for stats
  indicators: 60_000,  // 1 minute for indicator lists
  correlations: 60_000 // 1 minute for correlations
};

function getSettings(db) {
  return settingsStore.getSettings(db);
}

function upsertSetting(db, key, value) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO settings (key, value, updated_at)
       VALUES (?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`,
      [key, settingsStore.prepareSettingValue(key, value)],
      (err) => err ? reject(err) : resolve()
    );
  });
}

function parseJson(value, fallback) {
  try {
    return JSON.parse(value || '');
  } catch {
    return fallback;
  }
}

module.exports = function createIntelligenceRouter(db) {
  const router = express.Router();
  let correlationJob = null;
  let cveRefreshJob = null;

  // Indicators, correlations, and CVE enrichment are shared intelligence.
  // Tenant-owned alert lookups inside this router are always tenant scoped.
  router.get('/stats', requireRole('viewer'), async (req, res) => {
    try {
      const cacheKey = `intel:stats:${req.tenant_id || 'global'}`;
      const stats = await cache.wrap(cacheKey, () => new Promise((resolve) => {
        const result = {};
        db.get('SELECT COUNT(*) as count FROM indicators', [], (err, row) => {
          if (!err && row) result.indicators = row.count;
          db.get('SELECT COUNT(*) as count FROM correlated_findings', [], (err2, row2) => {
            if (!err2 && row2) result.correlations = row2.count;
            resolve(result);
          });
        });
      }), CACHE_TTL.stats);
      res.json(stats);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/indicators', requireRole('viewer'), (req, res) => {
    const { type, source, search, page: rawPage, limit: rawLimit } = req.query;
    const hasPagination = rawPage !== undefined || rawLimit !== undefined;
    const page = Math.max(1, parseInt(rawPage, 10) || 1);
    const limit = Math.min(1000, Math.max(1, parseInt(rawLimit, 10) || 500));
    const offset = (page - 1) * limit;
    const conditions = [];
    const params = [];
    if (type) {
      conditions.push('type = ?');
      params.push(type);
    }
    if (source) {
      conditions.push('source = ?');
      params.push(source);
    }
    if (search) {
      conditions.push('(value LIKE ? OR externalId LIKE ? OR malware_family LIKE ?)');
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }
    const whereClause = conditions.length > 0 ? ` WHERE ${conditions.join(' AND ')}` : '';
    const baseQuery = `SELECT * FROM indicators${whereClause}`;
    if (hasPagination) {
      db.get(`SELECT COUNT(*) as count FROM indicators${whereClause}`, params, (countErr, countRow) => {
        if (countErr) return res.status(500).json({ error: countErr.message });
        const total = countRow ? countRow.count : 0;
        db.all(`${baseQuery} ORDER BY updated_at DESC LIMIT ? OFFSET ?`, [...params, limit, offset], (err, rows) => {
          if (err) return res.status(500).json({ error: err.message });
          return res.json({ data: rows || [], total, page, limit });
        });
      });
    } else {
      db.all(`${baseQuery} ORDER BY updated_at DESC LIMIT 1000`, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        return res.json(rows || []);
      });
    }
  });

  router.get('/indicators/export', requireRole('viewer'), (req, res) => {
    const format = (req.query.format || 'json').toLowerCase();
    const { type, source, search } = req.query;
    const conditions = [];
    const params = [];
    if (type) { conditions.push('type = ?'); params.push(type); }
    if (source) { conditions.push('source = ?'); params.push(source); }
    if (search) {
      conditions.push('(value LIKE ? OR externalId LIKE ? OR malware_family LIKE ?)');
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }
    const whereClause = conditions.length > 0 ? ` WHERE ${conditions.join(' AND ')}` : '';
    const limit = Math.min(10000, Math.max(1, parseInt(req.query.limit || '5000', 10) || 5000));

    db.all(`SELECT * FROM indicators${whereClause} ORDER BY updated_at DESC LIMIT ?`, [...params, limit], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      const items = rows || [];
      if (format === 'csv') {
        const header = 'value,type,source,severity,confidence,first_seen,last_seen,malware_family,tlp';
        const lines = items.map(i =>
          `"${(i.value || '').replace(/"/g, '""')}","${i.type || ''}","${i.source || ''}","${i.severity || ''}",${i.confidence || ''},"${i.first_seen || ''}","${i.last_seen || ''}","${i.malware_family || ''}","${i.tlp || 'TLP:AMBER'}"`
        );
        res.set('Content-Type', 'text/csv');
        res.set('Content-Disposition', 'attachment; filename="threatdock-iocs.csv"');
        return res.send([header, ...lines].join('\n'));
      }
      if (format === 'stix') {
        const stix = {
          type: 'bundle',
          id: `bundle--${require('crypto').randomUUID()}`,
          spec_version: '2.1',
          objects: items.map(i => ({
            type: 'indicator',
            id: `indicator--${require('crypto').randomUUID()}`,
            created: i.first_seen || new Date().toISOString(),
            modified: i.last_seen || new Date().toISOString(),
            name: i.value || '',
            description: `ThreatDock IOC from ${i.source || 'unknown'} (${i.type || 'unknown'})`,
            pattern: `[${i.type || 'file:hashes'}:value = '${(i.value || '').replace(/'/g, "\\'")}']`,
            pattern_type: 'stix',
            valid_from: i.first_seen || new Date().toISOString(),
            indicator_types: ['malicious-activity'],
            severity: i.severity || 'Unknown'
          }))
        };
        res.set('Content-Type', 'application/json');
        res.set('Content-Disposition', 'attachment; filename="threatdock-iocs-stix.json"');
        return res.json(stix);
      }
      res.set('Content-Disposition', 'attachment; filename="threatdock-iocs.json"');
      return res.json(items);
    });
  });

  router.get('/correlations', requireRole('viewer'), (req, res) => {
    const hasPagination = req.query.page !== undefined || req.query.limit !== undefined;
    if (hasPagination) {
      const page = Math.max(1, parseInt(req.query.page, 10) || 1);
      const limit = Math.min(1000, Math.max(1, parseInt(req.query.limit, 10) || 500));
      const offset = (page - 1) * limit;
      db.get('SELECT COUNT(*) as count FROM correlated_findings', [], (countErr, countRow) => {
        if (countErr) return res.status(500).json({ error: countErr.message });
        const total = countRow ? countRow.count : 0;
        db.all('SELECT * FROM correlated_findings ORDER BY score DESC, updated_at DESC LIMIT ? OFFSET ?', [limit, offset], (err, rows) => {
          if (err) return res.status(500).json({ error: err.message });
          return res.json({ data: rows || [], total, page, limit });
        });
      });
    } else {
      db.all('SELECT * FROM correlated_findings ORDER BY score DESC, updated_at DESC LIMIT 1000', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        return res.json(rows || []);
      });
    }
  });

  router.post('/correlations/rebuild', requireRole('admin'), async (req, res) => {
    if (correlationJob) return res.status(202).json({ message: 'Correlation rebuild already running' });
    correlationJob = intelligenceService.rebuildCorrelations(db)
      .then(async () => {
        // Invalidate stats cache after rebuild completes
        await cache.del(`intel:stats:${req.tenant_id || 'global'}`).catch(() => {});
      })
      .catch(err => console.error('Correlation rebuild failed:', err.message))
      .finally(() => { correlationJob = null; });
    await auditLog(db, {
      tenant_id: req.tenant_id,
      actor: req.user,
      event_name: 'correlations_rebuild_requested',
      status: 'success'
    });
    return res.status(202).json({ message: 'Correlation rebuild started' });
  });

  router.get('/cve-enrichment', requireRole('viewer'), (req, res) => {
    const { cve } = req.query;
    const params = [];
    let query = 'SELECT * FROM cve_enrichment';
    if (cve) {
      const values = String(cve).split(',').map(item => item.trim().toUpperCase()).filter(Boolean);
      if (values.length > 0) {
        query += ` WHERE cve_id IN (${values.map(() => '?').join(',')})`;
        params.push(...values);
      }
    }
    query += ' ORDER BY kev_known DESC, epss_score DESC LIMIT 1000';
    db.all(query, params, (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      return res.json(rows || []);
    });
  });

  router.post('/cve-enrichment/refresh', requireRole('admin'), async (req, res) => {
    if (cveRefreshJob) return res.status(202).json({ message: 'CVE enrichment refresh already running' });
    cveRefreshJob = Promise.resolve();
    try {
      const requested = Array.isArray(req.body.cves) ? req.body.cves : [];
      let cves = requested.map(item => String(item).toUpperCase()).filter(Boolean);
      if (cves.length === 0) {
        const alerts = await new Promise((resolve, reject) => {
          db.all(
            'SELECT "externalId", title FROM alerts WHERE tenant_id = ? ORDER BY date DESC LIMIT 1000',
            [req.tenant_id],
            (err, rows) => err ? reject(err) : resolve(rows || [])
          );
        });
        cves = [...new Set(alerts.flatMap(alert => intelligenceService.extractCves(`${alert.externalId || ''} ${alert.title || ''}`)))];
      }
      cveRefreshJob = intelligenceService.enrichCves(db, cves)
        .catch(err => console.error('CVE enrichment refresh failed:', err.message))
        .finally(() => { cveRefreshJob = null; });
      await auditLog(db, {
        tenant_id: req.tenant_id,
        actor: req.user,
        event_name: 'cve_enrichment_refresh_requested',
        status: 'success',
        metadata: { cve_count: cves.length }
      });
      return res.status(202).json({ message: 'CVE enrichment refresh started', refreshed: cves.length });
    } catch (err) {
      cveRefreshJob = null;
      return res.status(500).json({ error: err.message });
    }
  });

  router.get('/risk-rules', requireRole('viewer'), async (req, res) => {
    try {
      const settings = await getSettings(db);
      return res.json({
        weights: parseJson(settings.RISK_WEIGHTS, {}),
        notificationRules: parseJson(settings.NOTIFICATION_RULES, [])
      });
    } catch (err) {
      return res.status(500).json({ error: 'Failed to load risk rules' });
    }
  });

  router.put('/risk-rules', requireRole('admin'), async (req, res) => {
    try {
      const weights = req.body.weights || {};
      const notificationRules = Array.isArray(req.body.notificationRules) ? req.body.notificationRules : [];
      await upsertSetting(db, 'RISK_WEIGHTS', JSON.stringify(weights));
      await upsertSetting(db, 'NOTIFICATION_RULES', JSON.stringify(notificationRules));
      await auditLog(db, {
        tenant_id: req.tenant_id,
        actor: req.user,
        event_name: 'risk_rules_updated',
        status: 'success'
      });
      return res.json({ message: 'Risk and notification rules saved' });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  });

  return router;
};
