const express = require('express');
const intelligenceService = require('../services/intelligence');
const settingsStore = require('../services/settingsStore');

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

  router.get('/stats', (req, res) => {
    const stats = {};
    db.get('SELECT COUNT(*) as count FROM indicators', [], (err, row) => {
      if (!err) stats.indicators = row.count;
      db.get('SELECT COUNT(*) as count FROM correlated_findings', [], (err2, row2) => {
        if (!err2) stats.correlations = row2.count;
        res.json(stats);
      });
    });
  });

  router.get('/indicators', (req, res) => {
    const { type, source, search } = req.query;
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
    let query = 'SELECT * FROM indicators';
    if (conditions.length > 0) query += ` WHERE ${conditions.join(' AND ')}`;
    query += ' ORDER BY updated_at DESC LIMIT 1000';
    db.all(query, params, (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows || []);
    });
  });

  router.get('/correlations', (req, res) => {
    db.all('SELECT * FROM correlated_findings ORDER BY score DESC, updated_at DESC LIMIT 1000', [], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows || []);
    });
  });

  router.post('/correlations/rebuild', async (req, res) => {
    if (correlationJob) {
      return res.status(202).json({ message: 'Correlation rebuild already running' });
    }

    correlationJob = intelligenceService.rebuildCorrelations(db)
      .catch(err => {
        console.error('Correlation rebuild failed:', err.message);
      })
      .finally(() => {
        correlationJob = null;
      });

    res.status(202).json({ message: 'Correlation rebuild started' });
  });

  router.get('/cve-enrichment', (req, res) => {
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
      res.json(rows || []);
    });
  });

  router.post('/cve-enrichment/refresh', async (req, res) => {
    if (cveRefreshJob) {
      return res.status(202).json({ message: 'CVE enrichment refresh already running' });
    }

    cveRefreshJob = Promise.resolve();
    try {
      const requested = Array.isArray(req.body.cves) ? req.body.cves : [];
      let cves = requested.map(item => String(item).toUpperCase()).filter(Boolean);
      if (cves.length === 0) {
        const alerts = await new Promise((resolve, reject) => {
          db.all('SELECT externalId, title FROM alerts ORDER BY date DESC LIMIT 1000', [], (err, rows) => {
            if (err) return reject(err);
            resolve(rows || []);
          });
        });
        cves = [...new Set(alerts.flatMap(alert => intelligenceService.extractCves(`${alert.externalId || ''} ${alert.title || ''}`)))];
      }
      cveRefreshJob = intelligenceService.enrichCves(db, cves)
        .catch(err => {
          console.error('CVE enrichment refresh failed:', err.message);
        })
        .finally(() => {
          cveRefreshJob = null;
        });

      res.status(202).json({ message: 'CVE enrichment refresh started', refreshed: cves.length });
    } catch (err) {
      cveRefreshJob = null;
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/risk-rules', async (req, res) => {
    try {
      const settings = await getSettings(db);
      res.json({
        weights: parseJson(settings.RISK_WEIGHTS, {}),
        notificationRules: parseJson(settings.NOTIFICATION_RULES, [])
      });
    } catch (err) {
      res.status(500).json({ error: 'Failed to load risk rules' });
    }
  });

  router.put('/risk-rules', async (req, res) => {
    if (!req.user || req.user.role !== 'Admin') {
      return res.status(403).json({ error: 'Requires Admin role' });
    }
    try {
      const weights = req.body.weights || {};
      const notificationRules = Array.isArray(req.body.notificationRules) ? req.body.notificationRules : [];
      await upsertSetting(db, 'RISK_WEIGHTS', JSON.stringify(weights));
      await upsertSetting(db, 'NOTIFICATION_RULES', JSON.stringify(notificationRules));
      res.json({ message: 'Risk and notification rules saved' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
};
