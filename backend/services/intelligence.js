const axios = require('axios');
const { cache } = require('./queue');

const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const FIRST_EPSS_URL = 'https://api.first.org/data/v1/epss';

const severityOrder = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  Unknown: 0
};

function runAsync(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function allAsync(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

function normalizeSeverity(value) {
  const v = String(value || '').toLowerCase();
  if (v === 'critical') return 'Critical';
  if (v === 'high') return 'High';
  if (v === 'medium' || v === 'moderate') return 'Medium';
  if (v === 'low') return 'Low';
  return 'Unknown';
}

function maxSeverity(items) {
  return items
    .map(item => normalizeSeverity(item.severity))
    .sort((a, b) => severityOrder[b] - severityOrder[a])[0] || 'Unknown';
}

function extractCves(text) {
  const matches = String(text || '').match(/CVE-\d{4}-\d{4,}/gi) || [];
  return [...new Set(matches.map(cve => cve.toUpperCase()))];
}

function extractDomains(text) {
  const matches = String(text || '').match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi) || [];
  return [...new Set(matches.map(domain => domain.toLowerCase()))]
    .filter(domain => !domain.endsWith('.js') && !domain.endsWith('.css'));
}

function detectIndicatorType(value) {
  const v = String(value || '').trim();
  if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return 'cve';
  if (/^https?:\/\//i.test(v)) return 'url';
  if (/^[a-f0-9]{32}$/i.test(v)) return 'md5';
  if (/^[a-f0-9]{40}$/i.test(v)) return 'sha1';
  if (/^[a-f0-9]{64}$/i.test(v)) return 'sha256';
  if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(v)) return v.includes(':') ? 'ip:port' : 'ip';
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return 'email';
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) return 'domain';
  return 'keyword';
}

function confidenceForAlert(alert, type) {
  if (alert.source === 'ThreatFox') return 85;
  if (alert.source === 'OTX') return 70;
  if (type === 'cve') return 75;
  return 55;
}

async function saveIndicatorsFromAlerts(db, alerts) {
  const candidates = [];

  for (const alert of alerts || []) {
    const text = `${alert.externalId || ''} ${alert.title || ''} ${alert.url || ''}`;
    for (const cve of extractCves(text)) {
      candidates.push({ value: cve, type: 'cve', alert });
    }

    if (alert.source === 'ThreatFox') {
      const value = String(alert.title || '').trim();
      if (value) candidates.push({ value, type: detectIndicatorType(value), alert });
    }

    if (alert.source === 'OTX' && /^https?:\/\//i.test(String(alert.url || ''))) {
      candidates.push({ value: alert.url, type: 'url', alert });
    }
  }

  // Deduplicate candidates by (source, value, type) before batch insert
  const seen = new Set();
  const unique = [];
  for (const item of candidates) {
    const key = `${item.alert.source || 'ThreatDock'}:${item.value}:${item.type}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(item);
  }

  // Batch INSERT
  const BATCH_SIZE = 1000;
  for (let i = 0; i < unique.length; i += BATCH_SIZE) {
    const batch = unique.slice(i, i + BATCH_SIZE);
    const values = [];
    const params = [];
    let idx = 0;
    for (const item of batch) {
      const now = new Date().toISOString();
      const n = idx * 9;
      values.push(`($${n+1},$${n+2},$${n+3},$${n+4},$${n+5},$${n+6},$${n+7},$${n+8},$${n+9},CURRENT_TIMESTAMP)`);
      params.push(
        item.value,
        item.type,
        item.alert.source || 'ThreatDock',
        item.alert.externalId || '',
        normalizeSeverity(item.alert.severity),
        confidenceForAlert(item.alert, item.type),
        item.alert.date || now,
        now,
        JSON.stringify({ alertTitle: item.alert.title || '', alertUrl: item.alert.url || '' })
      );
      idx++;
    }
    await db.query(`
      INSERT INTO indicators (value, type, source, externalId, severity, confidence, first_seen, last_seen, metadata, updated_at)
      VALUES ${values.join(', ')}
      ON CONFLICT(source, value, type) DO UPDATE SET
        severity = excluded.severity,
        confidence = excluded.confidence,
        last_seen = excluded.last_seen,
        metadata = excluded.metadata,
        updated_at = CURRENT_TIMESTAMP
    `, params);
  }
}

function addGroup(groups, groupKey, title, alert, indicator, entityRef) {
  if (!groups.has(groupKey)) {
    groups.set(groupKey, {
      groupKey,
      title,
      alerts: [],
      indicators: [],
      sources: new Set(),
      entityRefs: new Set()
    });
  }

  const group = groups.get(groupKey);
  if (alert) {
    group.alerts.push(alert);
    if (alert.source) group.sources.add(alert.source);
  }
  if (indicator) {
    group.indicators.push(indicator);
    if (indicator.source) group.sources.add(indicator.source);
  }
  if (entityRef) group.entityRefs.add(entityRef);
}

async function rebuildCorrelations(db) {
  // Check cache — skip if correlations were rebuilt in the last 5 minutes
  const cached = await cache.get('correlations:rebuilt');
  if (cached) return;

  const [alerts, indicators, assets, vendors] = await Promise.all([
    allAsync(db, 'SELECT id, source, externalId, title, severity, date, url FROM alerts ORDER BY date DESC LIMIT 5000'),
    allAsync(db, 'SELECT id, value, type, source, severity FROM indicators ORDER BY updated_at DESC LIMIT 5000'),
    allAsync(db, 'SELECT id, domain, ip FROM assets'),
    allAsync(db, 'SELECT id, name FROM vendors')
  ]);

  const groups = new Map();

  for (const alert of alerts) {
    const text = `${alert.externalId || ''} ${alert.title || ''} ${alert.url || ''}`;
    for (const cve of extractCves(text)) {
      addGroup(groups, `cve:${cve}`, cve, alert, null, cve);
    }
    for (const domain of extractDomains(text)) {
      addGroup(groups, `domain:${domain}`, domain, alert, null, domain);
    }
  }

  for (const indicator of indicators) {
    const key = `${indicator.type}:${String(indicator.value || '').toLowerCase()}`;
    addGroup(groups, key, indicator.value, null, indicator, indicator.value);
  }

  // Build reverse index: word → [groupKey] for O(m) asset matching instead of O(n * m)
  const wordIndex = new Map();
  for (const [key, group] of groups.entries()) {
    const words = key.toLowerCase().split(/[:.\s-]+/);
    for (const word of words) {
      if (word.length < 2) continue;
      if (!wordIndex.has(word)) wordIndex.set(word, []);
      wordIndex.get(word).push(key);
    }
  }

  for (const asset of assets) {
    const values = [asset.domain, asset.ip].filter(Boolean).map(value => String(value).toLowerCase());
    for (const value of values) {
      const matched = new Set();
      // Check direct key match first
      for (const [key] of groups) {
        if (key.includes(value)) matched.add(key);
      }
      // Then check via word index for partial matches
      const valueWords = value.split(/[:.\s-]+/);
      for (const w of valueWords) {
        if (w.length < 2) continue;
        const idxHits = wordIndex.get(w);
        if (idxHits) idxHits.forEach(k => matched.add(k));
      }
      for (const key of matched) {
        const group = groups.get(key);
        if (group) group.entityRefs.add(`asset:${asset.id}:${asset.domain || asset.ip}`);
      }
    }
  }

  // Pre-index alert text for O(v * 1) vendor matching instead of O(v * a)
  const alertTexts = alerts.map(alert => ({
    alert,
    text: `${alert.title || ''} ${alert.source || ''}`.toLowerCase()
  }));
  for (const vendor of vendors) {
    const name = String(vendor.name || '').toLowerCase();
    if (!name) continue;
    for (const { alert, text } of alertTexts) {
      if (text.includes(name)) {
        addGroup(groups, `vendor:${name}`, vendor.name, alert, null, `vendor:${vendor.id}:${vendor.name}`);
      }
    }
  }

  // Batch INSERT correlated findings
  const BATCH_SIZE = 500;
  const entries = [];
  for (const group of groups.values()) {
    const allItems = [...group.alerts, ...group.indicators];
    if (allItems.length === 0) continue;
    const severity = maxSeverity(allItems);
    const sourceCount = group.sources.size;
    const score = Math.min(100, (severityOrder[severity] || 0) * 20 + sourceCount * 8 + allItems.length * 2);
    const confidence = Math.min(100, 45 + sourceCount * 15 + Math.min(allItems.length * 5, 30));
    entries.push({
      groupKey: group.groupKey,
      title: group.title || group.groupKey,
      severity,
      score,
      confidence,
      sources: JSON.stringify([...group.sources]),
      alertIds: JSON.stringify(group.alerts.map(a => a.id).filter(Boolean)),
      indicatorIds: JSON.stringify(group.indicators.map(i => i.id).filter(Boolean)),
      entityRefs: JSON.stringify([...group.entityRefs])
    });
  }

  for (let i = 0; i < entries.length; i += BATCH_SIZE) {
    const batch = entries.slice(i, i + BATCH_SIZE);
    const values = [];
    const params = [];
    let idx = 0;
    for (const e of batch) {
      const n = idx * 9;
      values.push(`($${n+1},$${n+2},$${n+3},$${n+4},$${n+5},$${n+6},$${n+7},$${n+8},$${n+9},'Open',CURRENT_TIMESTAMP)`);
      params.push(e.groupKey, e.title, e.severity, e.score, e.confidence, e.sources, e.alertIds, e.indicatorIds, e.entityRefs);
      idx++;
    }
    await db.query(`
      INSERT INTO correlated_findings (group_key, title, severity, score, confidence, sources, alert_ids, indicator_ids, entity_refs, status, updated_at)
      VALUES ${values.join(', ')}
      ON CONFLICT(group_key) DO UPDATE SET
        title = excluded.title, severity = excluded.severity, score = excluded.score,
        confidence = excluded.confidence, sources = excluded.sources,
        alert_ids = excluded.alert_ids, indicator_ids = excluded.indicator_ids,
        entity_refs = excluded.entity_refs, updated_at = CURRENT_TIMESTAMP
    `, params);
  }

  // Cache rebuilt flag for 5 minutes so subsequent calls in the same window skip
  await cache.set('correlations:rebuilt', true, 5 * 60 * 1000);
}

async function fetchKevMap() {
  const response = await axios.get(CISA_KEV_URL, { timeout: 15000 });
  const vulnerabilities = response.data && Array.isArray(response.data.vulnerabilities)
    ? response.data.vulnerabilities
    : [];
  const map = new Map();
  vulnerabilities.forEach(item => {
    if (item.cveID) map.set(String(item.cveID).toUpperCase(), item);
  });
  return map;
}

async function fetchEpssMap(cveIds) {
  const map = new Map();
  for (let i = 0; i < cveIds.length; i += 100) {
    const chunk = cveIds.slice(i, i + 100);
    const response = await axios.get(FIRST_EPSS_URL, {
      params: { cve: chunk.join(',') },
      timeout: 15000
    });
    const rows = response.data && Array.isArray(response.data.data) ? response.data.data : [];
    rows.forEach(row => {
      if (row.cve) {
        map.set(String(row.cve).toUpperCase(), {
          epss: parseFloat(row.epss),
          percentile: parseFloat(row.percentile)
        });
      }
    });
  }
  return map;
}

async function enrichCves(db, cveIds) {
  let uniqueCves = [...new Set((cveIds || []).map(cve => String(cve).toUpperCase()))].slice(0, 300);
  if (uniqueCves.length === 0) return;

  // Skip CVE yang masih fresh (< 24 jam)
  try {
    const freshRows = await allAsync(db,
      `SELECT cve_id FROM cve_enrichment WHERE updated_at > CURRENT_TIMESTAMP - INTERVAL '24 hours'`
    );
    const freshSet = new Set(freshRows.map(r => r.cve_id));
    uniqueCves = uniqueCves.filter(cve => !freshSet.has(cve));
    if (uniqueCves.length === 0) return;
  } catch (e) {
    // Jika query gagal (misal tipe DB), lanjutkan tanpa filter
  }

  const [kevMap, epssMap] = await Promise.all([
    fetchKevMap().catch(() => new Map()),
    fetchEpssMap(uniqueCves).catch(() => new Map())
  ]);

  // Batch INSERT
  const BATCH_SIZE = 500;
  for (let i = 0; i < uniqueCves.length; i += BATCH_SIZE) {
    const batch = uniqueCves.slice(i, i + BATCH_SIZE);
    const values = [];
    const params = [];
    let idx = 0;
    for (const cve of batch) {
      const kev = kevMap.get(cve);
      const epss = epssMap.get(cve);
      const n = idx * 8;
      values.push(`($${n+1},$${n+2},$${n+3},$${n+4},$${n+5},$${n+6},$${n+7},$${n+8},CURRENT_TIMESTAMP)`);
      params.push(
        cve,
        epss && Number.isFinite(epss.epss) ? epss.epss : null,
        epss && Number.isFinite(epss.percentile) ? epss.percentile : null,
        kev ? 1 : 0,
        kev ? kev.dateAdded || '' : '',
        kev ? kev.dueDate || '' : '',
        kev ? kev.requiredAction || '' : '',
        kev ? kev.knownRansomwareCampaignUse || '' : ''
      );
      idx++;
    }
    await db.query(`
      INSERT INTO cve_enrichment (cve_id, epss_score, epss_percentile, kev_known, kev_date_added, kev_due_date, kev_required_action, ransomware_use, updated_at)
      VALUES ${values.join(', ')}
      ON CONFLICT(cve_id) DO UPDATE SET
        epss_score = excluded.epss_score,
        epss_percentile = excluded.epss_percentile,
        kev_known = excluded.kev_known,
        kev_date_added = excluded.kev_date_added,
        kev_due_date = excluded.kev_due_date,
        kev_required_action = excluded.kev_required_action,
        ransomware_use = excluded.ransomware_use,
        updated_at = CURRENT_TIMESTAMP
    `, params);
  }
}

module.exports = {
  detectIndicatorType,
  extractCves,
  extractDomains,
  normalizeSeverity,
  maxSeverity,  // used by worker.js
  rebuildCorrelations,
  saveIndicatorsFromAlerts,
  enrichCves,
  severityOrder
};
