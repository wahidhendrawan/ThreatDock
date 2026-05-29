const axios = require('axios');

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

  for (const item of candidates) {
    const now = new Date().toISOString();
    await runAsync(
      db,
      `INSERT INTO indicators (value, type, source, externalId, severity, confidence, first_seen, last_seen, metadata, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(source, value, type) DO UPDATE SET
         severity = excluded.severity,
         confidence = excluded.confidence,
         last_seen = excluded.last_seen,
         metadata = excluded.metadata,
         updated_at = CURRENT_TIMESTAMP`,
      [
        item.value,
        item.type,
        item.alert.source || 'ThreatDock',
        item.alert.externalId || '',
        normalizeSeverity(item.alert.severity),
        confidenceForAlert(item.alert, item.type),
        item.alert.date || now,
        now,
        JSON.stringify({ alertTitle: item.alert.title || '', alertUrl: item.alert.url || '' })
      ]
    );
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
  const [alerts, indicators, assets, vendors] = await Promise.all([
    allAsync(db, 'SELECT * FROM alerts ORDER BY date DESC LIMIT 5000'),
    allAsync(db, 'SELECT * FROM indicators ORDER BY updated_at DESC LIMIT 5000'),
    allAsync(db, 'SELECT * FROM assets'),
    allAsync(db, 'SELECT * FROM vendors')
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

  for (const asset of assets) {
    const values = [asset.domain, asset.ip].filter(Boolean).map(value => String(value).toLowerCase());
    for (const value of values) {
      for (const [key, group] of groups.entries()) {
        if (key.includes(value)) group.entityRefs.add(`asset:${asset.id}:${asset.domain || asset.ip}`);
      }
    }
  }

  for (const vendor of vendors) {
    const name = String(vendor.name || '').toLowerCase();
    if (!name) continue;
    for (const alert of alerts) {
      const text = `${alert.title || ''} ${alert.source || ''}`.toLowerCase();
      if (text.includes(name)) {
        addGroup(groups, `vendor:${name}`, vendor.name, alert, null, `vendor:${vendor.id}:${vendor.name}`);
      }
    }
  }

  for (const group of groups.values()) {
    const allItems = [...group.alerts, ...group.indicators];
    if (allItems.length === 0) continue;
    const severity = maxSeverity(allItems);
    const sourceCount = group.sources.size;
    const score = Math.min(100, (severityOrder[severity] || 0) * 20 + sourceCount * 8 + allItems.length * 2);
    const confidence = Math.min(100, 45 + sourceCount * 15 + Math.min(allItems.length * 5, 30));

    await runAsync(
      db,
      `INSERT INTO correlated_findings (group_key, title, severity, score, confidence, sources, alert_ids, indicator_ids, entity_refs, status, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open', CURRENT_TIMESTAMP)
       ON CONFLICT(group_key) DO UPDATE SET
         title = excluded.title,
         severity = excluded.severity,
         score = excluded.score,
         confidence = excluded.confidence,
         sources = excluded.sources,
         alert_ids = excluded.alert_ids,
         indicator_ids = excluded.indicator_ids,
         entity_refs = excluded.entity_refs,
         updated_at = CURRENT_TIMESTAMP`,
      [
        group.groupKey,
        group.title || group.groupKey,
        severity,
        score,
        confidence,
        JSON.stringify([...group.sources]),
        JSON.stringify(group.alerts.map(alert => alert.id).filter(Boolean)),
        JSON.stringify(group.indicators.map(indicator => indicator.id).filter(Boolean)),
        JSON.stringify([...group.entityRefs])
      ]
    );
  }
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
  const uniqueCves = [...new Set((cveIds || []).map(cve => String(cve).toUpperCase()))].slice(0, 300);
  if (uniqueCves.length === 0) return;

  const [kevMap, epssMap] = await Promise.all([
    fetchKevMap().catch(() => new Map()),
    fetchEpssMap(uniqueCves).catch(() => new Map())
  ]);

  for (const cve of uniqueCves) {
    const kev = kevMap.get(cve);
    const epss = epssMap.get(cve);
    await runAsync(
      db,
      `INSERT INTO cve_enrichment (cve_id, epss_score, epss_percentile, kev_known, kev_date_added, kev_due_date, kev_required_action, ransomware_use, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(cve_id) DO UPDATE SET
         epss_score = excluded.epss_score,
         epss_percentile = excluded.epss_percentile,
         kev_known = excluded.kev_known,
         kev_date_added = excluded.kev_date_added,
         kev_due_date = excluded.kev_due_date,
         kev_required_action = excluded.kev_required_action,
         ransomware_use = excluded.ransomware_use,
         updated_at = CURRENT_TIMESTAMP`,
      [
        cve,
        epss && Number.isFinite(epss.epss) ? epss.epss : null,
        epss && Number.isFinite(epss.percentile) ? epss.percentile : null,
        kev ? 1 : 0,
        kev ? kev.dateAdded || '' : '',
        kev ? kev.dueDate || '' : '',
        kev ? kev.requiredAction || '' : '',
        kev ? kev.knownRansomwareCampaignUse || '' : ''
      ]
    );
  }
}

module.exports = {
  detectIndicatorType,
  extractCves,
  extractDomains,
  normalizeSeverity,
  rebuildCorrelations,
  saveIndicatorsFromAlerts,
  enrichCves,
  severityOrder
};
