const express = require('express');
const { outboundHttp: axios } = require('../services/outboundHttp');
const crypto = require('crypto');
const intelligence = require('../services/intelligence');
const settingsStore = require('../services/settingsStore');

function allAsync(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

function runAsync(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function getSettings(db) {
  return settingsStore.getSettings(db);
}

function normalizeQueryType(queryType, value) {
  if (queryType && queryType !== 'keyword') return queryType;
  const detected = intelligence.detectIndicatorType(value);
  if (detected === 'cve') return 'cve';
  if (['ip', 'ip:port', 'domain', 'url', 'md5', 'sha1', 'sha256'].includes(detected)) return 'ioc';
  return queryType || 'keyword';
}

function vtPathFor(value) {
  const type = intelligence.detectIndicatorType(value);
  if (type === 'domain') return `/domains/${encodeURIComponent(value)}`;
  if (type === 'ip' || type === 'ip:port') return `/ip_addresses/${encodeURIComponent(value.split(':')[0])}`;
  if (['md5', 'sha1', 'sha256'].includes(type)) return `/files/${encodeURIComponent(value)}`;
  if (type === 'url') {
    const id = Buffer.from(value).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    return `/urls/${id}`;
  }
  return null;
}

function otxIndicatorPath(value) {
  const type = intelligence.detectIndicatorType(value);
  if (type === 'domain') return `/indicators/domain/${encodeURIComponent(value)}/general`;
  if (type === 'ip' || type === 'ip:port') return `/indicators/IPv4/${encodeURIComponent(value.split(':')[0])}/general`;
  if (['md5', 'sha1', 'sha256'].includes(type)) return `/indicators/file/${encodeURIComponent(value)}/general`;
  if (type === 'url') return `/indicators/url/${encodeURIComponent(value)}/general`;
  return null;
}

async function localLookup(db, query) {
  const like = `%${query}%`;
  const [alerts, indicators, cves] = await Promise.all([
    allAsync(
      db,
      `SELECT id, source, externalId, title, severity, date, url, status, priority
       FROM alerts
       WHERE lower(title) LIKE lower(?) OR lower(externalId) LIKE lower(?) OR lower(url) LIKE lower(?)
       ORDER BY date DESC LIMIT 100`,
      [like, like, like]
    ),
    allAsync(
      db,
      `SELECT id, value, type, source, severity, confidence, first_seen, last_seen, malware_family
       FROM indicators
       WHERE lower(value) LIKE lower(?) OR lower(externalId) LIKE lower(?) OR lower(malware_family) LIKE lower(?)
       ORDER BY updated_at DESC LIMIT 100`,
      [like, like, like]
    ),
    allAsync(db, 'SELECT * FROM cve_enrichment WHERE cve_id = ?', [query.toUpperCase()])
  ]);

  return [
    ...alerts.map(alert => ({
      provider: 'ThreatDock Alerts',
      type: 'Local Alert',
      severity: alert.severity || 'Unknown',
      title: alert.externalId ? `${alert.externalId}: ${alert.title}` : alert.title,
      url: alert.url,
      date: alert.date,
      metadata: alert
    })),
    ...indicators.map(indicator => ({
      provider: 'ThreatDock Indicators',
      type: indicator.type,
      severity: indicator.severity || 'Unknown',
      title: `${indicator.value} (${indicator.source})`,
      date: indicator.last_seen,
      metadata: indicator
    })),
    ...cves.map(row => ({
      provider: 'ThreatDock CVE Enrichment',
      type: row.kev_known ? 'CISA KEV / EPSS' : 'EPSS',
      severity: row.kev_known ? 'Critical' : (row.epss_score >= 0.5 ? 'High' : 'Medium'),
      title: `${row.cve_id} EPSS ${row.epss_score || 0}${row.kev_known ? ' / Known exploited' : ''}`,
      date: row.updated_at,
      metadata: row
    }))
  ];
}

async function threatFoxLookup(settings, query) {
  const key = settings.THREATFOX_AUTH_KEY || process.env.THREATFOX_AUTH_KEY;
  if (!key) return [];
  const response = await axios.post(
    'https://threatfox-api.abuse.ch/api/v1/',
    { query: 'search_ioc', search_term: query },
    { headers: { 'Auth-Key': key, 'User-Agent': 'ThreatDock' }, timeout: 12000 }
  );
  const rows = response.data && Array.isArray(response.data.data) ? response.data.data : [];
  return rows.map(row => ({
    provider: 'ThreatFox',
    type: row.ioc_type || 'IOC',
    severity: 'High',
    title: row.ioc || row.indicator || query,
    date: row.first_seen,
    url: row.id ? `https://threatfox.abuse.ch/ioc/${row.id}` : '',
    metadata: row
  }));
}

async function otxLookup(settings, query) {
  const key = settings.OTX_API_KEY || process.env.OTX_API_KEY;
  if (!key) return [];
  const headers = { 'X-OTX-API-KEY': key, 'User-Agent': 'ThreatDock' };
  const results = [];

  const indicatorPath = otxIndicatorPath(query);
  if (indicatorPath) {
    const response = await axios.get(`https://otx.alienvault.com/api/v1${indicatorPath}`, { headers, timeout: 12000 });
    const pulseCount = response.data && Array.isArray(response.data.pulse_info && response.data.pulse_info.pulses)
      ? response.data.pulse_info.pulses.length
      : 0;
    results.push({
      provider: 'AlienVault OTX',
      type: 'Indicator Reputation',
      severity: pulseCount > 0 ? 'High' : 'Low',
      title: `${query} appears in ${pulseCount} OTX pulse(s)`,
      url: `https://otx.alienvault.com/indicator/${encodeURIComponent(query)}`,
      metadata: response.data
    });
  }

  const pulseResponse = await axios.get('https://otx.alienvault.com/api/v1/search/pulses', {
    headers,
    params: { q: query, limit: 20 },
    timeout: 12000
  });
  const pulses = pulseResponse.data && Array.isArray(pulseResponse.data.results) ? pulseResponse.data.results : [];
  pulses.forEach(pulse => results.push({
    provider: 'AlienVault OTX',
    type: 'Pulse Match',
    severity: pulse.indicator_count > 10 ? 'High' : 'Medium',
    title: pulse.name || `OTX pulse for ${query}`,
    date: pulse.modified || pulse.created,
    url: pulse.id ? `https://otx.alienvault.com/pulse/${pulse.id}` : '',
    metadata: pulse
  }));

  return results;
}

async function virusTotalLookup(settings, query) {
  const key = settings.VIRUSTOTAL_API_KEY || process.env.VIRUSTOTAL_API_KEY;
  const path = vtPathFor(query);
  if (!key || !path) return [];
  const response = await axios.get(`https://www.virustotal.com/api/v3${path}`, {
    headers: { 'x-apikey': key },
    timeout: 12000
  });
  const attrs = response.data && response.data.data && response.data.data.attributes;
  const malicious = attrs && attrs.last_analysis_stats ? attrs.last_analysis_stats.malicious || 0 : 0;
  return [{
    provider: 'VirusTotal Community',
    type: 'Reputation',
    severity: malicious > 0 ? 'High' : 'Low',
    title: `${query} reputation: ${malicious} malicious engine(s)`,
    url: `https://www.virustotal.com/gui/search/${encodeURIComponent(query)}`,
    metadata: attrs || response.data
  }];
}

async function urlScanLookup(settings, query) {
  const key = settings.URLSCAN_API_KEY || process.env.URLSCAN_API_KEY;
  const headers = key ? { 'API-Key': key } : {};
  const response = await axios.get('https://urlscan.io/api/v1/search/', {
    headers,
    params: { q: query, size: 25 },
    timeout: 12000
  });
  const rows = response.data && Array.isArray(response.data.results) ? response.data.results : [];
  return rows.map(row => ({
    provider: 'URLScan.io',
    type: row.verdicts && row.verdicts.overall && row.verdicts.overall.malicious ? 'Malicious URL Observation' : 'URL Observation',
    severity: row.verdicts && row.verdicts.overall && row.verdicts.overall.malicious ? 'High' : 'Low',
    title: row.page && (row.page.title || row.page.url || row.page.domain) || `URLScan result for ${query}`,
    date: row.task && row.task.time,
    url: row.result || (row.task && row.task.url),
    metadata: row
  }));
}

async function mispLookup(settings, query) {
  const baseUrl = settings.MISP_URL || process.env.MISP_URL;
  const key = settings.MISP_API_KEY || process.env.MISP_API_KEY;
  if (!baseUrl || !key) return [];
  const response = await axios.post(
    `${baseUrl.replace(/\/$/, '')}/attributes/restSearch`,
    { value: query, limit: 50, returnFormat: 'json' },
    {
      headers: { Authorization: key, Accept: 'application/json', 'Content-Type': 'application/json' },
      timeout: 12000,
      validateStatus: status => status >= 200 && status < 500
    }
  );
  const attrs = response.data && Array.isArray(response.data.response && response.data.response.Attribute)
    ? response.data.response.Attribute
    : [];
  return attrs.map(attr => ({
    provider: 'MISP',
    type: attr.type || 'Attribute',
    severity: attr.to_ids ? 'High' : 'Medium',
    title: `${attr.value} (${attr.category || 'MISP'})`,
    date: attr.timestamp ? new Date(parseInt(attr.timestamp, 10) * 1000).toISOString() : '',
    url: baseUrl,
    metadata: attr
  }));
}

function uniqueResults(results) {
  const seen = new Set();
  return results.filter(result => {
    const key = crypto.createHash('sha1').update(`${result.provider}:${result.type}:${result.title}:${result.url || ''}`).digest('hex');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

module.exports = function createHuntRouter(db) {
  const router = express.Router();

  router.post('/', async (req, res) => {
    const queryValue = String(req.body.query_value || req.body.query || '').trim();
    const queryType = normalizeQueryType(req.body.query_type, queryValue);
    const user = req.user ? req.user.preferred_username || req.user.name || req.user.email || 'Anonymous' : 'Anonymous';

    if (!queryValue) return res.status(400).json({ error: 'query_value is required' });

    try {
      const settings = await getSettings(db);
      const providers = ['ThreatDock Alerts', 'ThreatDock Indicators'];
      const lookups = [
        localLookup(db, queryValue),
        threatFoxLookup(settings, queryValue).then(rows => { if (rows.length) providers.push('ThreatFox'); return rows; }).catch(err => [{ provider: 'ThreatFox', type: 'Provider Error', severity: 'Low', title: err.message }]),
        otxLookup(settings, queryValue).then(rows => { if (rows.length) providers.push('AlienVault OTX'); return rows; }).catch(err => [{ provider: 'AlienVault OTX', type: 'Provider Error', severity: 'Low', title: err.message }]),
        virusTotalLookup(settings, queryValue).then(rows => { if (rows.length) providers.push('VirusTotal Community'); return rows; }).catch(err => [{ provider: 'VirusTotal Community', type: 'Provider Error', severity: 'Low', title: err.message }]),
        urlScanLookup(settings, queryValue).then(rows => { if (rows.length) providers.push('URLScan.io'); return rows; }).catch(err => [{ provider: 'URLScan.io', type: 'Provider Error', severity: 'Low', title: err.message }]),
        mispLookup(settings, queryValue).then(rows => { if (rows.length) providers.push('MISP'); return rows; }).catch(err => [{ provider: 'MISP', type: 'Provider Error', severity: 'Low', title: err.message }])
      ];

      const results = uniqueResults((await Promise.all(lookups)).flat()).slice(0, 300);
      const payload = {
        status: 'success',
        query_type: queryType,
        query_value: queryValue,
        providers: [...new Set(providers)],
        hits: results.length,
        results
      };

      const saved = await runAsync(
        db,
        'INSERT INTO hunt_queries (query_type, query_value, results, user) VALUES (?, ?, ?, ?)',
        [queryType, queryValue, JSON.stringify(payload), user]
      );

      res.status(201).json({ id: saved.lastID, ...payload });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/history', (req, res) => {
    db.all('SELECT id, query_type, query_value, results, created_at, user FROM hunt_queries ORDER BY created_at DESC LIMIT 50', (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  });

  return router;
};
