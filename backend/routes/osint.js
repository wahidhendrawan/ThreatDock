const express = require('express');
const { outboundHttp: axios } = require('../services/outboundHttp');
const settingsStore = require('../services/settingsStore');
const osintService = require('../services/osint');

function getSettings(db) {
  return settingsStore.getSettings(db);
}

function uniqueBy(items, keyFn) {
  const seen = new Set();
  return items.filter(item => {
    const key = keyFn(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

module.exports = function createOsintRouter(db) {
  const router = express.Router();

  router.get('/findings', (req, res) => {
    const { category, keyword } = req.query;
    const conditions = [];
    const params = [];
    if (category) {
      conditions.push('category = ?');
      params.push(category);
    }
    if (keyword) {
      conditions.push('lower(keyword) LIKE lower(?)');
      params.push(`%${keyword}%`);
    }
    let query = 'SELECT * FROM osint_findings';
    if (conditions.length > 0) query += ` WHERE ${conditions.join(' AND ')}`;
    query += ' ORDER BY created_at DESC LIMIT 500';
    db.all(query, params, (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  });

  router.post('/digital-risk/search', async (req, res) => {
    const keyword = String(req.body.keyword || '').trim();
    if (!keyword) return res.status(400).json({ error: 'Keyword, email, username, or identity is required' });

    try {
      const settings = await getSettings(db);
      const results = [];
      const providers = [];
      const otxKey = settings.OTX_API_KEY || process.env.OTX_API_KEY;
      const urlscanKey = settings.URLSCAN_API_KEY || process.env.URLSCAN_API_KEY;

      const breachDirectoryKey = settings.BREACHDIRECTORY_RAPIDAPI_KEY || process.env.BREACHDIRECTORY_RAPIDAPI_KEY;
      const breachDirectoryHost = settings.BREACHDIRECTORY_RAPIDAPI_HOST || process.env.BREACHDIRECTORY_RAPIDAPI_HOST || 'breachdirectory.p.rapidapi.com';
      if (breachDirectoryKey) {
        providers.push('BreachDirectory');
        try {
          const response = await axios.get(`https://${breachDirectoryHost}/`, {
            headers: {
              'x-rapidapi-key': breachDirectoryKey,
              'x-rapidapi-host': breachDirectoryHost,
              'User-Agent': 'ThreatDock'
            },
            params: { func: 'auto', term: keyword },
            timeout: 12000,
            validateStatus: status => status >= 200 && status < 500
          });

          const data = response.data || {};
          const rawRecords = Array.isArray(data.result) ? data.result
            : Array.isArray(data.results) ? data.results
            : Array.isArray(data.data) ? data.data
            : Array.isArray(data.sources) ? data.sources.map(source => ({ sources: [source] }))
            : data.found || data.success ? [data] : [];

          rawRecords.forEach((item, index) => {
            const sources = Array.isArray(item.sources) ? item.sources.join(', ')
              : Array.isArray(item.source) ? item.source.join(', ')
              : item.sources || item.source || item.database || item.name || 'breach directory';
            const hasSecretMaterial = Boolean(item.password || item.hash || item.sha1 || item.has_password);
            results.push({
              provider: 'BreachDirectory',
              type: 'Credential Breach',
              title: `${keyword} found in ${sources || `breach record #${index + 1}`}`,
              severity: hasSecretMaterial ? 'High' : 'Medium',
              date: item.date || item.breach_date || new Date().toISOString(),
              url: 'https://rapidapi.com/Emi-K/api/breachdirectory',
              description: `BreachDirectory returned a match. Sources: ${sources}. Password/hash details are intentionally not stored by ThreatDock.`
            });
          });
          if (rawRecords.length === 0 && response.status !== 404) {
            results.push({
              provider: 'BreachDirectory',
              type: 'Credential Breach',
              severity: 'Low',
              title: `No BreachDirectory match for "${keyword}"`,
              description: 'The provider responded successfully but did not return breach records.'
            });
          }
        } catch (err) {
          results.push({ provider: 'BreachDirectory', type: 'Provider Error', severity: 'Low', title: err.message });
        }
      }

      const intelxKey = settings.INTELX_API_KEY || process.env.INTELX_API_KEY;
      if (intelxKey) {
        providers.push('Intelligence X');
        try {
          const response = await axios.post('https://2.intelx.io/intelligent/search', {
            term: keyword,
            maxresults: 20,
            media: 0,
            terminate: []
          }, {
            headers: { 'x-key': intelxKey },
            timeout: 10000
          });
          if (response.data && response.data.id) {
            results.push({
              provider: 'Intelligence X',
              type: 'Identity Exposure Search',
              title: `Search submitted for "${keyword}"`,
              severity: 'Medium',
              date: new Date().toISOString(),
              url: `https://intelx.io/?s=${encodeURIComponent(keyword)}`,
              description: `Search ID: ${response.data.id}`
            });
          }
        } catch (err) {
          results.push({ provider: 'Intelligence X', type: 'Provider Error', severity: 'Low', title: err.message });
        }
      }

      if (otxKey) {
        providers.push('AlienVault OTX');
        try {
          const response = await axios.get('https://otx.alienvault.com/api/v1/search/pulses', {
            headers: { 'X-OTX-API-KEY': otxKey },
            params: { q: keyword, limit: 20 },
            timeout: 10000
          });
          const pulses = response.data.results || [];
          pulses.forEach(pulse => results.push({
            provider: 'AlienVault OTX',
            type: 'Dark Web / Threat Intel Mention',
            title: pulse.name || `OTX pulse for ${keyword}`,
            severity: pulse.indicator_count > 10 ? 'High' : 'Medium',
            date: pulse.modified || pulse.created,
            url: pulse.id ? `https://otx.alienvault.com/pulse/${pulse.id}` : 'https://otx.alienvault.com/',
            description: pulse.description || ''
          }));
        } catch (err) {
          results.push({ provider: 'AlienVault OTX', type: 'Provider Error', severity: 'Low', title: err.message });
        }
      }

      providers.push('URLScan.io');
      try {
        const response = await axios.get('https://urlscan.io/api/v1/search/', {
          headers: (urlscanKey ? { 'API-Key': urlscanKey } : {}),
          params: { q: keyword, size: 25 },
          timeout: 10000
        });
        (response.data.results || []).forEach(item => results.push({
          provider: 'URLScan.io',
          type: 'Internet Exposure Mention',
          title: (item.page && (item.page.title || item.page.url || item.page.domain)) || `URLScan result for ${keyword}`,
          severity: item.verdicts && item.verdicts.overall && item.verdicts.overall.malicious ? 'High' : 'Low',
          date: item.task && item.task.time,
          url: item.result || (item.task && item.task.url),
          description: item.page && item.page.domain
        }));
      } catch (err) {
        results.push({ provider: 'URLScan.io', type: 'Provider Error', severity: 'Low', title: err.message });
      }

      db.all(
        `SELECT source, "externalId", title, severity, date, url
         FROM alerts
         WHERE lower(title) LIKE lower(?) OR lower("externalId") LIKE lower(?)
         ORDER BY date DESC
         LIMIT 50`,
        [`%${keyword}%`, `%${keyword}%`],
        (err, rows) => {
          if (err) return res.status(500).json({ error: err.message });
          rows.forEach(row => results.push({
            provider: row.source,
            type: 'Threat Intel Match',
            title: row.title,
            severity: row.severity || 'Unknown',
            date: row.date,
            url: row.url,
            description: row.externalId
          }));

          const uniqueResults = uniqueBy(results, item => `${item.provider}:${item.title}:${item.url || ''}`);
          osintService.saveFindings(db, 'digital-risk', keyword, uniqueResults);
          res.json({
            keyword,
            providers,
            results: uniqueResults,
            notes: [
              'Free/community coverage uses URLScan.io and AlienVault OTX API keys for internet and threat-intel mentions.',
              'Credential breach depth uses BREACHDIRECTORY_RAPIDAPI_KEY from RapidAPI and INTELX_API_KEY; without keys, results are limited to public/community sources and local alerts.'
            ]
          });
        }
      );
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post('/brand/search', async (req, res) => {
    const brand = String(req.body.brand || '').trim();
    if (!brand) return res.status(400).json({ error: 'Brand, domain, or product keyword is required' });

    try {
      const results = await osintService.searchBrandExposure(db, brand);
      osintService.saveFindings(db, 'brand-exposure', brand, results);
      res.json({
        brand,
        results,
        notes: [
          'Free/community coverage uses crt.sh, URLScan.io, AlienVault OTX, and VirusTotal Community.',
          'Use URLSCAN_API_KEY, OTX_API_KEY, and VIRUSTOTAL_API_KEY in Settings for richer brand exposure data.'
        ]
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
};

