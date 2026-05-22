const express = require('express');
const axios = require('axios');

function getSettings(db) {
  return new Promise((resolve, reject) => {
    db.all('SELECT key, value FROM settings', [], (err, rows) => {
      if (err) return reject(err);
      const settings = {};
      rows.forEach(r => { settings[r.key] = r.value; });
      resolve(settings);
    });
  });
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

function buildHeaders(key, name) {
  return key ? { [name]: key } : {};
}

module.exports = function createOsintRouter(db) {
  const router = express.Router();

  router.post('/digital-risk/search', async (req, res) => {
    const keyword = String(req.body.keyword || '').trim();
    if (!keyword) return res.status(400).json({ error: 'Keyword, email, username, or identity is required' });

    try {
      const settings = await getSettings(db);
      const results = [];
      const providers = [];
      const otxKey = settings.OTX_API_KEY || process.env.OTX_API_KEY;
      const urlscanKey = settings.URLSCAN_API_KEY || process.env.URLSCAN_API_KEY;

      const hibpKey = settings.HIBP_API_KEY || process.env.HIBP_API_KEY;
      if (hibpKey && keyword.includes('@')) {
        providers.push('Have I Been Pwned');
        try {
          const response = await axios.get(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(keyword)}`, {
            headers: {
              'hibp-api-key': hibpKey,
              'User-Agent': 'ThreatDock'
            },
            params: { truncateResponse: false },
            timeout: 10000,
            validateStatus: status => [200, 404].includes(status)
          });
          if (response.status === 200 && Array.isArray(response.data)) {
            response.data.forEach(item => results.push({
              provider: 'Have I Been Pwned',
              type: 'Credential Breach',
              title: item.Title || item.Name,
              severity: item.IsVerified === false ? 'Medium' : 'High',
              date: item.BreachDate,
              url: item.Domain ? `https://${item.Domain}` : 'https://haveibeenpwned.com/',
              description: item.Description ? item.Description.replace(/<[^>]+>/g, '') : ''
            }));
          }
        } catch (err) {
          results.push({ provider: 'Have I Been Pwned', type: 'Provider Error', severity: 'Low', title: err.message });
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
          headers: buildHeaders(urlscanKey, 'API-Key'),
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
        `SELECT source, externalId, title, severity, date, url
         FROM alerts
         WHERE lower(title) LIKE lower(?) OR lower(externalId) LIKE lower(?)
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

          res.json({
            keyword,
            providers,
            results: uniqueBy(results, item => `${item.provider}:${item.title}:${item.url || ''}`),
            notes: [
              'Free/community coverage uses URLScan.io and AlienVault OTX API keys for internet and threat-intel mentions.',
              'Credential and dark-web breach depth improves with HIBP_API_KEY and INTELX_API_KEY; without keys, results are limited to public/community sources and local alerts.'
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
      const normalizedDomain = brand.includes('.') ? brand : null;
      const settings = await getSettings(db);
      const results = [];
      const otxKey = settings.OTX_API_KEY || process.env.OTX_API_KEY;
      const urlscanKey = settings.URLSCAN_API_KEY || process.env.URLSCAN_API_KEY;
      const vtKey = settings.VIRUSTOTAL_API_KEY || process.env.VIRUSTOTAL_API_KEY;
      if (normalizedDomain) {
        try {
          const crtResponse = await axios.get(`https://crt.sh/?q=${encodeURIComponent(normalizedDomain)}&output=json`, {
            timeout: 10000,
            validateStatus: status => status >= 200 && status < 500
          });
          if (Array.isArray(crtResponse.data)) {
            uniqueBy(crtResponse.data, row => row.name_value)
              .slice(0, 100)
              .forEach(row => results.push({
                provider: 'crt.sh',
                type: 'Certificate Transparency',
                title: row.name_value,
                severity: row.name_value && row.name_value.includes('*') ? 'Low' : 'Medium',
                date: row.entry_timestamp,
                url: `https://crt.sh/?id=${row.id}`,
                description: row.issuer_name
              }));
          }
        } catch (err) {
          results.push({ provider: 'crt.sh', type: 'Provider Error', severity: 'Low', title: err.message });
        }
      }

      try {
        const response = await axios.get('https://urlscan.io/api/v1/search/', {
          headers: buildHeaders(urlscanKey, 'API-Key'),
          params: { q: normalizedDomain ? `domain:${normalizedDomain}` : brand, size: 50 },
          timeout: 10000
        });
        (response.data.results || []).forEach(item => results.push({
          provider: 'URLScan.io',
          type: item.verdicts && item.verdicts.overall && item.verdicts.overall.malicious ? 'Suspicious Brand Exposure' : 'Brand / Domain Observation',
          title: (item.page && (item.page.url || item.page.domain)) || `URLScan result for ${brand}`,
          severity: item.verdicts && item.verdicts.overall && item.verdicts.overall.malicious ? 'High' : 'Low',
          date: item.task && item.task.time,
          url: item.result || (item.task && item.task.url),
          description: item.page && item.page.ip
        }));
      } catch (err) {
        results.push({ provider: 'URLScan.io', type: 'Provider Error', severity: 'Low', title: err.message });
      }

      if (otxKey) {
        try {
          const response = await axios.get('https://otx.alienvault.com/api/v1/search/pulses', {
            headers: { 'X-OTX-API-KEY': otxKey },
            params: { q: brand, limit: 20 },
            timeout: 10000
          });
          (response.data.results || []).forEach(pulse => results.push({
            provider: 'AlienVault OTX',
            type: 'Threat Intel Brand Mention',
            title: pulse.name || `OTX pulse for ${brand}`,
            severity: pulse.indicator_count > 10 ? 'High' : 'Medium',
            date: pulse.modified || pulse.created,
            url: pulse.id ? `https://otx.alienvault.com/pulse/${pulse.id}` : 'https://otx.alienvault.com/',
            description: pulse.description || ''
          }));
        } catch (err) {
          results.push({ provider: 'AlienVault OTX', type: 'Provider Error', severity: 'Low', title: err.message });
        }
      }

      if (vtKey && normalizedDomain) {
        try {
          const response = await axios.get(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(normalizedDomain)}`, {
            headers: { 'x-apikey': vtKey },
            timeout: 10000
          });
          const attrs = response.data.data && response.data.data.attributes;
          if (attrs) {
            const malicious = attrs.last_analysis_stats && attrs.last_analysis_stats.malicious;
            results.push({
              provider: 'VirusTotal Community',
              type: 'Domain Reputation',
              title: `${normalizedDomain} reputation: ${malicious || 0} malicious engine(s)`,
              severity: malicious > 0 ? 'High' : 'Low',
              date: attrs.last_modification_date ? new Date(attrs.last_modification_date * 1000).toISOString() : undefined,
              url: `https://www.virustotal.com/gui/domain/${encodeURIComponent(normalizedDomain)}`,
              description: attrs.reputation !== undefined ? `Reputation: ${attrs.reputation}` : ''
            });
          }
        } catch (err) {
          results.push({ provider: 'VirusTotal Community', type: 'Provider Error', severity: 'Low', title: err.message });
        }
      }

      db.all(
        `SELECT source, externalId, title, severity, date, url
         FROM alerts
         WHERE lower(title) LIKE lower(?) OR lower(url) LIKE lower(?)
         ORDER BY date DESC
         LIMIT 50`,
        [`%${brand}%`, `%${brand}%`],
        (err, rows) => {
          if (err) return res.status(500).json({ error: err.message });
          rows.forEach(row => results.push({
            provider: row.source,
            type: 'Brand Mention',
            title: row.title,
            severity: row.severity || 'Unknown',
            date: row.date,
            url: row.url,
            description: row.externalId
          }));

          res.json({
            brand,
            results: uniqueBy(results, item => `${item.provider}:${item.title}:${item.url || ''}`),
            notes: [
              'Free/community coverage uses crt.sh, URLScan.io, AlienVault OTX, and VirusTotal Community.',
              'Use URLSCAN_API_KEY, OTX_API_KEY, and VIRUSTOTAL_API_KEY in Settings for richer brand exposure data.'
            ]
          });
        }
      );
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
};
