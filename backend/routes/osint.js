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

module.exports = function createOsintRouter(db) {
  const router = express.Router();

  router.post('/digital-risk/search', async (req, res) => {
    const keyword = String(req.body.keyword || '').trim();
    if (!keyword) return res.status(400).json({ error: 'Keyword, email, username, or identity is required' });

    try {
      const settings = await getSettings(db);
      const results = [];
      const providers = [];

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
              'Dark web and credential leak search requires provider API keys such as HIBP_API_KEY, INTELX_API_KEY, DeHashed, SpyCloud, or SOCRadar.',
              'Without those keys, ThreatDock returns local threat-intel matches only.'
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
      const results = [];
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
              'Certificate Transparency lookup is available for domains.',
              'Recommended phishing/typosquatting APIs: URLScan, DNSTwist, SecurityTrails, Silent Push, SOCRadar, or Bolster.'
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
