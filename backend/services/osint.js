const { outboundHttp: axios } = require('./outboundHttp');
const settingsStore = require('./settingsStore');

function uniqueBy(items, keyFn) {
  const seen = new Set();
  return items.filter(item => {
    const key = String(keyFn(item)).toLowerCase().trim();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function contextualizeTitle(item, brand) {
  const provider = item.provider;
  const rawTitle = String(item.title || '');
  
  if (provider === 'crt.sh') {
    return `SSL/TLS Certificate issued for: ${rawTitle}`;
  }
  if (provider === 'URLScan.io') {
    return `Website interaction detected on: ${rawTitle}`;
  }
  if (provider === 'AlienVault OTX') {
    return `Threat intelligence mention in pulse: ${rawTitle}`;
  }
  if (provider === 'VirusTotal Community') {
    return `Domain reputation analysis for: ${rawTitle}`;
  }
  return rawTitle || `Exposure finding for ${brand}`;
}

function buildHeaders(key, name) {
  return key ? { [name]: key } : {};
}

async function searchBrandExposure(db, brand) {
  const normalizedDomain = brand.includes('.') ? brand : null;
  const settings = await settingsStore.getSettings(db);
  const results = [];
  const otxKey = settings.OTX_API_KEY;
  const urlscanKey = settings.URLSCAN_API_KEY;
  const vtKey = settings.VIRUSTOTAL_API_KEY;

  if (normalizedDomain) {
    try {
      const crtResponse = await axios.get(`https://crt.sh/?q=${encodeURIComponent(normalizedDomain)}&output=json`, {
        timeout: 10000,
        validateStatus: status => status >= 200 && status < 500
      });
      if (Array.isArray(crtResponse.data)) {
        crtResponse.data.forEach(row => results.push({
          provider: 'crt.sh',
          type: 'Certificate Transparency',
          title: contextualizeTitle({ provider: 'crt.sh', title: row.name_value }, brand),
          severity: row.name_value && row.name_value.includes('*') ? 'Low' : 'Medium',
          date: row.entry_timestamp,
          url: `https://crt.sh/?id=${row.id}`,
          description: `Issuer: ${row.issuer_name}`
        }));
      }
    } catch (err) {
      console.warn(`crt.sh search failed for ${brand}:`, err.message);
    }
  }

  try {
    const response = await axios.get('https://urlscan.io/api/v1/search/', {
      headers: buildHeaders(urlscanKey, 'API-Key'),
      params: { q: normalizedDomain ? `domain:${normalizedDomain}` : brand, size: 50 },
      timeout: 10000
    });
    (response.data.results || []).forEach(item => {
      const site = (item.page && (item.page.url || item.page.domain)) || brand;
      results.push({
        provider: 'URLScan.io',
        type: item.verdicts && item.verdicts.overall && item.verdicts.overall.malicious ? 'Suspicious Brand Exposure' : 'Brand / Domain Observation',
        title: contextualizeTitle({ provider: 'URLScan.io', title: site }, brand),
        severity: item.verdicts && item.verdicts.overall && item.verdicts.overall.malicious ? 'High' : 'Low',
        date: item.task && item.task.time,
        url: item.result || (item.task && item.task.url),
        description: `IP: ${item.page && item.page.ip} | Country: ${item.page && item.page.country}`
      });
    });
  } catch (err) {
    console.warn(`URLScan search failed for ${brand}:`, err.message);
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
        title: contextualizeTitle({ provider: 'AlienVault OTX', title: pulse.name }, brand),
        severity: pulse.indicator_count > 10 ? 'High' : 'Medium',
        date: pulse.modified || pulse.created,
        url: pulse.id ? `https://otx.alienvault.com/pulse/${pulse.id}` : 'https://otx.alienvault.com/',
        description: pulse.description || ''
      }));
    } catch (err) {
      console.warn(`OTX search failed for ${brand}:`, err.message);
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
          title: contextualizeTitle({ provider: 'VirusTotal Community', title: normalizedDomain }, brand),
          severity: malicious > 0 ? 'High' : 'Low',
          date: attrs.last_modification_date ? new Date(attrs.last_modification_date * 1000).toISOString() : undefined,
          url: `https://www.virustotal.com/gui/domain/${encodeURIComponent(normalizedDomain)}`,
          description: `Reputation Score: ${attrs.reputation} | Malicious: ${malicious || 0}`
        });
      }
    } catch (err) {
      console.warn(`VirusTotal search failed for ${brand}:`, err.message);
    }
  }

  // Also search local alerts
  return new Promise((resolve, reject) => {
    db.all(
      `SELECT source, "externalId", title, severity, date, url
       FROM alerts
       WHERE lower(title) LIKE lower(?) OR lower(url) LIKE lower(?)
       ORDER BY date DESC
       LIMIT 50`,
      [`%${brand}%`, `%${brand}%`],
      (err, rows) => {
        if (err) return reject(err);
        rows.forEach(row => results.push({
          provider: row.source,
          type: 'Brand Mention',
          title: row.title,
          severity: row.severity || 'Unknown',
          date: row.date,
          url: row.url,
          description: row.externalId
        }));

        const uniqueResults = uniqueBy(results, item => `${item.provider}:${item.title}:${item.url || ''}`);
        resolve(uniqueResults);
      }
    );
  });
}

function saveFindings(db, category, keyword, results) {
  const stmt = db.prepare(`
    INSERT INTO osint_findings (category, keyword, provider, type, title, severity, date, url, description, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
  `);
  results.slice(0, 200).forEach(item => {
    stmt.run(
      category,
      keyword,
      item.provider || '',
      item.type || '',
      item.title || '',
      item.severity || 'Unknown',
      item.date || '',
      item.url || '',
      item.description || ''
    );
  });
  stmt.finalize();
}

module.exports = {
  searchBrandExposure,
  saveFindings
};
