const { outboundHttp: axios } = require('./outboundHttp');

/**
 * Fetch CVEs from NVD API — optimized for hourly ingestion.
 * Pulls CVEs from the last 24 hours only (runs hourly, no need for 7-day window).
 * Limits response to 100 results per page to reduce parsing overhead.
 */
async function fetchNvdCves() {
  const now = new Date();
  const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const fmt = (d) => d.toISOString().split('.')[0];

  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${fmt(dayAgo)}&pubEndDate=${fmt(now)}&resultsPerPage=100`;
  const headers = {};
  const apiKey = process.env.NVD_API_KEY;
  if (apiKey) headers['apiKey'] = apiKey;

  // AbortController for timeout
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await axios.get(url, { headers, signal: controller.signal });
    clearTimeout(timeout);

    // Only return what we need — strip heavy nested objects
    const raw = response.data || { vulnerabilities: [] };
    if (!Array.isArray(raw.vulnerabilities)) return { vulnerabilities: [] };

    // Minimize payload: extract only fields needed by app.js processing
    return {
      vulnerabilities: raw.vulnerabilities.map((item) => {
        const cve = item.cve || {};
        const metrics = cve.metrics || {};
        const descriptions = cve.descriptions || [];
        const enDesc = descriptions.find((d) => d.lang === 'en');

        return {
          cve: {
            id: cve.id,
            published: cve.published,
            lastModified: cve.lastModified,
            descriptions: enDesc ? [{ lang: 'en', value: enDesc.value }] : [],
            metrics: {
              cvssMetricV31: metrics.cvssMetricV31
                ? [{ cvssData: { baseSeverity: metrics.cvssMetricV31[0]?.cvssData?.baseSeverity } }]
                : undefined,
              cvssMetricV30: metrics.cvssMetricV30
                ? [{ cvssData: { baseSeverity: metrics.cvssMetricV30[0]?.cvssData?.baseSeverity } }]
                : undefined,
              cvssMetricV2: metrics.cvssMetricV2
                ? [{ cvssData: { baseScore: metrics.cvssMetricV2[0]?.cvssData?.baseScore } }]
                : undefined
            }
          }
        };
      })
    };
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('timeout of 10000ms exceeded');
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

module.exports = { fetchNvdCves };
