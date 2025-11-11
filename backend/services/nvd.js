const axios = require('axios');

/**
 * Fetch recent CVEs from the National Vulnerability Database (NVD) API.
 * Pulls CVEs published within the last 7 days. If an API key is provided,
 * it will be used to increase the request rate limit.
 * @returns {Promise<Object>} The response object containing vulnerabilities
 */
async function fetchNvdCves() {
  const now = new Date();
  const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  function formatDate(d) {
    // Format as YYYY-MM-DDTHH:MM:SS (no milliseconds)
    return d.toISOString().split('.')[0];
  }
  const startStr = formatDate(weekAgo);
  const endStr = formatDate(now);
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${startStr}&pubEndDate=${endStr}`;
  const headers = {};
  const apiKey = process.env.NVD_API_KEY;
  if (apiKey) {
    headers['apiKey'] = apiKey;
  }
  try {
    const response = await axios.get(url, { headers });
    return response.data || { vulnerabilities: [] };
  } catch (error) {
    console.error('NVD CVE fetch failed:', error.message);
    return { vulnerabilities: [] };
  }
}

module.exports = { fetchNvdCves };