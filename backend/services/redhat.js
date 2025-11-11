const axios = require('axios');

/**
 * Fetch recent Red Hat CVEs from Red Hat's public security data API.
 * Retrieves CVEs published in the last seven days.
 * @returns {Promise<Array>} An array of Red Hat CVE objects
 */
async function fetchRedHatCves() {
  const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const afterDate = weekAgo.toISOString().split('T')[0]; // YYYY-MM-DD
  const url = `https://access.redhat.com/hydra/rest/securitydata/cve.json?after=${afterDate}`;
  try {
    const response = await axios.get(url);
    return response.data || [];
  } catch (error) {
    console.error('Red Hat CVEs fetch failed:', error.message);
    return [];
  }
}

module.exports = { fetchRedHatCves };