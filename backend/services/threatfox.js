const axios = require('axios');

/**
 * Fetch recent Indicators of Compromise (IOCs) from ThreatFox.
 * Requires an Auth-Key available for free via abuse.ch. The API returns a list
 * of IOCs when queried with "get_iocs". We limit to a 7-day window.
 * @returns {Promise<Array>} An array of IOC objects
 */
async function fetchThreatFoxIocs() {
  const authKey = process.env.THREATFOX_AUTH_KEY;
  if (!authKey) {
    return [];
  }
  const url = 'https://threatfox-api.abuse.ch/api/v1/';
  const payload = {
    query: 'get_iocs',
    days: 7
  };
  const headers = {
    'Auth-Key': authKey,
    'User-Agent': 'ThreatDock'
  };
  try {
    const response = await axios.post(url, payload, { headers });
    const data = response.data || {};
    if (data && Array.isArray(data.data)) {
      return data.data;
    }
    return [];
  } catch (error) {
    console.error('ThreatFox IOC fetch failed:', error.message);
    return [];
  }
}

module.exports = { fetchThreatFoxIocs };