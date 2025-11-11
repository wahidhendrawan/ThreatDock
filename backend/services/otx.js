const axios = require('axios');

/**
 * Fetch subscribed pulses from AlienVault Open Threat Exchange (OTX).
 * Requires an API key; returns an array of pulse objects.
 * @returns {Promise<Array>}
 */
async function fetchOtxPulses() {
  const apiKey = process.env.OTX_API_KEY;
  if (!apiKey) {
    // If no API key provided, skip fetching
    return [];
  }
  const url = 'https://otx.alienvault.com/api/v1/pulses/subscribed';
  const headers = {
    'X-OTX-API-KEY': apiKey,
    'User-Agent': 'ThreatDock'
  };
  try {
    const response = await axios.get(url, { headers, params: { page: 1 } });
    // Response is expected to be an object with 'results' or a list
    const data = response.data;
    if (Array.isArray(data)) {
      return data;
    }
    if (Array.isArray(data.results)) {
      return data.results;
    }
    return [];
  } catch (error) {
    console.error('OTX pulse fetch failed:', error.message);
    return [];
  }
}

module.exports = { fetchOtxPulses };