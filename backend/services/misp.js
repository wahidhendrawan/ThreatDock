const axios = require('axios');

/*
 * MISP Integration
 *
 * This service fetches recent events from a MISP instance.  Provide the
 * environment variables `MISP_URL` and `MISP_API_KEY` to enable this
 * integration.  The MISP API key must correspond to a user account with
 * appropriate permissions.  If either variable is missing, the service
 * returns an empty array.
 *
 * Events are pulled via the `/events/index` endpoint, which returns a
 * lightweight summary of each event.  We normalise the data into the
 * unified alert schema used by ThreatDock: { source, externalId, title,
 * severity, date, url }.  MISP uses numeric threat levels (1=High,
 * 2=Medium, 3=Low, 4=Undefined) that we map to corresponding text.
 */

function mapThreatLevel(level) {
  switch (String(level)) {
    case '1':
      return 'High';
    case '2':
      return 'Medium';
    case '3':
      return 'Low';
    default:
      return 'Unknown';
  }
}

async function fetchMispEvents() {
  const baseUrl = process.env.MISP_URL;
  const apiKey = process.env.MISP_API_KEY;
  if (!baseUrl || !apiKey) {
    return [];
  }
  const url = `${baseUrl.replace(/\/$/, '')}/events/index`;
  try {
    const res = await axios.get(url, {
      headers: {
        Authorization: apiKey,
        Accept: 'application/json',
        'Content-Type': 'application/json'
      }
    });
    const events = Array.isArray(res.data) ? res.data : res.data.response || [];
    const results = [];
    for (const evt of events) {
      // The event structure may vary; ensure we handle missing fields gracefully
      const id = evt.id || evt.Event?.id;
      const info = evt.info || evt.Event?.info || `MISP Event ${id}`;
      const date = evt.date || evt.Event?.date || '';
      const threat = evt.threat_level_id || evt.Event?.threat_level_id;
      const severity = mapThreatLevel(threat);
      const uuid = evt.uuid || evt.Event?.uuid;
      results.push({
        source: 'MISP',
        externalId: uuid || String(id),
        title: info,
        severity,
        date,
        url: id ? `${baseUrl.replace(/\/$/, '')}/events/view/${id}` : ''
      });
    }
    return results;
  } catch (err) {
    console.error('Failed to fetch MISP events:', err.message);
    return [];
  }
}

module.exports = { fetchMispEvents };