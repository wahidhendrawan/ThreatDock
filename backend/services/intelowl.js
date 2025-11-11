/*
 * IntelOwl Integration (Stub)
 *
 * IntelOwl is an open source threat intelligence platform that aggregates
 * analysis from multiple services.  A full integration would require
 * deploying an IntelOwl instance or using an API provided by a third party.
 * At this time ThreatDock includes a stub implementation for IntelOwl.
 *
 * To enable IntelOwl integration, set the environment variable
 * `INTELO_OWL_API_KEY` and implement the API call in the function
 * below.  The function should return an array of alerts with the
 * standard structure { source, externalId, title, severity, date, url }.
 */

async function fetchIntelOwlData() {
  // Placeholder stub: return an empty array until a real IntelOwl API is configured.
  // To implement, you could make requests to your IntelOwl instance's API
  // using an API key (e.g. POST /api/v1/artifacts or GET /api/v1/analysis).
  return [];
}

module.exports = { fetchIntelOwlData };