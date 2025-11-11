const axios = require('axios');

/**
 * Fetch the latest GitHub security advisories.
 * Uses the GitHub advisories API (public endpoint) and optionally a token.
 * @returns {Promise<Array>} An array of advisory objects
 */
async function fetchGitHubAdvisories() {
  const url = 'https://api.github.com/advisories?per_page=100';
  const headers = { 'Accept': 'application/vnd.github+json' };
  const token = process.env.GITHUB_TOKEN;
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  try {
    const response = await axios.get(url, { headers });
    // The API returns an array of advisories
    return response.data || [];
  } catch (error) {
    console.error('GitHub advisories fetch failed:', error.message);
    return [];
  }
}

module.exports = { fetchGitHubAdvisories };