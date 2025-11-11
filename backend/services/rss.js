const Parser = require('rss-parser');

// Instantiate a single parser instance
const parser = new Parser();

// Define a curated list of RSS feeds to ingest.  These feeds are drawn from
// the open‑source “awesome‑threat‑intel‑rss” project and cover trusted
// cybersecurity news sources such as SANS, US‑CERT, BleepingComputer and more.
// Each entry includes a human‑readable name and the feed URL.  To add more
// feeds, append an object with `name` and `url` properties to this array.
const feedList = [
  {
    name: 'SANS Internet Storm Center',
    url: 'https://isc.sans.edu/rssfeed_full.xml'
  },
  {
    name: 'US‑CERT Alerts',
    url: 'https://us-cert.cisa.gov/ncas/alerts.xml'
  },
  {
    name: 'BleepingComputer',
    url: 'https://www.bleepingcomputer.com/feed'
  },
  {
    name: 'Dark Reading',
    url: 'https://www.darkreading.com/rss/all.xml'
  },
  {
    name: 'Krebs on Security',
    url: 'http://krebsonsecurity.com/feed/'
  }
];

/**
 * Fetch recent articles from all configured RSS feeds.  Each feed is parsed
 * using `rss-parser`, and the resulting items are normalised to a common
 * alert format.  Items missing a GUID will fall back to their link as the
 * external identifier.  The date field uses the ISO string if available.
 *
 * @returns {Promise<Array<{source: string, externalId: string, title: string, date: string, url: string}>>}
 */
async function fetchRssFeeds() {
  const results = [];
  for (const feed of feedList) {
    try {
      const parsed = await parser.parseURL(feed.url);
      if (parsed && Array.isArray(parsed.items)) {
        for (const item of parsed.items) {
          results.push({
            source: feed.name,
            externalId: item.guid || item.id || item.link || '',
            title: item.title || 'RSS Article',
            date: item.isoDate || item.pubDate || '',
            url: item.link || ''
          });
        }
      }
    } catch (err) {
      // Log and continue on errors so that one misbehaving feed does not
      // interrupt the aggregation of others.  The error message is kept
      // concise to avoid leaking sensitive information.
      console.error(`Failed to fetch RSS feed ${feed.url}: ${err.message}`);
    }
  }
  return results;
}

module.exports = { fetchRssFeeds };