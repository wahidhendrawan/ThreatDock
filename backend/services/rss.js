const Parser = require('rss-parser');

// Use node-fetch to provide custom behavior if needed, or simply standard custom headers
const parser = new Parser({
  timeout: 10000,
  headers: {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5'
  }
});

const feedList = [
  { name: 'SANS Internet Storm Center', url: 'https://isc.sans.edu/rssfeed_full.xml' },
  { name: 'US-CERT Alerts', url: 'https://us-cert.cisa.gov/ncas/alerts.xml' },
  { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed' },
  { name: 'Krebs on Security', url: 'http://krebsonsecurity.com/feed/' }
];

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
      console.error(`Failed to fetch RSS feed ${feed.url}: ${err.message}`);
    }
  }
  return results;
}

module.exports = { fetchRssFeeds };
