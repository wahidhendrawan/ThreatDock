const Parser = require('rss-parser');

const { outboundHttp } = require('./outboundHttp');

const parser = new Parser();
const FEED_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.5'
};
const MAX_FEED_BYTES = 5 * 1024 * 1024;

// Final URLs: outboundHttp does not follow redirects.
const feedList = [
  { name: 'SANS Internet Storm Center', url: 'https://isc.sans.edu/rssfeed_full.xml' },
  { name: 'US-CERT Alerts', url: 'https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml' },
  { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/' },
  { name: 'Krebs on Security', url: 'https://krebsonsecurity.com/feed/' }
];

async function fetchRssFeeds() {
  const results = [];
  for (const feed of feedList) {
    try {
      // outboundHttp enforces HTTPS, the host allowlist and public-IP pinning.
      const response = await outboundHttp.get(feed.url, {
        headers: FEED_HEADERS,
        timeout: 10000,
        responseType: 'text',
        maxContentLength: MAX_FEED_BYTES
      });
      const parsed = await parser.parseString(response.data);
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

module.exports = { fetchRssFeeds, feedList };
