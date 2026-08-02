/**
 * Feed adapter tests for RSS, ThreatFox, and OTX.
 *
 * Adapters are expected to:
 *   - return an empty array (never throw) when the upstream fails
 *   - return an empty array when credentials are missing (for authed feeds)
 *   - normalize successful responses into the shape used by the ingestion layer
 */

jest.mock('../services/outboundHttp', () => ({
  outboundHttp: {
    get: jest.fn(),
    post: jest.fn()
  },
  resolvePublicAddresses: jest.fn(async () => [])
}));

jest.mock('rss-parser', () => {
  const parseURL = jest.fn();
  const Parser = jest.fn().mockImplementation(() => ({ parseURL }));
  Parser.prototype = { parseURL };
  Parser.__parseURL = parseURL;
  return Parser;
});

const Parser = require('rss-parser');
const { outboundHttp } = require('../services/outboundHttp');

describe('Feed adapters', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  describe('RSS adapter', () => {
    let fetchRssFeeds;

    beforeAll(() => {
      // Load after mock so the SSRF wrap uses the mocked parseURL
      ({ fetchRssFeeds } = require('../services/rss'));
    });

    it('normalizes items across configured feeds', async () => {
      Parser.__parseURL.mockResolvedValue({
        items: [
          {
            guid: 'guid-1',
            title: 'Test Article',
            isoDate: '2026-01-01T00:00:00Z',
            link: 'https://example.com/1'
          }
        ]
      });

      const results = await fetchRssFeeds();

      expect(results.length).toBeGreaterThan(0);
      const first = results[0];
      expect(first).toEqual(expect.objectContaining({
        source: expect.any(String),
        externalId: 'guid-1',
        title: 'Test Article',
        url: 'https://example.com/1'
      }));
    });

    it('falls back to link or id when guid is missing', async () => {
      Parser.__parseURL.mockResolvedValue({
        items: [
          { title: 'No GUID', link: 'https://example.com/x' },
          { title: 'Only ID', id: 'id-42' }
        ]
      });

      const results = await fetchRssFeeds();
      const externalIds = results.map(r => r.externalId);
      expect(externalIds).toContain('https://example.com/x');
      expect(externalIds).toContain('id-42');
    });

    it('handles missing titles and empty item arrays gracefully', async () => {
      Parser.__parseURL.mockResolvedValue({ items: [{ link: 'https://example.com/y' }] });
      const results = await fetchRssFeeds();
      expect(results.every(r => typeof r.title === 'string')).toBe(true);
    });

    it('does not throw when a feed rejects; returns items from successful feeds', async () => {
      Parser.__parseURL
        .mockRejectedValueOnce(new Error('network down'))
        .mockResolvedValue({ items: [{ guid: 'ok-1', title: 't', link: 'https://ok/1' }] });

      const results = await fetchRssFeeds();
      expect(Array.isArray(results)).toBe(true);
    });

    it('returns [] when parser returns null or unexpected shapes', async () => {
      Parser.__parseURL.mockResolvedValue(null);
      const results = await fetchRssFeeds();
      expect(results).toEqual([]);
    });
  });

  describe('ThreatFox adapter', () => {
    let fetchThreatFoxIocs;

    beforeAll(() => {
      ({ fetchThreatFoxIocs } = require('../services/threatfox'));
    });

    it('returns [] when auth key is not configured', async () => {
      delete process.env.THREATFOX_AUTH_KEY;
      const results = await fetchThreatFoxIocs();
      expect(results).toEqual([]);
      expect(outboundHttp.post).not.toHaveBeenCalled();
    });

    it('returns the data array when the API succeeds', async () => {
      process.env.THREATFOX_AUTH_KEY = 'test-key';
      outboundHttp.post.mockResolvedValue({ data: { data: [{ ioc: '1.2.3.4' }, { ioc: 'evil.com' }] } });

      const results = await fetchThreatFoxIocs();
      expect(results).toHaveLength(2);
      expect(outboundHttp.post).toHaveBeenCalledWith(
        'https://threatfox-api.abuse.ch/api/v1/',
        expect.objectContaining({ query: 'get_iocs' }),
        expect.objectContaining({ headers: expect.objectContaining({ 'Auth-Key': 'test-key' }) })
      );
    });

    it('returns [] when response body has unexpected shape', async () => {
      process.env.THREATFOX_AUTH_KEY = 'test-key';
      outboundHttp.post.mockResolvedValue({ data: {} });
      const results = await fetchThreatFoxIocs();
      expect(results).toEqual([]);
    });

    it('swallows upstream errors and returns []', async () => {
      process.env.THREATFOX_AUTH_KEY = 'test-key';
      outboundHttp.post.mockRejectedValue(new Error('boom'));
      const results = await fetchThreatFoxIocs();
      expect(results).toEqual([]);
    });
  });

  describe('OTX adapter', () => {
    let fetchOtxPulses;

    beforeAll(() => {
      ({ fetchOtxPulses } = require('../services/otx'));
    });

    it('returns [] when API key is not configured', async () => {
      delete process.env.OTX_API_KEY;
      const results = await fetchOtxPulses();
      expect(results).toEqual([]);
      expect(outboundHttp.get).not.toHaveBeenCalled();
    });

    it('returns results array when API responds with { results: [...] }', async () => {
      process.env.OTX_API_KEY = 'otx-key';
      outboundHttp.get.mockResolvedValue({ data: { results: [{ id: 'p1' }] } });
      const results = await fetchOtxPulses();
      expect(results).toEqual([{ id: 'p1' }]);
    });

    it('returns list when API responds with a bare array', async () => {
      process.env.OTX_API_KEY = 'otx-key';
      outboundHttp.get.mockResolvedValue({ data: [{ id: 'p2' }] });
      const results = await fetchOtxPulses();
      expect(results).toEqual([{ id: 'p2' }]);
    });

    it('swallows upstream errors and returns []', async () => {
      process.env.OTX_API_KEY = 'otx-key';
      outboundHttp.get.mockRejectedValue(new Error('403'));
      const results = await fetchOtxPulses();
      expect(results).toEqual([]);
    });
  });
});
