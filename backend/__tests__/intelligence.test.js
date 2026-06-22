const {
  detectIndicatorType,
  extractCves,
  extractDomains,
  normalizeSeverity,
  severityOrder
} = require('../services/intelligence');

describe('normalizeSeverity', () => {
  test('returns proper casing', () => {
    expect(normalizeSeverity('critical')).toBe('Critical');
    expect(normalizeSeverity('HIGH')).toBe('High');
    expect(normalizeSeverity('Moderate')).toBe('Medium');
    expect(normalizeSeverity('Low')).toBe('Low');
    expect(normalizeSeverity('')).toBe('Unknown');
    expect(normalizeSeverity(null)).toBe('Unknown');
    expect(normalizeSeverity('invalid')).toBe('Unknown');
  });
});

describe('severityOrder', () => {
  test('has correct priority values', () => {
    expect(severityOrder.Critical).toBe(4);
    expect(severityOrder.High).toBe(3);
    expect(severityOrder.Unknown).toBe(0);
  });
});

describe('detectIndicatorType', () => {
  test('detects CVE', () => {
    expect(detectIndicatorType('CVE-2024-12345')).toBe('cve');
    expect(detectIndicatorType('cve-2023-9999')).toBe('cve');
  });

  test('detects URL', () => {
    expect(detectIndicatorType('https://evil.com/payload')).toBe('url');
    expect(detectIndicatorType('http://phishing.net')).toBe('url');
  });

  test('detects MD5', () => {
    expect(detectIndicatorType('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6')).toBe('md5');
  });

  test('detects SHA256', () => {
    expect(detectIndicatorType('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1')).toBe('sha256');
  });

  test('detects IP', () => {
    expect(detectIndicatorType('192.168.1.1')).toBe('ip');
    expect(detectIndicatorType('10.0.0.1:8080')).toBe('ip:port');
  });

  test('detects domain', () => {
    expect(detectIndicatorType('evil.example.com')).toBe('domain');
  });

  test('detects email', () => {
    expect(detectIndicatorType('attacker@evil.com')).toBe('email');
  });

  test('falls back to keyword', () => {
    expect(detectIndicatorType('something_unknown')).toBe('keyword');
  });
});

describe('extractCves', () => {
  test('extracts CVE IDs from text', () => {
    const result = extractCves('Found CVE-2024-12345 and CVE-2023-9999 in log');
    expect(result).toEqual(['CVE-2024-12345', 'CVE-2023-9999']);
  });

  test('deduplicates CVEs', () => {
    const result = extractCves('CVE-2024-12345 is critical. Also CVE-2024-12345 again.');
    expect(result).toEqual(['CVE-2024-12345']);
  });

  test('returns empty array for no CVEs', () => {
    expect(extractCves('No vulnerabilities here')).toEqual([]);
    expect(extractCves('')).toEqual([]);
    expect(extractCves(null)).toEqual([]);
  });
});

describe('extractDomains', () => {
  test('extracts domains from text', () => {
    const result = extractDomains('Check example.com and test.org references');
    expect(result).toContain('example.com');
    expect(result).toContain('test.org');
  });

  test('filters out .js and .css extensions', () => {
    const result = extractDomains('cdn.example.com/script.js and site.com/style.css');
    expect(result).not.toContain('script.js');
    expect(result).not.toContain('style.css');
  });

  test('returns empty array for no domains', () => {
    expect(extractDomains('No domains here')).toEqual([]);
    expect(extractDomains('')).toEqual([]);
    expect(extractDomains(null)).toEqual([]);
  });
});
