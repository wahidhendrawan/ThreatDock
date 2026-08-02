const axios = require('axios');
const dns = require('dns');
const https = require('https');
const net = require('net');

// Hosts owned by the public intelligence providers supported by ThreatDock.
// Every other destination (MISP, OIDC, n8n, Teams, error webhooks, alternate
// RapidAPI hosts, etc.) must be explicitly listed in OUTBOUND_ALLOWED_HOSTS.
const BUILT_IN_ALLOWED_HOSTS = new Set([
  '2.intelx.io',
  'api.first.org',
  'api.github.com',
  'api.securitytrails.com',
  'api.telegram.org',
  'access.redhat.com',
  'breachdirectory.p.rapidapi.com',
  'crt.sh',
  'dns.google',
  'hooks.slack.com',
  'isc.sans.edu',
  'krebsonsecurity.com',
  'otx.alienvault.com',
  'services.nvd.nist.gov',
  'threatfox-api.abuse.ch',
  'urlscan.io',
  'us-cert.cisa.gov',
  'www.bleepingcomputer.com',
  'www.cisa.gov',
  'www.virustotal.com'
]);

class OutboundPolicyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'OutboundPolicyError';
    this.code = 'ERR_OUTBOUND_POLICY';
  }
}

function normalizeHost(host) {
  return String(host || '').trim().toLowerCase().replace(/\.$/, '');
}

function configuredAllowedHosts() {
  return String(process.env.OUTBOUND_ALLOWED_HOSTS || '')
    .split(',')
    .map(normalizeHost)
    .filter(Boolean);
}

function matchesConfiguredHost(host, rule) {
  if (rule.startsWith('*.')) {
    const suffix = rule.slice(1); // ".example.com"
    return host.endsWith(suffix) && host.length > suffix.length;
  }
  return host === rule;
}

function isAllowedHost(host) {
  const normalized = normalizeHost(host);
  return BUILT_IN_ALLOWED_HOSTS.has(normalized)
    || configuredAllowedHosts().some(rule => matchesConfiguredHost(normalized, rule));
}

function isPublicIp(address) {
  const ip = String(address || '').split('%')[0].toLowerCase();
  const family = net.isIP(ip);
  if (!family) return false;

  if (family === 4) {
    const [first, second, third] = ip.split('.').map(Number);
    if (first === 0 || first === 10 || first === 127 || first >= 224) return false;
    if (first === 100 && second >= 64 && second <= 127) return false; // Shared address space
    if (first === 169 && second === 254) return false; // Link local / cloud metadata
    if (first === 172 && second >= 16 && second <= 31) return false;
    if (first === 192 && second === 168) return false;
    if (first === 192 && second === 0 && third === 0) return false;
    if (first === 192 && second === 0 && third === 2) return false; // TEST-NET-1
    if (first === 198 && (second === 18 || second === 19)) return false; // Benchmarking
    if (first === 198 && second === 51 && third === 100) return false; // TEST-NET-2
    if (first === 203 && second === 0 && third === 113) return false; // TEST-NET-3
    return true;
  }

  // Reject unspecified, loopback, unique-local, link-local, multicast, and
  // documentation IPv6 ranges. IPv4-mapped IPv6 addresses inherit IPv4 policy.
  if (ip === '::' || ip === '::1' || ip.startsWith('fc') || ip.startsWith('fd')
    || /^fe[89ab]/.test(ip) || ip.startsWith('ff') || ip.startsWith('2001:db8')) {
    return false;
  }
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  return mapped ? isPublicIp(mapped[1]) : true;
}

function parseAndValidateUrl(value) {
  let url;
  try {
    url = value instanceof URL ? value : new URL(String(value));
  } catch {
    throw new OutboundPolicyError('Outbound request URL is invalid.');
  }

  if (url.protocol !== 'https:') {
    throw new OutboundPolicyError('Outbound requests must use HTTPS.');
  }
  if (url.username || url.password) {
    throw new OutboundPolicyError('Outbound request URLs must not include credentials.');
  }
  if (url.port && url.port !== '443') {
    throw new OutboundPolicyError('Outbound requests must use port 443.');
  }

  const host = normalizeHost(url.hostname);
  if (!host || net.isIP(host)) {
    throw new OutboundPolicyError('Outbound requests must use an allowlisted DNS hostname.');
  }
  if (!isAllowedHost(host)) {
    throw new OutboundPolicyError(`Outbound host is not allowlisted: ${host}`);
  }
  return url;
}

async function resolvePublicAddresses(host) {
  const normalized = normalizeHost(host);
  if (!isAllowedHost(normalized)) {
    throw new OutboundPolicyError(`Outbound host is not allowlisted: ${normalized}`);
  }

  let records;
  try {
    records = await dns.promises.lookup(normalized, { all: true, verbatim: true });
  } catch {
    throw new OutboundPolicyError(`Unable to resolve outbound host: ${normalized}`);
  }
  if (!Array.isArray(records) || records.length === 0 || records.some(record => !isPublicIp(record.address))) {
    throw new OutboundPolicyError(`Outbound host resolved to a non-public address: ${normalized}`);
  }
  return records;
}

async function assertOutboundUrl(value) {
  const url = parseAndValidateUrl(value);
  await resolvePublicAddresses(url.hostname);
  return url;
}

function guardedLookup(hostname, _options, callback) {
  resolvePublicAddresses(hostname)
    .then(records => callback(null, records[0].address, records[0].family))
    .catch(error => callback(error));
}

// Pin Node's connection lookup to a public address selected by our guard.
// This prevents a hostname from passing a preliminary lookup then rebinding to
// loopback or an RFC1918 address during connection establishment.
const httpsAgent = new https.Agent({
  keepAlive: true,
  lookup: guardedLookup
});

const outboundHttp = axios.create({
  httpsAgent,
  maxRedirects: 0
});

// The interceptor fails in some test environments where axios is deeply mocked
// and `create` does not return a full axios instance. This guard prevents a
// crash when a test suite requires this module without mocking its exports.
if (outboundHttp.interceptors) {
  outboundHttp.interceptors.request.use(async (config) => {
    const target = config.baseURL ? new URL(config.url, config.baseURL) : new URL(config.url);
    await assertOutboundUrl(target);
    config.httpsAgent = httpsAgent;
    // Redirects are disabled rather than trusted. A caller must explicitly
    // validate a subsequent destination before making a new request.
    config.maxRedirects = 0;
    return config;
  });
}



module.exports = {
  BUILT_IN_ALLOWED_HOSTS,
  OutboundPolicyError,
  assertOutboundUrl,
  httpsAgent,
  isAllowedHost,
  isPublicIp,
  outboundHttp,
  parseAndValidateUrl,
  resolvePublicAddresses
};
