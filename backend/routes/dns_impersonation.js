const express = require('express');
const dns = require('dns').promises;
const { generateMutations } = require('../services/dnstwist');

const COMMON_TLD_VARIANTS = [
  'com', 'net', 'org', 'co', 'id', 'io', 'biz', 'info', 'xyz', 'site',
  'online', 'tech', 'app', 'co.id', 'com.au', 'co.uk'
];

const BRAND_AFFIXES = ['secure', 'login', 'verify', 'support', 'portal', 'helpdesk'];

function normalizeDomainInput(value) {
  if (typeof value !== 'string') return '';
  const withoutScheme = value.trim().toLowerCase().replace(/^https?:\/\//, '');
  const hostPort = withoutScheme.split('/')[0] || '';
  const host = hostPort.split(':')[0] || '';
  return host.replace(/\.$/, '');
}

function isValidDomain(value) {
  return /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i.test(value);
}

function parseDomain(domain) {
  const labels = String(domain || '').split('.').filter(Boolean);
  if (labels.length < 2) return null;
  return {
    brand: labels[0],
    tld: labels.slice(1).join('.')
  };
}

function buildCandidateDomains(domain) {
  const parsed = parseDomain(domain);
  const candidates = new Set(generateMutations(domain));
  if (!parsed) return [...candidates];

  // TLD substitutions (common phishing/impersonation patterns)
  for (const tld of COMMON_TLD_VARIANTS) {
    if (tld !== parsed.tld) {
      candidates.add(`${parsed.brand}.${tld}`);
    }
  }

  // Brand affixes (e.g. brand-login.com, brandsecure.com)
  for (const affix of BRAND_AFFIXES) {
    candidates.add(`${parsed.brand}-${affix}.${parsed.tld}`);
    candidates.add(`${parsed.brand}${affix}.${parsed.tld}`);
  }

  candidates.delete(domain);
  return [...candidates].slice(0, 180);
}

function withTimeout(promise, timeoutMs = 2200) {
  return Promise.race([
    promise,
    new Promise((resolve) => setTimeout(() => resolve([]), timeoutMs))
  ]).catch(() => []);
}

async function lookupDomainRecords(domain) {
  const [a, aaaa, cname, ns] = await Promise.all([
    withTimeout(dns.resolve4(domain)),
    withTimeout(dns.resolve6(domain)),
    withTimeout(dns.resolveCname(domain)),
    withTimeout(dns.resolveNs(domain))
  ]);

  const hasRecords = (a && a.length) || (aaaa && aaaa.length) || (cname && cname.length) || (ns && ns.length);
  if (!hasRecords) return null;

  const primary = (a && a[0]) || (aaaa && aaaa[0]) || (cname && cname[0]) || (ns && ns[0]) || null;
  const recordTypes = [
    ...(a && a.length ? ['A'] : []),
    ...(aaaa && aaaa.length ? ['AAAA'] : []),
    ...(cname && cname.length ? ['CNAME'] : []),
    ...(ns && ns.length ? ['NS'] : [])
  ];

  return {
    domain,
    ip: primary,
    status: a.length || aaaa.length ? 'Registered / Active' : 'Registered / Delegated',
    severity: 'High',
    records: recordTypes
  };
}

module.exports = function createDnsImpersonationRouter(db) {
  const router = express.Router();

  const handleScan = async (req, res) => {
    const domain = normalizeDomainInput(req.body && req.body.domain);
    if (!isValidDomain(domain)) {
      return res.status(400).json({ error: 'Valid domain is required' });
    }

    try {
      const mutations = buildCandidateDomains(domain);

      // Perform parallel DNS lookups across mutation + TLD candidate set
      const lookupPromises = mutations.map(async (mutant) => {
        return lookupDomainRecords(mutant);
      });

      const resolved = await Promise.all(lookupPromises);
      const activeImpersonators = resolved.filter(Boolean);

      res.json({
        original: domain,
        mutations_generated: mutations.length,
        scanned_domains: mutations.length,
        active_impersonators: activeImpersonators
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  };

  router.post('/scan', handleScan);
  router.post('/', handleScan);

  return router;
};
