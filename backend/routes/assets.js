const express = require('express');
const dns = require('dns').promises;
const net = require('net');
const axios = require('axios');

const COMMON_PORTS = [80, 443, 8080, 8443, 22, 25, 53, 110, 143, 993, 995, 3389];
const DEFAULT_PUBLIC_DNS = ['1.1.1.1', '8.8.8.8'];

function isPrivateIP(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  const first = parseInt(parts[0], 10);
  const second = parseInt(parts[1], 10);
  if (isNaN(first) || isNaN(second)) return false;
  if (first === 10) return true;
  if (first === 127) return true;
  if (first === 169 && second === 254) return true;
  if (first === 172 && second >= 16 && second <= 31) return true;
  if (first === 192 && second === 168) return true;
  return false;
}

const FORBIDDEN_HOSTNAMES = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]', 'metadata.google.internal', '169.254.169.254'];

function probePort(host, port, timeout = 1800) {
  return new Promise((resolve) => {
    if (!host || typeof host !== 'string') { resolve(false); return; }
    const lower = host.toLowerCase();
    if (FORBIDDEN_HOSTNAMES.includes(lower)) { resolve(false); return; }
    if (net.isIP(host) && isPrivateIP(host)) { resolve(false); return; }
    const socket = new net.Socket();
    let done = false;
    const finish = (open) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeout);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(port, host);
  });
}

function getSettings(db) {
  return new Promise((resolve, reject) => {
    db.all('SELECT key, value FROM settings', [], (err, rows) => {
      if (err) return reject(err);
      const settings = {};
      rows.forEach(r => { settings[r.key] = r.value; });
      resolve(settings);
    });
  });
}

function isDomain(value) {
  return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value);
}

async function publicLookup(host, settings) {
  const resolver = new dns.Resolver();
  const configuredServers = String(settings.PUBLIC_DNS_SERVERS || process.env.PUBLIC_DNS_SERVERS || '')
    .split(',')
    .map(server => server.trim())
    .filter(Boolean);
  resolver.setServers(configuredServers.length > 0 ? configuredServers : DEFAULT_PUBLIC_DNS);
  const [v4, v6] = await Promise.all([
    resolver.resolve4(host).catch(() => []),
    resolver.resolve6(host).catch(() => [])
  ]);
  return [...v4.map(address => ({ address, family: 4 })), ...v6.map(address => ({ address, family: 6 }))];
}

module.exports = function createAssetsRouter(db) {
  const router = express.Router();

  // GET /api/assets
  router.get('/', (req, res) => {
    db.all('SELECT * FROM assets ORDER BY created_at DESC', (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  });

  // POST /api/assets
  router.post('/', (req, res) => {
    const { domain, ip, port, service, tech_stack, notes } = req.body;
    const stmt = db.prepare(`INSERT INTO assets (domain, ip, port, service, tech_stack, notes) VALUES (?, ?, ?, ?, ?, ?)`);
    stmt.run([domain, ip, port, service, tech_stack, notes], function(err) {
      if (err) return res.status(400).json({ error: err.message });
      res.status(201).json({ id: this.lastID });
    });
    stmt.finalize();
  });

  function isValidScanTarget(target) {
    if (!target || typeof target !== 'string') return false;
    const clean = target.replace(/^https?:\/\//, '').split('/')[0];
    if (FORBIDDEN_HOSTNAMES.includes(clean.toLowerCase())) return false;
    if (net.isIP(clean) && isPrivateIP(clean)) return false;
    return /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(clean) && clean.includes('.');
  }

  // POST /api/assets/scan
  router.post('/scan', async (req, res) => {
    const { target: rawTarget, ports } = req.body;
    const target = typeof rawTarget === 'string' ? rawTarget : '';
    const cleanTarget = target.trim().replace(/^https?:\/\//, '').split('/')[0];
    if (!cleanTarget || !isValidScanTarget(cleanTarget)) {
      return res.status(400).json({ error: 'Valid public target domain or host is required' });
    }

    const scanPorts = Array.isArray(ports) && ports.length > 0
      ? ports.map(p => parseInt(p, 10)).filter(p => p > 0 && p <= 65535).slice(0, 50)
      : COMMON_PORTS;

    try {
      const settings = await getSettings(db);
      const configuredDns = String(settings.PUBLIC_DNS_SERVERS || process.env.PUBLIC_DNS_SERVERS || '')
        .split(',')
        .map(s => s.trim())
        .filter(Boolean);
      const dnsServersUsed = configuredDns.length > 0 ? configuredDns : DEFAULT_PUBLIC_DNS;
      const addresses = await publicLookup(cleanTarget, settings).catch(() => []);
      const uniqueIps = [...new Set(addresses.map(a => a.address))];
      const resolvedIps = uniqueIps.filter(ip => !isPrivateIP(ip));

      if (resolvedIps.length === 0) {
        return res.status(400).json({ error: 'Could not resolve target to a public IP address' });
      }

      const hostForProbe = resolvedIps[0];
      const openPorts = [];

      for (const port of scanPorts) {
        const isOpen = await probePort(hostForProbe, port);
        if (isOpen) openPorts.push(port);
      }

      const discovered = openPorts.length > 0 ? openPorts : [null];
      const saved = [];
      for (const port of discovered) {
        const service = port === 443 || port === 8443 ? 'HTTPS'
          : port === 80 || port === 8080 ? 'HTTP'
          : port ? `TCP/${port}` : 'Resolved Host';
        const risk = port && ![80, 443].includes(port) ? 45 : 15;
        await new Promise((resolve) => {
          db.run(
            `INSERT INTO assets (domain, ip, port, service, status, risk_score, last_seen, notes)
             VALUES (?, ?, ?, ?, 'Active', ?, datetime('now'), ?)
             ON CONFLICT(domain, ip, port) DO UPDATE SET
               service = excluded.service,
               status = 'Active',
               risk_score = excluded.risk_score,
               last_seen = datetime('now'),
               notes = excluded.notes`,
            [
              cleanTarget,
              uniqueIps[0] || null,
              port,
              service,
              risk,
              'Discovered by ThreatDock asset scan'
            ],
            function(err) {
              if (!err) saved.push({ domain: cleanTarget, ip: uniqueIps[0] || null, port, service, risk_score: risk });
              resolve();
            }
          );
        });
      }

      const enrichments = [];
      const discoveredHosts = new Set();
      const securityTrailsKey = settings.SECURITYTRAILS_API_KEY || process.env.SECURITYTRAILS_API_KEY;
      if (securityTrailsKey) {
        try {
          const response = await axios.get(`https://api.securitytrails.com/v1/domain/${cleanTarget}/subdomains`, {
            headers: { apikey: securityTrailsKey },
            timeout: 8000
          });
          const subdomains = (response.data.subdomains || []).slice(0, 50).map(s => `${s}.${cleanTarget}`);
          enrichments.push({ provider: 'SecurityTrails', type: 'subdomains', count: subdomains.length, items: subdomains });
          subdomains.forEach(host => discoveredHosts.add(host));
        } catch (err) {
          enrichments.push({ provider: 'SecurityTrails', error: err.message });
        }
      }

      const otxKey = settings.OTX_API_KEY || process.env.OTX_API_KEY;
      if (otxKey && isDomain(cleanTarget)) {
        try {
          const response = await axios.get(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(cleanTarget)}/passive_dns`, {
            headers: { 'X-OTX-API-KEY': otxKey },
            timeout: 10000
          });
          const hostnames = (response.data.passive_dns || [])
            .map(item => item.hostname || item.address)
            .filter(Boolean)
            .filter(host => host.endsWith(cleanTarget))
            .slice(0, 50);
          hostnames.forEach(host => discoveredHosts.add(host));
          enrichments.push({ provider: 'AlienVault OTX', type: 'passive_dns', count: hostnames.length, items: hostnames });
        } catch (err) {
          enrichments.push({ provider: 'AlienVault OTX', error: err.message });
        }
      }

      const vtKey = settings.VIRUSTOTAL_API_KEY || process.env.VIRUSTOTAL_API_KEY;
      if (vtKey && isDomain(cleanTarget)) {
        try {
          const response = await axios.get(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(cleanTarget)}/subdomains`, {
            headers: { 'x-apikey': vtKey },
            params: { limit: 40 },
            timeout: 10000
          });
          const subdomains = (response.data.data || [])
            .map(item => item.id)
            .filter(Boolean)
            .slice(0, 40);
          subdomains.forEach(host => discoveredHosts.add(host));
          enrichments.push({ provider: 'VirusTotal Community', type: 'subdomains', count: subdomains.length, items: subdomains });
        } catch (err) {
          enrichments.push({ provider: 'VirusTotal Community', error: err.message });
        }
      }

      const urlscanKey = settings.URLSCAN_API_KEY || process.env.URLSCAN_API_KEY;
      if (isDomain(cleanTarget)) {
        try {
          const response = await axios.get('https://urlscan.io/api/v1/search/', {
            headers: urlscanKey ? { 'API-Key': urlscanKey } : {},
            params: { q: `domain:${cleanTarget}`, size: 25 },
            timeout: 10000
          });
          const hosts = (response.data.results || [])
            .map(item => item.page && item.page.domain)
            .filter(Boolean)
            .filter(host => host.endsWith(cleanTarget))
            .slice(0, 25);
          hosts.forEach(host => discoveredHosts.add(host));
          enrichments.push({ provider: 'URLScan.io', type: 'observed_domains', count: hosts.length, items: hosts });
        } catch (err) {
          enrichments.push({ provider: 'URLScan.io', error: err.message });
        }
      }

      for (const host of [...discoveredHosts].slice(0, 100)) {
        await new Promise((resolve) => {
          db.run(
            `INSERT INTO assets (domain, service, status, risk_score, last_seen, notes)
             VALUES (?, 'Discovered Subdomain', 'Active', 20, datetime('now'), ?)
             ON CONFLICT(domain, ip, port) DO UPDATE SET
               service = excluded.service,
               status = 'Active',
               risk_score = excluded.risk_score,
               last_seen = datetime('now'),
               notes = excluded.notes`,
            [host, `Discovered while scanning ${cleanTarget}`],
            () => resolve()
          );
        });
      }

      res.json({
        target: cleanTarget,
        ips: uniqueIps,
        dnsServers: dnsServersUsed,
        openPorts,
        saved,
        enrichments,
        recommendations: [
          'Free/baseline: DNS lookup and TCP port probing are built in.',
          'Free/community API options: AlienVault OTX, URLScan.io, and VirusTotal Community API keys.',
          'Open-source option: run Amass/Subfinder externally and import discovered assets.'
        ]
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // PATCH /api/assets/:id
  router.patch('/:id', (req, res) => {
    const { status, risk_score, notes } = req.body;
    const updates = [];
    const params = [];
    if (status !== undefined) { updates.push('status = ?'); params.push(status); }
    if (risk_score !== undefined) { updates.push('risk_score = ?'); params.push(risk_score); }
    if (notes !== undefined) { updates.push('notes = ?'); params.push(notes); }
    
    if (updates.length === 0) return res.json({ success: true });
    
    params.push(req.params.id);
    db.run(`UPDATE assets SET ${updates.join(', ')} WHERE id = ?`, params, function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ updated: this.changes });
    });
  });

  // DELETE /api/assets/:id
  router.delete('/:id', (req, res) => {
    db.run('DELETE FROM assets WHERE id = ?', [req.params.id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ deleted: this.changes });
    });
  });

  return router;
};
