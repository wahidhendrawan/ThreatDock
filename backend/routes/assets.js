const express = require('express');
const dns = require('dns').promises;
const net = require('net');
const axios = require('axios');

const COMMON_PORTS = [80, 443, 8080, 8443, 22, 25, 53, 110, 143, 993, 995, 3389];

function probePort(host, port, timeout = 1800) {
  return new Promise((resolve) => {
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

  // POST /api/assets/scan
  router.post('/scan', async (req, res) => {
    const { target, ports } = req.body;
    const cleanTarget = String(target || '').trim().replace(/^https?:\/\//, '').split('/')[0];
    if (!cleanTarget) return res.status(400).json({ error: 'Target domain or host is required' });

    const scanPorts = Array.isArray(ports) && ports.length > 0
      ? ports.map(p => parseInt(p, 10)).filter(p => p > 0 && p <= 65535).slice(0, 50)
      : COMMON_PORTS;

    try {
      const settings = await getSettings(db);
      const addresses = await dns.lookup(cleanTarget, { all: true }).catch(() => []);
      const uniqueIps = [...new Set(addresses.map(a => a.address))];
      const hostForProbe = uniqueIps[0] || cleanTarget;
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
      const securityTrailsKey = settings.SECURITYTRAILS_API_KEY || process.env.SECURITYTRAILS_API_KEY;
      if (securityTrailsKey) {
        try {
          const response = await axios.get(`https://api.securitytrails.com/v1/domain/${cleanTarget}/subdomains`, {
            headers: { apikey: securityTrailsKey },
            timeout: 8000
          });
          const subdomains = (response.data.subdomains || []).slice(0, 50).map(s => `${s}.${cleanTarget}`);
          enrichments.push({ provider: 'SecurityTrails', type: 'subdomains', count: subdomains.length, items: subdomains });
        } catch (err) {
          enrichments.push({ provider: 'SecurityTrails', error: err.message });
        }
      }

      res.json({
        target: cleanTarget,
        ips: uniqueIps,
        openPorts,
        saved,
        enrichments,
        recommendations: [
          'Free/baseline: DNS lookup and TCP port probing are built in.',
          'Open-source option: run Amass/Subfinder externally and import discovered assets.',
          'API options: SecurityTrails, Shodan, Censys, or ProjectDiscovery Cloud with API keys.'
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
