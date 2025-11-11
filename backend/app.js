require('dotenv').config();
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const cron = require('node-cron');

const githubService = require('./services/github');
const nvdService = require('./services/nvd');
const redhatService = require('./services/redhat');
const otxService = require('./services/otx');
const threatfoxService = require('./services/threatfox');
const mispService = require('./services/misp');
const intelOwlService = require('./services/intelowl');
const yaraSigmaService = require('./services/yaraSigma');
const notificationService = require('./services/notifications');

const authMiddleware = require('./middleware/auth');
const rssService = require('./services/rss');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Apply HTTP Basic authentication middleware.  If environment variables
// AUTH_USER and AUTH_PASSWORD are not set, authMiddleware will
// simply pass requests through.  Otherwise all requests will
// require valid credentials in the Authorization header.
app.use(authMiddleware);

// Initialize SQLite database
const db = new sqlite3.Database('alerts.db');
// Create alerts table if it does not exist
db.run(`CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT,
  externalId TEXT,
  title TEXT,
  severity TEXT,
  date TEXT,
  url TEXT,
  status TEXT DEFAULT 'Open',
  attack_phase TEXT DEFAULT 'Unknown'
)`);

// Attempt to add status and attack_phase columns if they are missing.  SQLite
// will throw an error if the column already exists; we suppress the error.
db.run("ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'Open'", () => {});
db.run("ALTER TABLE alerts ADD COLUMN attack_phase TEXT DEFAULT 'Unknown'", () => {});

// Utility: map Red Hat severities to standardized values
function mapRedHatSeverity(sev) {
  if (!sev) return 'Unknown';
  if (sev === 'Important') return 'High';
  if (sev === 'Moderate') return 'Medium';
  return sev; // Low or Critical remain unchanged
}

/**
 * Fetch data from all configured sources and store in SQLite.
 */
async function fetchAllSources() {
  try {
    // Fetch data in parallel
    const [ghData, nvdData, rhData, otxData, tfData, rssData, mispData, intelData, yaraData] = await Promise.all([
      githubService.fetchGitHubAdvisories(),
      nvdService.fetchNvdCves(),
      redhatService.fetchRedHatCves(),
      otxService.fetchOtxPulses(),
      threatfoxService.fetchThreatFoxIocs(),
      rssService.fetchRssFeeds(),
      mispService.fetchMispEvents(),
      intelOwlService.fetchIntelOwlData(),
      yaraSigmaService.fetchYaraSigmaMatches()
    ]);

    const alerts = [];

    // Process GitHub advisories
    if (Array.isArray(ghData)) {
      for (const adv of ghData) {
        alerts.push({
          source: 'GitHub',
          externalId: adv.ghsa_id || adv.id || '',
          title: adv.summary || adv.description || 'GitHub Advisory',
          severity: adv.severity ? adv.severity.charAt(0).toUpperCase() + adv.severity.slice(1) : 'Unknown',
          date: adv.published_at || adv.updated_at || '',
          url: adv.html_url || (adv.ghsa_id ? `https://github.com/advisories/${adv.ghsa_id}` : ''),
          status: 'Open',
          attack_phase: 'Unknown'
        });
      }
    }

    // Process NVD CVEs
    if (nvdData && Array.isArray(nvdData.vulnerabilities)) {
      for (const item of nvdData.vulnerabilities) {
        const cve = item.cve;
        if (!cve) continue;
        const cveId = cve.id;
        // Determine severity from CVSS metrics
        let severity = 'Unknown';
        const metrics = cve.metrics || {};
        if (metrics.cvssMetricV31 && metrics.cvssMetricV31.length > 0) {
          severity = metrics.cvssMetricV31[0].cvssData.baseSeverity;
        } else if (metrics.cvssMetricV30 && metrics.cvssMetricV30.length > 0) {
          severity = metrics.cvssMetricV30[0].cvssData.baseSeverity;
        } else if (metrics.cvssMetricV2 && metrics.cvssMetricV2.length > 0) {
          const score = metrics.cvssMetricV2[0].cvssData.baseScore;
          severity = score >= 9 ? 'Critical' : score >= 7 ? 'High' : score >= 4 ? 'Medium' : 'Low';
        }
        let title = '';
        if (cve.descriptions && cve.descriptions.length > 0) {
          const desc = cve.descriptions.find(d => d.lang === 'en');
          if (desc) title = desc.value;
        }
        if (!title) title = cveId;
        const datePublished = cve.published || cve.lastModified || '';
        alerts.push({
          source: 'NVD',
          externalId: cveId,
          title,
          severity,
          date: datePublished,
          url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
          status: 'Open',
          attack_phase: 'Unknown'
        });
      }
    }

    // Process Red Hat CVEs
    if (Array.isArray(rhData)) {
      for (const item of rhData) {
        const cveId = item.CVE;
        const severity = item.ThreatSeverity ? mapRedHatSeverity(item.ThreatSeverity) : 'Unknown';
        let title = (item.Bugzilla && item.Bugzilla.description) || item.details || '';
        if (!title || title.trim() === '') title = `Red Hat Advisory ${cveId}`;
        const datePublished = item.PublicDate || '';
        alerts.push({
          source: 'Red Hat',
          externalId: cveId,
          title,
          severity,
          date: datePublished,
          url: `https://access.redhat.com/security/cve/${cveId}`,
          status: 'Open',
          attack_phase: 'Unknown'
        });
      }
    }

    // Process OTX pulses
    if (Array.isArray(otxData)) {
      for (const pulse of otxData) {
        alerts.push({
          source: 'OTX',
          externalId: pulse.id ? pulse.id.toString() : '',
          title: pulse.name || 'OTX Pulse',
          severity: 'Medium', // OTX pulses do not provide severity; assign Medium
          date: pulse.modified || pulse.created || '',
          url: pulse.id ? `https://otx.alienvault.com/pulse/${pulse.id}` : '',
          status: 'Open',
          attack_phase: 'Unknown'
        });
      }
    }

    // Process ThreatFox IOCs
    if (Array.isArray(tfData)) {
      for (const ioc of tfData) {
        alerts.push({
          source: 'ThreatFox',
          externalId: ioc.id ? ioc.id.toString() : '',
          title: `ThreatFox IOC (${ioc.ioc_type || 'unknown'})`,
          severity: 'High', // treat ThreatFox IOCs as high severity
          date: ioc.first_seen || '',
          url: ioc.id ? `https://threatfox.abuse.ch/ioc/${ioc.id}` : ''
        ,
          status: 'Open',
          attack_phase: 'Unknown'
        });
      }
    }

    // Process RSS feed articles
    if (Array.isArray(rssData)) {
      for (const article of rssData) {
        alerts.push({
          source: article.source || 'RSS',
          externalId: article.externalId || '',
          title: article.title || 'RSS Article',
          severity: 'Low', // treat news articles as low severity by default
          date: article.date || '',
          url: article.url || '',
          status: 'Open',
          attack_phase: 'Unknown'
        });
      }
    }

    // Process MISP events
    if (Array.isArray(mispData)) {
      for (const evt of mispData) {
        alerts.push({
          source: evt.source,
          externalId: evt.externalId || '',
          title: evt.title || 'MISP Event',
          severity: evt.severity || 'Medium',
          date: evt.date || '',
          url: evt.url || '',
          status: 'Open',
          attack_phase: 'Unknown'
        });
      }
    }

    // Process IntelOwl data (stub)
    if (Array.isArray(intelData)) {
      for (const item of intelData) {
        alerts.push({
          source: item.source || 'IntelOwl',
          externalId: item.externalId || '',
          title: item.title || 'IntelOwl',
          severity: item.severity || 'Medium',
          date: item.date || '',
          url: item.url || '',
          status: 'Open',
          attack_phase: 'Unknown'
        });
      }
    }

    // Process YARA/Sigma matches (stub)
    if (Array.isArray(yaraData)) {
      for (const match of yaraData) {
        alerts.push({
          source: match.source || 'YARA/Sigma',
          externalId: match.externalId || '',
          title: match.title || 'YARA/Sigma Match',
          severity: match.severity || 'Medium',
          date: match.date || '',
          url: match.url || '',
          status: 'Open',
          attack_phase: match.attack_phase || 'Unknown'
        });
      }
    }

    // Persist alerts to DB
    db.serialize(() => {
      db.run('DELETE FROM alerts');
      const stmt = db.prepare('INSERT INTO alerts (source, externalId, title, severity, date, url, status, attack_phase) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
      for (const alert of alerts) {
        stmt.run(
          alert.source,
          alert.externalId,
          alert.title,
          alert.severity,
          alert.date,
          alert.url,
          alert.status || 'Open',
          alert.attack_phase || 'Unknown'
        );
      }
      stmt.finalize();
    });

    console.log(`Fetched and stored ${alerts.length} alerts.`);

    // Send notifications after storing alerts
    try {
      await notificationService.sendSlackNotifications(alerts);
    } catch (notifyErr) {
      console.error('Error sending notifications:', notifyErr.message);
    }
  } catch (err) {
    console.error('Error fetching alerts:', err);
  }
}

// Initial fetch on startup
fetchAllSources();
// Schedule to run every hour at minute 0
cron.schedule('0 * * * *', fetchAllSources);

// Mount alerts router
const alertsRouter = require('./routes/alerts')(db);
app.use('/alerts', alertsRouter);

// Health endpoint
app.get('/', (req, res) => {
  res.send('ThreatDock backend is running.');
});

// Start server
app.listen(PORT, () => {
  console.log(`Backend server listening on port ${PORT}`);
});