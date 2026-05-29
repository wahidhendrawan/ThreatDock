require('dotenv').config();
const express = require('express');
const cors = require('cors');
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
const intelligenceService = require('./services/intelligence');
const settingsStore = require('./services/settingsStore');
const dbUtil = require('./services/db');
const { createDatabase, initializeDatabase } = require('./services/database');

const authMiddleware = require('./middleware/auth');
const rssService = require('./services/rss');
const osintService = require('./services/osint');

const app = express();
const PORT = process.env.PORT || 5002;

// Middleware
const helmet = require('helmet');
app.use(helmet());
app.use(cors());
app.use(express.json());

app.disable('x-powered-by');

// Initialize PostgreSQL database adapter
const db = createDatabase();

app.use((req, res, next) => {
  req.db = db;
  next();
});

// Remove global authMiddleware here

function getRuntimeSettings() {
  return settingsStore.getSettings(db);
}

async function applyRuntimeSettings() {
  const runtimeKeys = [
    'GITHUB_TOKEN',
    'NVD_API_KEY',
    'OTX_API_KEY',
    'THREATFOX_AUTH_KEY',
    'BREACHDIRECTORY_RAPIDAPI_KEY',
    'BREACHDIRECTORY_RAPIDAPI_HOST',
    'MISP_URL',
    'MISP_API_KEY',
    'INTELO_OWL_API_KEY',
    'SLACK_WEBHOOK_URL',
    'N8N_WEBHOOK_URL',
    'TELEGRAM_BOT_TOKEN',
    'TELEGRAM_CHAT_ID',
    'TEAMS_WEBHOOK_URL',
    'NOTIFY_THRESHOLD',
    'NOTIFICATION_RULES',
    'RISK_WEIGHTS'
  ];
  const settings = await getRuntimeSettings();
  runtimeKeys.forEach(key => {
    if (settings[key] !== undefined) process.env[key] = settings[key];
  });
  return settings;
}

// Utility: map Red Hat severities to standardized values
function mapRedHatSeverity(sev) {
  if (!sev) return 'Unknown';
  if (sev === 'Important') return 'High';
  if (sev === 'Moderate') return 'Medium';
  return sev; // Low or Critical remain unchanged
}

function countFetchedItems(source, data) {
  if (Array.isArray(data)) return data.length;
  if (source === 'NVD' && data && Array.isArray(data.vulnerabilities)) return data.vulnerabilities.length;
  return data ? 1 : 0;
}

function recordSourceRun(source, status, itemCount, durationMs, error, startedAt, finishedAt) {
  const errorText = error ? String(error).slice(0, 1000) : '';
  db.run(
    `INSERT INTO ingestion_runs (source, status, item_count, duration_ms, error, started_at, finished_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [source, status, itemCount, durationMs, errorText, startedAt, finishedAt]
  );
  db.run(
    `INSERT INTO source_health (source, status, last_success, last_failure, last_error, last_count, last_duration_ms, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
     ON CONFLICT(source) DO UPDATE SET
       status = excluded.status,
       last_success = CASE WHEN excluded.status = 'Success' THEN excluded.last_success ELSE source_health.last_success END,
       last_failure = CASE WHEN excluded.status = 'Failure' THEN excluded.last_failure ELSE source_health.last_failure END,
       last_error = excluded.last_error,
       last_count = excluded.last_count,
       last_duration_ms = excluded.last_duration_ms,
       updated_at = CURRENT_TIMESTAMP`,
    [
      source,
      status,
      status === 'Success' ? finishedAt : null,
      status === 'Failure' ? finishedAt : null,
      errorText,
      itemCount,
      durationMs
    ]
  );
}

async function fetchSourceWithHealth(source, fetcher) {
  const startedAt = new Date().toISOString();
  const start = Date.now();
  try {
    const data = await fetcher();
    const finishedAt = new Date().toISOString();
    recordSourceRun(source, 'Success', countFetchedItems(source, data), Date.now() - start, '', startedAt, finishedAt);
    return data;
  } catch (err) {
    const finishedAt = new Date().toISOString();
    recordSourceRun(source, 'Failure', 0, Date.now() - start, err.message, startedAt, finishedAt);
    console.error(`${source} fetch failed:`, err.message);
    return [];
  }
}

async function persistAlerts(alerts) {
  await dbUtil.transaction(db, async (txDb) => {
    const stmt = await dbUtil.prepare(txDb, `
      INSERT INTO alerts (source, externalId, title, severity, date, url, status, attack_phase)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(source, externalId) DO UPDATE SET
        title = excluded.title,
        severity = excluded.severity,
        date = excluded.date,
        url = excluded.url,
        attack_phase = CASE WHEN excluded.attack_phase != 'Unknown' THEN excluded.attack_phase ELSE alerts.attack_phase END
    `);

    try {
      for (const alert of alerts) {
        await dbUtil.runStatement(stmt, [
          alert.source,
          alert.externalId,
          alert.title,
          alert.severity,
          alert.date,
          alert.url,
          alert.status || 'Open',
          alert.attack_phase || 'Unknown'
        ]);
      }
    } finally {
      await dbUtil.finalize(stmt);
    }
  });
}

let fetchAllSourcesRunning = false;

/**
 * Fetch data from all configured sources and store in PostgreSQL.
 */
async function fetchAllSources() {
  if (fetchAllSourcesRunning) {
    console.warn('Skipping source fetch because a previous run is still active.');
    return;
  }

  fetchAllSourcesRunning = true;
  try {
    await applyRuntimeSettings();
    const [ghData, nvdData, rhData, otxData, tfData, rssData, mispData, intelData, yaraData] = await Promise.all([
      fetchSourceWithHealth('GitHub', () => githubService.fetchGitHubAdvisories()),
      fetchSourceWithHealth('NVD', () => nvdService.fetchNvdCves()),
      fetchSourceWithHealth('Red Hat', () => redhatService.fetchRedHatCves()),
      fetchSourceWithHealth('OTX', () => otxService.fetchOtxPulses()),
      fetchSourceWithHealth('ThreatFox', () => threatfoxService.fetchThreatFoxIocs()),
      fetchSourceWithHealth('RSS', () => rssService.fetchRssFeeds()),
      fetchSourceWithHealth('MISP', () => mispService.fetchMispEvents()),
      fetchSourceWithHealth('IntelOwl', () => intelOwlService.fetchIntelOwlData()),
      fetchSourceWithHealth('YARA/Sigma', () => yaraSigmaService.fetchYaraSigmaMatches())
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
        const iocValue = ioc.ioc || ioc.indicator || ioc.value || '';
        const iocType = (ioc.ioc_type || '').toLowerCase();
        const alertUrl = (iocType === 'url' || iocType === 'domain' || iocType === 'ip:port' || iocType === 'ip')
          ? iocValue
          : (ioc.id ? `https://threatfox.abuse.ch/ioc/${ioc.id}` : '');

        alerts.push({
          source: 'ThreatFox',
          externalId: ioc.id ? ioc.id.toString() : '',
          title: iocValue || `ThreatFox IOC (${ioc.ioc_type || 'unknown'})`,
          severity: 'High', // treat ThreatFox IOCs as high severity
          date: ioc.first_seen || '',
          url: alertUrl,
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

    // Persist alerts to DB using upsert to avoid overwriting user updates (status, attack_phase)
    await persistAlerts(alerts);

    console.log(`Fetched and stored ${alerts.length} alerts.`);

    // Perform automated brand monitoring for configured brands
    try {
      const settings = await settingsStore.getSettings(db);
      let monitoredBrands = [];
      try {
        monitoredBrands = JSON.parse(settings.MONITORED_BRANDS || '[]');
      } catch (e) {
        console.error('Failed to parse MONITORED_BRANDS:', e.message);
      }

      if (Array.isArray(monitoredBrands) && monitoredBrands.length > 0) {
        console.log(`Starting automated brand monitoring for: ${monitoredBrands.join(', ')}`);
        for (const brand of monitoredBrands) {
          const brandResults = await osintService.searchBrandExposure(db, brand);
          osintService.saveFindings(db, 'brand-exposure', brand, brandResults);
        }
      }
    } catch (brandErr) {
      console.error('Automated brand monitoring failed:', brandErr.message);
    }

    try {
      await intelligenceService.saveIndicatorsFromAlerts(db, alerts);
      await intelligenceService.rebuildCorrelations(db);
      const cveIds = [...new Set(alerts.flatMap(alert => intelligenceService.extractCves(`${alert.externalId || ''} ${alert.title || ''}`)))];
      intelligenceService.enrichCves(db, cveIds).catch(err => {
        console.error('CVE enrichment failed:', err.message);
      });
    } catch (intelErr) {
      console.error('Intelligence post-processing failed:', intelErr.message);
    }

    // Send notifications after storing alerts
    try {
      await notificationService.sendSlackNotifications(alerts);
      await notificationService.sendN8nWebhook(alerts);
      await notificationService.sendTelegramNotifications(alerts);
      await notificationService.sendTeamsWebhook(alerts);
    } catch (notifyErr) {
      console.error('Error sending notifications:', notifyErr.message);
    }
  } catch (err) {
    console.error('Error fetching alerts:', err);
  } finally {
    fetchAllSourcesRunning = false;
  }
}

// Mount alerts router
const alertsRouter = require('./routes/alerts')(db);
app.use('/api/alerts', authMiddleware, alertsRouter);

// Mount Auth router (Unprotected)
const authRouter = require('./routes/auth');
app.use('/auth', authRouter);

// Mount API routers
const assetsRouter = require('./routes/assets')(db);
app.use('/api/assets', authMiddleware, assetsRouter);

const vendorsRouter = require('./routes/vendors')(db);
app.use('/api/vendors', authMiddleware, vendorsRouter);

const dnsImpersonationRouter = require('./routes/dns_impersonation')(db);
app.use('/api/dns-impersonation', authMiddleware, dnsImpersonationRouter);
app.use('/api/dns_impersonation', authMiddleware, dnsImpersonationRouter);

const huntRouter = require('./routes/threatHunting')(db);
app.use('/api/hunt', authMiddleware, huntRouter);

const osintRouter = require('./routes/osint')(db);
app.use('/api/osint', authMiddleware, osintRouter);

const ingestionRouter = require('./routes/ingestion')(db);
app.use('/api/ingestion', authMiddleware, ingestionRouter);

const intelligenceRouter = require('./routes/intelligence')(db);
app.use('/api/intelligence', authMiddleware, intelligenceRouter);

const usersRouter = require('./routes/users')(db);
app.use('/api/users', authMiddleware, usersRouter);

const settingsRouter = require('./routes/settings')(db);
app.use('/api/settings', authMiddleware, settingsRouter);

// Health endpoint
app.get('/', (req, res) => {
  res.send('ThreatDock backend is running.');
});

async function start() {
  await initializeDatabase(db);

  // Initial fetch on startup
  fetchAllSources();
  // Schedule to run every hour at minute 0
  cron.schedule('0 * * * *', fetchAllSources);

  app.listen(PORT, () => {
    console.log(`Backend server listening on port ${PORT}`);
  });
}

start().catch(err => {
  console.error('Failed to start backend:', err.message);
  db.close(() => process.exit(1));
});
