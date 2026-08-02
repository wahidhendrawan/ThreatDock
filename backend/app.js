require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { schedule } = require('./services/scheduler');
const errorMonitor = require('./services/errorMonitor');

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
const { JobQueue } = require('./services/queue');
const { runRebuildCorrelations } = require('./services/worker');
const { circuitBreaker, CircuitBreakerError } = require('./services/circuitBreaker');
const { DeadLetterQueue } = require('./services/deadLetterQueue');

const authMiddleware = require('./middleware/auth');
const rateLimit = require('./middleware/rateLimit');
const rssService = require('./services/rss');
const osintService = require('./services/osint');

const app = express();
const PORT = process.env.PORT || 5002;

// Middleware
const helmet = require('helmet');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https:'],
      imgSrc: ["'self'", 'data:', 'https:'],
      fontSrc: ["'self'", 'https:', 'data:'],
      connectSrc: ["'self'", 'ws:', 'wss:'],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  }
}));
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});
app.use(cors());

// P0-3: JSON body size limit (defense against oversized payloads).
// Applies to all API requests. Individual routes may still layer stricter limits.
const JSON_BODY_LIMIT = process.env.JSON_BODY_LIMIT || '10mb';
app.use(express.json({ limit: JSON_BODY_LIMIT }));

// P0-3: Reject non-JSON content on JSON-only endpoints and cap URL-encoded payloads.
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

// P0-3: Per-request timeout guard so that a slow client/large upstream cannot pin a socket.
const REQUEST_TIMEOUT_MS = parseInt(process.env.REQUEST_TIMEOUT_MS || '30000', 10);
app.use((req, res, next) => {
  req.setTimeout(REQUEST_TIMEOUT_MS, () => {
    if (!res.headersSent) {
      res.status(504).json({ error: 'Request timed out' });
    }
    req.destroy();
  });
  next();
});

app.disable('x-powered-by');

// P0-3: Map body-parser failures to clear client errors instead of generic 500s.
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request payload exceeds the configured size limit.' });
  }
  if (err && (err.type === 'entity.parse.failed' || err instanceof SyntaxError)) {
    return res.status(400).json({ error: 'Malformed request body.' });
  }
  return next(err);
});

// Trust proxy for correct IP detection behind nginx
app.set('trust proxy', 1);

// Initialize error monitoring (global handlers + express middleware)
errorMonitor.init(app);

// Create HTTP server and WebSocket
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

// Initialize PostgreSQL database adapter
const db = createDatabase();
const jobQueue = new JobQueue();
const deadLetterQueue = new DeadLetterQueue(db);

app.use((req, res, next) => {
  req.db = db;
  next();
});

// Remove global authMiddleware here

// Settings cache with TTL
let cachedSettings = null;
let lastSettingsFetch = 0;
const SETTINGS_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

function getRuntimeSettings() {
  return settingsStore.getSettings(db);
}

async function applyRuntimeSettings() {
  const now = Date.now();
  let settings;
  if (cachedSettings && (now - lastSettingsFetch) < SETTINGS_CACHE_TTL) {
    settings = cachedSettings;
  } else {
    settings = await getRuntimeSettings();
    cachedSettings = settings;
    lastSettingsFetch = now;
  }
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

async function recordSourceRun(source, status, itemCount, durationMs, error, startedAt, finishedAt) {
  const errorText = error ? String(error).slice(0, 1000) : '';
  await Promise.all([
    db.run(
      `INSERT INTO ingestion_runs (source, status, item_count, duration_ms, error, started_at, finished_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [source, status, itemCount, durationMs, errorText, startedAt, finishedAt]
    ),
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
    )
  ]);
  io.emit('source:health', { source, status, itemCount, durationMs });
}

/**
 * Fetch from a source with retry (exponential backoff), health tracking, and timeout.
 */
const RETRY_CONFIGS = {
  'NVD': { retries: 2, baseDelay: 2000 },
  'OTX': { retries: 2, baseDelay: 2000 },
  'RSS': { retries: 1, baseDelay: 1000 },
  'Red Hat': { retries: 1, baseDelay: 1000 },
  'GitHub': { retries: 2, baseDelay: 1000 },
  'ThreatFox': { retries: 1, baseDelay: 1000 },
  default: { retries: 1, baseDelay: 1000 }
};

async function fetchSourceWithHealth(source, fetcher) {
  const startedAt = new Date().toISOString();
  const start = Date.now();
  const cfg = RETRY_CONFIGS[source] || RETRY_CONFIGS.default;

  try {
    const data = await circuitBreaker.execute(source, async () => {
      let lastError;
      for (let attempt = 0; attempt <= cfg.retries; attempt += 1) {
        if (attempt > 0) {
          const delay = cfg.baseDelay * (2 ** (attempt - 1));
          console.log(`${source} retry ${attempt}/${cfg.retries} (delay ${delay}ms)...`);
          await new Promise(resolve => setTimeout(resolve, delay));
        }

        try {
          return await fetcher();
        } catch (error) {
          lastError = error;
          if (attempt < cfg.retries) {
            console.warn(`${source} attempt ${attempt + 1} failed: ${error.message}`);
          }
        }
      }
      throw lastError || new Error(`${source} fetch failed`);
    });

    const finishedAt = new Date().toISOString();
    await recordSourceRun(
      source,
      'Success',
      countFetchedItems(source, data),
      Date.now() - start,
      '',
      startedAt,
      finishedAt
    );
    return data;
  } catch (error) {
    const finishedAt = new Date().toISOString();
    const circuitOpen = error instanceof CircuitBreakerError;
    const status = circuitOpen ? 'Skipped' : 'Failure';

    await recordSourceRun(source, status, 0, Date.now() - start, error.message, startedAt, finishedAt)
      .catch(recordError => console.error(`${source} health recording failed:`, recordError.message));

    if (!circuitOpen) {
      await deadLetterQueue.add(
        source,
        'source_fetch',
        { startedAt, retries: cfg.retries },
        error.message
      );
      console.error(`${source} fetch failed after ${cfg.retries + 1} attempts:`, error.message);
    } else {
      console.warn(error.message);
    }
    return [];
  }
}

async function getDefaultTenant() {
  const result = await db.query("SELECT id FROM tenants WHERE slug = 'default'");
  if (result.rows.length === 0) throw new Error('Default tenant not found');
  return result.rows[0].id;
}

async function persistAlerts(alerts, tenantId) {
  if (alerts.length === 0) return;
  // Deduplicate by (source, externalId) to avoid ON CONFLICT errors in batch
  const seen = new Set();
  const unique = [];
  for (const alert of alerts) {
    const key = `${alert.source}:${alert.externalId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(alert);
  }
  const BATCH_SIZE = 1000;
  for (let i = 0; i < unique.length; i += BATCH_SIZE) {
    const batch = unique.slice(i, i + BATCH_SIZE);
    const values = [];
    const params = [];
    let idx = 0;
    for (const alert of batch) {
      const n = idx * 9;
      values.push(`($${n+1},$${n+2},$${n+3},$${n+4},$${n+5},$${n+6},$${n+7},$${n+8},$${n+9})`);
      params.push(
        tenantId,
        alert.source,
        alert.externalId,
        alert.title,
        alert.severity,
        alert.date,
        alert.url,
        alert.status || 'Open',
        alert.attack_phase || 'Unknown'
      );
      idx++;
    }
    await db.query(`
      INSERT INTO alerts (tenant_id, source, "externalId", title, severity, date, url, status, attack_phase)
      VALUES ${values.join(', ')}
      ON CONFLICT(source, "externalId") DO UPDATE SET
        title = excluded.title,
        severity = excluded.severity,
        date = excluded.date,
        url = excluded.url,
        attack_phase = CASE WHEN excluded.attack_phase != 'Unknown' THEN excluded.attack_phase ELSE alerts.attack_phase END
    `, params);
  }
}

let fetchAllSourcesRunning = false;
let fetchStartedAt = 0;
const FETCH_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes safety timeout

/**
 * Fetch data from all configured sources and store in PostgreSQL.
 */
async function fetchAllSources() {
  // Safety: reset if stuck longer than FETCH_TIMEOUT_MS
  if (fetchAllSourcesRunning) {
    if (Date.now() - fetchStartedAt > FETCH_TIMEOUT_MS) {
      console.warn('Previous fetch timed out. Resetting lock.');
      fetchAllSourcesRunning = false;
    } else {
      console.warn('Skipping source fetch because a previous run is still active.');
      return;
    }
  }

  fetchAllSourcesRunning = true;
  fetchStartedAt = Date.now();
  try {
    await applyRuntimeSettings();

    // Get default tenant for background writes
    const defaultTenantId = await getDefaultTenant();

    // fetchSourceWithHealth owns retries, timeouts, circuit state, and failure recording.
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
    await persistAlerts(alerts, defaultTenantId);
    io.emit('alerts:updated', { count: alerts.length });

    console.log(`Fetched and stored ${alerts.length} alerts.`);

    // Perform automated brand monitoring for configured brands (parallel via queue)
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
        await Promise.all(monitoredBrands.map(async (brand) => {
          const brandResults = await osintService.searchBrandExposure(db, brand, defaultTenantId);
          osintService.saveFindings(db, defaultTenantId, 'brand-exposure', brand, brandResults);
        }));
      }
    } catch (brandErr) {
      console.error('Automated brand monitoring failed:', brandErr.message);
    }

    try {
      await intelligenceService.saveIndicatorsFromAlerts(db, alerts);
      // Use worker thread for CPU-heavy correlation rebuild
      try {
        await runRebuildCorrelations(db);
      } catch (err) {
        console.error('Worker correlation rebuild failed, falling back to inline:', err.message);
        await intelligenceService.rebuildCorrelations(db);
      }
      io.emit('correlations:updated');
      const cveIds = [...new Set(alerts.flatMap(alert => intelligenceService.extractCves(`${alert.externalId || ''} ${alert.title || ''}`)))];
      intelligenceService.enrichCves(db, cveIds).catch(err => {
        console.error('CVE enrichment failed:', err.message);
      });
    } catch (intelErr) {
      console.error('Intelligence post-processing failed:', intelErr.message);
    }

    // Send notifications after storing alerts (parallel, non-blocking)
    try {
      await Promise.allSettled([
        notificationService.sendSlackNotifications(alerts),
        notificationService.sendN8nWebhook(alerts),
        notificationService.sendTelegramNotifications(alerts),
        notificationService.sendTeamsWebhook(alerts)
      ]);
    } catch (notifyErr) {
      console.error('Error sending notifications:', notifyErr.message);
    }
  } catch (err) {
    console.error('Error fetching alerts:', err);
  } finally {
    fetchAllSourcesRunning = false;
    io.emit('fetch:complete');
  }
}

// Apply rate limiters
const apiLimiter = rateLimit({ windowMs: 60000, max: 600, message: 'API rate limit exceeded (600/min)' });
const authLimiter = rateLimit({ windowMs: 60000, max: 120, message: 'Auth rate limit exceeded (120/min)' });

// Mount alerts router
const alertsRouter = require('./routes/alerts')(db);
app.use('/api/alerts', apiLimiter, authMiddleware, alertsRouter);

// Mount Auth router (Unprotected)
const authRouter = require('./routes/auth');
app.use('/auth', authLimiter, authRouter);

// Mount API routers
const assetsRouter = require('./routes/assets')(db);
app.use('/api/assets', apiLimiter, authMiddleware, assetsRouter);

const vendorsRouter = require('./routes/vendors')(db);
app.use('/api/vendors', apiLimiter, authMiddleware, vendorsRouter);

const dnsImpersonationRouter = require('./routes/dns_impersonation')(db);
app.use('/api/dns-impersonation', apiLimiter, authMiddleware, dnsImpersonationRouter);
app.use('/api/dns_impersonation', apiLimiter, authMiddleware, dnsImpersonationRouter);

const huntRouter = require('./routes/threatHunting')(db);
app.use('/api/hunt', apiLimiter, authMiddleware, huntRouter);

const osintRouter = require('./routes/osint')(db);
app.use('/api/osint', apiLimiter, authMiddleware, osintRouter);

const ingestionRouter = require('./routes/ingestion')(db, { fetchAllSources });
app.use('/api/ingestion', apiLimiter, authMiddleware, ingestionRouter);

// Swagger API docs
const swaggerSpec = require('./services/swagger');
app.use('/swagger', express.static('public/swagger'));
app.get('/api/docs.json', (req, res) => res.json(swaggerSpec));
app.get('/api/docs', (req, res) => {
  res.send(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>ThreatDock API Docs</title><link rel="stylesheet" href="/swagger/swagger-ui.css"></head><body><div id="swagger-ui"></div><script src="/swagger/swagger-ui-bundle.js"></script><script>SwaggerUIBundle({url:"/api/docs.json",dom_id:"#swagger-ui",presets:[SwaggerUIBundle.presets.apis],layout:"BaseLayout"})</script></body></html>`);
});

// Push notification endpoint (broadcasts to all WebSocket clients)
app.post('/api/notify', (req, res) => {
  const { title, body, severity } = req.body || {};
  if (!title) return res.status(400).json({ error: 'Title is required' });
  io.emit('push:notification', { title, body, severity: severity || 'info', timestamp: new Date().toISOString() });
  res.json({ sent: true });
});

const intelligenceRouter = require('./routes/intelligence')(db);
app.use('/api/intelligence', apiLimiter, authMiddleware, intelligenceRouter);

const usersRouter = require('./routes/users')(db);
app.use('/api/users', apiLimiter, authMiddleware, usersRouter);

const settingsRouter = require('./routes/settings')(db);
app.use('/api/settings', apiLimiter, authMiddleware, settingsRouter);

// Health endpoint
app.get('/', (req, res) => {
  res.send('ThreatDock backend is running.');
});

async function start() {
  await initializeDatabase(db);
  await deadLetterQueue.initialize();

  // Weekly data retention prune (Sunday at 3 AM)
  schedule('0 3 * * 0', async () => {
    try {
      const result = await db.query(`SELECT prune_old_alerts(90) as pruned`);
      const count = result.rows[0]?.pruned || 0;
      if (count > 0) console.log(`Pruned ${count} old alerts.`);
    } catch (err) {
      console.error('Alert pruning failed:', err.message);
    }
  }, { name: 'alert-prune' });

  // Initial fetch on startup
  fetchAllSources();
  // Schedule to run every hour at minute 0
  schedule('0 * * * *', fetchAllSources, { name: 'source-fetch' });

  server.listen(PORT, () => {
    console.log(`Backend server listening on port ${PORT}`);
  });
}

start().catch(err => {
  console.error('Failed to start backend:', err.message);
  db.close(() => process.exit(1));
});
