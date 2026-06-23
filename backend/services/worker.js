/**
 * Worker threads for CPU-intensive background processing.
 * Runs rebuildCorrelations in a separate thread to avoid blocking the event loop.
 */
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const path = require('path');

const WORKER_FILE = path.resolve(__dirname, 'worker.js');

/**
 * Run rebuildCorrelations in a worker thread.
 * @param {object} db - Database adapter (used only in main thread for data)
 * @returns {Promise<void>}
 */
async function runRebuildCorrelations(db) {
  // Fetch data in main thread (DB access stays here)
  const [alerts, indicators, assets, vendors] = await Promise.all([
    allAsync(db, 'SELECT id, source, externalId, title, severity, date, url FROM alerts ORDER BY date DESC LIMIT 5000'),
    allAsync(db, 'SELECT id, value, type, source, severity FROM indicators ORDER BY updated_at DESC LIMIT 5000'),
    allAsync(db, 'SELECT id, domain, ip FROM assets'),
    allAsync(db, 'SELECT id, name FROM vendors')
  ]);

  // Run CPU-heavy computation in worker thread
  return new Promise((resolve, reject) => {
    const worker = new Worker(WORKER_FILE, {
      workerData: { alerts, indicators, assets, vendors, type: 'correlations' }
    });

    worker.on('message', async (msg) => {
      if (msg.error) return reject(new Error(msg.error));
      try {
        // Batch INSERT results from worker
        const BATCH_SIZE = 500;
        for (let i = 0; i < msg.entries.length; i += BATCH_SIZE) {
          const batch = msg.entries.slice(i, i + BATCH_SIZE);
          const values = [];
          const params = [];
          let idx = 0;
          for (const e of batch) {
            const n = idx * 9;
            values.push(`($${n+1},$${n+2},$${n+3},$${n+4},$${n+5},$${n+6},$${n+7},$${n+8},$${n+9},'Open',CURRENT_TIMESTAMP)`);
            params.push(e.groupKey, e.title, e.severity, e.score, e.confidence, e.sources, e.alertIds, e.indicatorIds, e.entityRefs);
            idx++;
          }
          await db.query(`
            INSERT INTO correlated_findings (group_key, title, severity, score, confidence, sources, alert_ids, indicator_ids, entity_refs, status, updated_at)
            VALUES ${values.join(', ')}
            ON CONFLICT(group_key) DO UPDATE SET
              title = excluded.title, severity = excluded.severity, score = excluded.score,
              confidence = excluded.confidence, sources = excluded.sources,
              alert_ids = excluded.alert_ids, indicator_ids = excluded.indicator_ids,
              entity_refs = excluded.entity_refs, updated_at = CURRENT_TIMESTAMP
          `, params);
        }
        resolve();
      } catch (err) {
        reject(new Error('Batch insert failed: ' + err.message));
      }
    });

    worker.on('error', reject);
    worker.on('exit', (code) => {
      if (code !== 0) reject(new Error(`Worker exited with code ${code}`));
    });
  });
}

// Promise wrappers for DB
function allAsync(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

// ────────────────────────────────────────────
// Worker thread code (runs when NOT isMainThread)
// ────────────────────────────────────────────
if (!isMainThread) {
  const { severityOrder, maxSeverity, extractCves, extractDomains } = require('./intelligence');

  function addGroup(groups, groupKey, title, alert, indicator, entityRef) {
    if (!groups.has(groupKey)) {
      groups.set(groupKey, {
        groupKey, title, alerts: [], indicators: [],
        sources: new Set(), entityRefs: new Set()
      });
    }
    const group = groups.get(groupKey);
    if (alert) { group.alerts.push(alert); if (alert.source) group.sources.add(alert.source); }
    if (indicator) { group.indicators.push(indicator); if (indicator.source) group.sources.add(indicator.source); }
    if (entityRef) group.entityRefs.add(entityRef);
  }

  async function computeCorrelations({ alerts, indicators, assets, vendors }) {
    const groups = new Map();

    // Alert-based grouping
    for (const alert of alerts) {
      const text = `${alert.externalId || ''} ${alert.title || ''} ${alert.url || ''}`;
      for (const cve of extractCves(text)) addGroup(groups, `cve:${cve}`, cve, alert, null, cve);
      for (const domain of extractDomains(text)) addGroup(groups, `domain:${domain}`, domain, alert, null, domain);
    }

    // Indicator-based grouping
    for (const indicator of indicators) {
      const key = `${indicator.type}:${String(indicator.value || '').toLowerCase()}`;
      addGroup(groups, key, indicator.value, null, indicator, indicator.value);
    }

    // Asset matching via word index
    const wordIndex = new Map();
    for (const [key] of groups) {
      const words = key.toLowerCase().split(/[:.\s-]+/);
      for (const word of words) {
        if (word.length < 2) continue;
        if (!wordIndex.has(word)) wordIndex.set(word, []);
        wordIndex.get(word).push(key);
      }
    }
    for (const asset of assets) {
      const values = [asset.domain, asset.ip].filter(Boolean).map(v => String(v).toLowerCase());
      for (const value of values) {
        const matched = new Set();
        for (const [key] of groups) { if (key.includes(value)) matched.add(key); }
        const valueWords = value.split(/[:.\s-]+/);
        for (const w of valueWords) {
          if (w.length < 2) continue;
          (wordIndex.get(w) || []).forEach(k => matched.add(k));
        }
        for (const key of matched) {
          groups.get(key)?.entityRefs.add(`asset:${asset.id}:${asset.domain || asset.ip}`);
        }
      }
    }

    // Vendor matching
    const alertTexts = alerts.map(a => ({ alert: a, text: `${a.title || ''} ${a.source || ''}`.toLowerCase() }));
    for (const vendor of vendors) {
      const name = String(vendor.name || '').toLowerCase();
      if (!name) continue;
      for (const { alert, text } of alertTexts) {
        if (text.includes(name)) addGroup(groups, `vendor:${name}`, vendor.name, alert, null, `vendor:${vendor.id}:${vendor.name}`);
      }
    }

    // Serialize for main thread
    const entries = [];
    for (const group of groups.values()) {
      const allItems = [...group.alerts, ...group.indicators];
      if (allItems.length === 0) continue;
      const severity = maxSeverity(allItems);
      const sourceCount = group.sources.size;
      const score = Math.min(100, (severityOrder[severity] || 0) * 20 + sourceCount * 8 + allItems.length * 2);
      const confidence = Math.min(100, 45 + sourceCount * 15 + Math.min(allItems.length * 5, 30));
      entries.push({
        groupKey: group.groupKey,
        title: group.title || group.groupKey,
        severity, score, confidence,
        sources: JSON.stringify([...group.sources]),
        alertIds: JSON.stringify(group.alerts.map(a => a.id).filter(Boolean)),
        indicatorIds: JSON.stringify(group.indicators.map(i => i.id).filter(Boolean)),
        entityRefs: JSON.stringify([...group.entityRefs])
      });
    }
    return { entries };
  }

  // Worker message handler
  if (workerData?.type === 'correlations') {
    computeCorrelations(workerData).then(result => {
      parentPort.postMessage(result);
    }).catch(err => {
      parentPort.postMessage({ error: err.message });
    });
  }
}

module.exports = { runRebuildCorrelations };
