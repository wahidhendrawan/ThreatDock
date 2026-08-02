/**
 * Lightweight error monitoring service.
 * Captures unhandled errors, logs to file, optionally forwards to webhook.
 * Drop-in replacement for Sentry for self-hosted deployments.
 */
const fs = require('fs');
const path = require('path');
const { outboundHttp: axios } = require('./outboundHttp');

const LOG_DIR = process.env.ERROR_LOG_DIR || './logs';
const WEBHOOK_URL = process.env.ERROR_WEBHOOK_URL || '';
const MAX_LOG_SIZE = 10 * 1024 * 1024; // 10MB per log file

// Ensure log directory exists
try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (e) { /* ignore */ }

function getLogFile() {
  const date = new Date().toISOString().slice(0, 10);
  return path.join(LOG_DIR, `error-${date}.log`);
}

function formatError(err, context = {}) {
  const timestamp = new Date().toISOString();
  const stack = err?.stack || String(err || 'Unknown error');
  return JSON.stringify({
    timestamp,
    message: err?.message || String(err),
    stack: stack.split('\n').slice(0, 10).join('\n'),
    context,
    pid: process.pid,
    memory: process.memoryUsage?.()?.rss ? `${Math.round(process.memoryUsage().rss / 1024 / 1024)}MB` : 'N/A'
  }) + '\n';
}

function writeLog(entry) {
  try {
    const logFile = getLogFile();
    // Rotate if too large
    try {
      const stat = fs.statSync(logFile);
      if (stat.size > MAX_LOG_SIZE) {
        const rotated = logFile + '.1';
        if (fs.existsSync(rotated)) fs.unlinkSync(rotated);
        fs.renameSync(logFile, rotated);
      }
    } catch (e) { /* file doesn't exist yet */ }
    fs.appendFileSync(logFile, entry);
  } catch (e) {
    console.error('[ErrorMonitor] Failed to write log:', e.message);
  }
}

/**
 * Initialize global error handlers.
 */
function init(app) {
  // Global unhandled rejections
  process.on('unhandledRejection', (reason) => {
    const entry = formatError(reason, { type: 'unhandledRejection' });
    writeLog(entry);
    console.error('[UnhandledRejection]', reason?.message || reason);
  });

  // Global uncaught exceptions
  process.on('uncaughtException', (err) => {
    const entry = formatError(err, { type: 'uncaughtException' });
    writeLog(entry);
    console.error('[UncaughtException]', err.message);
    // Give logger time to write before exiting
    setTimeout(() => process.exit(1), 500);
  });

  // Express error handler middleware
  if (app) {
    app.use((err, req, res, _next) => {
      const entry = formatError(err, {
        type: 'express',
        method: req.method,
        url: req.originalUrl || req.url,
        ip: req.ip
      });
      writeLog(entry);
      console.error('[ExpressError]', err.message);

      // Forward to webhook (non-blocking)
      if (WEBHOOK_URL) {
        axios.post(WEBHOOK_URL, {
          text: `[ThreatDock Error] ${err.message}\nPath: ${req.method} ${req.originalUrl || req.url}`
        }, { timeout: 5000 }).catch(() => {});
      }

      res.status(err.status || 500).json({ error: 'Internal server error' });
    });
  }
}

/**
 * Manually capture an error.
 */
function captureError(err, context = {}) {
  const entry = formatError(err, context);
  writeLog(entry);
  console.error('[ErrorMonitor]', err?.message || err);
}

module.exports = { init, captureError };
