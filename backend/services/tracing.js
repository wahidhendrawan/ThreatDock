/**
 * Lightweight tracing/correlation helper.
 *
 * The full OpenTelemetry SDK adds substantial dependency weight. Until an
 * operator provides an OTLP endpoint via `OTEL_EXPORTER_OTLP_ENDPOINT`, we
 * emit W3C-compatible traceparent headers and structured trace fields in
 * our JSON logs. This keeps every request correlatable across services
 * without requiring a collector.
 *
 * When the endpoint is set, the module lazy-loads `@opentelemetry/sdk-node`
 * and starts the SDK. If that package is not installed we log a warning and
 * fall back to the no-op path so production never crashes over telemetry.
 */

const crypto = require('crypto');

let sdk = null;

function randHex(bytes) {
  return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Parse an incoming `traceparent` header per W3C Trace Context.
 * Returns { traceId, parentId } or null if the header is missing/invalid.
 */
function parseTraceparent(header) {
  if (typeof header !== 'string') return null;
  const parts = header.trim().split('-');
  if (parts.length !== 4) return null;
  const [version, traceId, parentId, flags] = parts;
  if (version !== '00') return null;
  if (!/^[0-9a-f]{32}$/.test(traceId) || traceId === '0'.repeat(32)) return null;
  if (!/^[0-9a-f]{16}$/.test(parentId) || parentId === '0'.repeat(16)) return null;
  if (!/^[0-9a-f]{2}$/.test(flags)) return null;
  return { traceId, parentId, flags };
}

function buildTraceparent({ traceId, spanId, sampled = true }) {
  const flags = sampled ? '01' : '00';
  return `00-${traceId}-${spanId}-${flags}`;
}

/**
 * Express middleware that attaches a trace context to every request.
 * Downstream code and logs can reference req.trace = { traceId, spanId }.
 */
function traceContextMiddleware(req, res, next) {
  const incoming = parseTraceparent(req.get('traceparent'));
  const traceId = incoming?.traceId || randHex(16);
  const spanId = randHex(8);
  req.trace = { traceId, spanId, parentSpanId: incoming?.parentId || null };
  res.setHeader('traceparent', buildTraceparent({ traceId, spanId }));
  next();
}

/**
 * Initialize the OpenTelemetry Node SDK when an OTLP endpoint is configured.
 * Safe to call from app bootstrap: no-ops when the dependency is missing.
 */
function initTelemetry({ serviceName = 'threatdock-backend' } = {}) {
  const endpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
  if (!endpoint) return { enabled: false, reason: 'no_endpoint' };
  if (sdk) return { enabled: true, reason: 'already_started' };

  try {
    const { NodeSDK } = require('@opentelemetry/sdk-node');
    const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-http');
    const { Resource } = require('@opentelemetry/resources');
    const { SemanticResourceAttributes } = require('@opentelemetry/semantic-conventions');

    sdk = new NodeSDK({
      resource: new Resource({
        [SemanticResourceAttributes.SERVICE_NAME]: serviceName
      }),
      traceExporter: new OTLPTraceExporter({ url: endpoint })
    });
    sdk.start();
    return { enabled: true, reason: 'started' };
  } catch (err) {
    console.warn(JSON.stringify({
      level: 'warn',
      event: 'tracing_init_failed',
      message: 'OpenTelemetry SDK unavailable; falling back to header-only correlation.',
      error: err.message
    }));
    return { enabled: false, reason: 'sdk_unavailable' };
  }
}

async function shutdownTelemetry() {
  if (sdk && typeof sdk.shutdown === 'function') {
    await sdk.shutdown().catch(() => {});
    sdk = null;
  }
}

module.exports = {
  parseTraceparent,
  buildTraceparent,
  traceContextMiddleware,
  initTelemetry,
  shutdownTelemetry
};
