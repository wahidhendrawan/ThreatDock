const crypto = require('crypto');

const startedAtMs = Date.now();
const requestCounts = new Map();
const requestDurations = new Map();
const durationBuckets = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

function escapeLabel(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

function createRequestId(value) {
  if (typeof value === 'string' && /^[A-Za-z0-9._-]{1,128}$/.test(value)) return value;
  return crypto.randomUUID();
}

function requestIdMiddleware(req, res, next) {
  const requestId = createRequestId(req.get('x-request-id'));
  req.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);
  next();
}

function normalizedRoute(req) {
  if (req.route?.path) return `${req.baseUrl || ''}${req.route.path}`;
  const url = req.baseUrl || req.path || '/';
  return url
    .replace(/\b[0-9]+\b/g, ':id')
    .replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/gi, ':id')
    .slice(0, 200);
}

function recordRequest(method, route, status, durationSeconds) {
  const key = `${method}|${route}|${status}`;
  requestCounts.set(key, (requestCounts.get(key) || 0) + 1);

  const durationKey = `${method}|${route}`;
  const measurement = requestDurations.get(durationKey) || {
    count: 0,
    sum: 0,
    buckets: new Array(durationBuckets.length).fill(0)
  };
  measurement.count += 1;
  measurement.sum += durationSeconds;
  durationBuckets.forEach((bucket, index) => {
    if (durationSeconds <= bucket) measurement.buckets[index] += 1;
  });
  requestDurations.set(durationKey, measurement);
}

function structuredLog(level, event, fields = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    event,
    service: 'threatdock-backend',
    ...fields
  };
  const writer = level === 'error' ? console.error : level === 'warn' ? console.warn : console.log;
  writer(JSON.stringify(entry));
}

function requestLoggingMiddleware(req, res, next) {
  const startedAt = process.hrtime.bigint();
  res.on('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
    const route = normalizedRoute(req);
    recordRequest(req.method, route, res.statusCode, durationMs / 1000);
    structuredLog(res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info', 'http_request', {
      request_id: req.requestId,
      method: req.method,
      route,
      status_code: res.statusCode,
      duration_ms: Math.round(durationMs * 1000) / 1000,
      remote_ip: req.ip
    });
  });
  next();
}

function formatLabels(labels) {
  return Object.entries(labels)
    .map(([name, value]) => `${name}="${escapeLabel(value)}"`)
    .join(',');
}

function renderPrometheusMetrics() {
  const lines = [
    '# HELP threatdock_process_start_time_seconds Unix timestamp for backend startup.',
    '# TYPE threatdock_process_start_time_seconds gauge',
    `threatdock_process_start_time_seconds ${startedAtMs / 1000}`,
    '# HELP threatdock_process_resident_memory_bytes Resident memory used by the Node.js process.',
    '# TYPE threatdock_process_resident_memory_bytes gauge',
    `threatdock_process_resident_memory_bytes ${process.memoryUsage().rss}`,
    '# HELP threatdock_http_requests_total Completed HTTP requests.',
    '# TYPE threatdock_http_requests_total counter'
  ];

  for (const [key, count] of requestCounts) {
    const [method, route, status] = key.split('|');
    lines.push(`threatdock_http_requests_total{${formatLabels({ method, route, status_code: status })}} ${count}`);
  }

  lines.push(
    '# HELP threatdock_http_request_duration_seconds Completed HTTP request durations.',
    '# TYPE threatdock_http_request_duration_seconds histogram'
  );
  for (const [key, measurement] of requestDurations) {
    const [method, route] = key.split('|');
    durationBuckets.forEach((bucket, index) => {
      lines.push(`threatdock_http_request_duration_seconds_bucket{${formatLabels({ method, route, le: bucket })}} ${measurement.buckets[index]}`);
    });
    lines.push(`threatdock_http_request_duration_seconds_bucket{${formatLabels({ method, route, le: '+Inf' })}} ${measurement.count}`);
    lines.push(`threatdock_http_request_duration_seconds_sum{${formatLabels({ method, route })}} ${measurement.sum}`);
    lines.push(`threatdock_http_request_duration_seconds_count{${formatLabels({ method, route })}} ${measurement.count}`);
  }

  return `${lines.join('\n')}\n`;
}

function resetMetricsForTest() {
  requestCounts.clear();
  requestDurations.clear();
}

module.exports = {
  createRequestId,
  requestIdMiddleware,
  requestLoggingMiddleware,
  renderPrometheusMetrics,
  resetMetricsForTest,
  structuredLog
};
