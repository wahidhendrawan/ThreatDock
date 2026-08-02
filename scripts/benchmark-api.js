#!/usr/bin/env node

const baseUrl = (process.env.PERF_BASE_URL || 'http://127.0.0.1:5002').replace(/\/$/, '');
const token = process.env.PERF_AUTH_TOKEN;
const requests = Math.max(1, Number.parseInt(process.env.PERF_REQUESTS || '50', 10));
const concurrency = Math.max(1, Number.parseInt(process.env.PERF_CONCURRENCY || '5', 10));
const maxP95Ms = Math.max(1, Number.parseInt(process.env.PERF_MAX_P95_MS || '500', 10));
const maxErrorRate = Number(process.env.PERF_MAX_ERROR_RATE || '0.01');
const enforceThresholds = process.env.PERF_ENFORCE_THRESHOLDS === 'true';

const endpoints = ['/healthz', '/api/docs.json'];
if (token) endpoints.push('/api/alerts?limit=25', '/api/assets?limit=25', '/api/intelligence/correlations?limit=25');

function percentile(samples, percentileValue) {
  if (!samples.length) return 0;
  const position = Math.ceil((percentileValue / 100) * samples.length) - 1;
  return samples.slice().sort((a, b) => a - b)[Math.max(0, position)];
}

async function requestEndpoint(path) {
  const startedAt = performance.now();
  try {
    const response = await fetch(`${baseUrl}${path}`, {
      headers: token && path.startsWith('/api/') && path !== '/api/docs.json' ? { Authorization: `Bearer ${token}` } : {}
    });
    return { path, status: response.status, durationMs: performance.now() - startedAt, ok: response.ok };
  } catch (error) {
    return { path, status: 0, durationMs: performance.now() - startedAt, ok: false, error: error.message };
  }
}

async function run() {
  const jobs = Array.from({ length: requests }, (_, index) => endpoints[index % endpoints.length]);
  const results = [];
  let next = 0;

  async function worker() {
    while (next < jobs.length) {
      const index = next++;
      results.push(await requestEndpoint(jobs[index]));
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, jobs.length) }, worker));
  const durations = results.map(result => result.durationMs);
  const failures = results.filter(result => !result.ok);
  const byEndpoint = Object.fromEntries(endpoints.map(path => {
    const values = results.filter(result => result.path === path);
    return [path, {
      requests: values.length,
      errors: values.filter(result => !result.ok).length,
      p50_ms: Number(percentile(values.map(result => result.durationMs), 50).toFixed(2)),
      p95_ms: Number(percentile(values.map(result => result.durationMs), 95).toFixed(2))
    }];
  }));
  const summary = {
    target: baseUrl,
    authenticated: Boolean(token),
    requests: results.length,
    concurrency,
    error_rate: Number((failures.length / results.length).toFixed(4)),
    p50_ms: Number(percentile(durations, 50).toFixed(2)),
    p95_ms: Number(percentile(durations, 95).toFixed(2)),
    thresholds: { max_p95_ms: maxP95Ms, max_error_rate: maxErrorRate },
    endpoints: byEndpoint,
    failures: failures.slice(0, 10)
  };

  console.log(JSON.stringify(summary, null, 2));
  const thresholdFailed = summary.p95_ms > maxP95Ms || summary.error_rate > maxErrorRate;
  if (enforceThresholds && thresholdFailed) process.exitCode = 1;
}

run().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
