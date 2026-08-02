const express = require('express');
const request = require('supertest');
const {
  createRequestId,
  requestIdMiddleware,
  requestLoggingMiddleware,
  renderPrometheusMetrics,
  resetMetricsForTest
} = require('../services/observability');

describe('observability middleware', () => {
  beforeEach(() => resetMetricsForTest());

  test('uses a valid client correlation ID and rejects malformed values', () => {
    expect(createRequestId('trace-abc.123')).toBe('trace-abc.123');
    expect(createRequestId('bad value')).toMatch(/^[0-9a-f-]{36}$/i);
    expect(createRequestId('x'.repeat(129))).toMatch(/^[0-9a-f-]{36}$/i);
  });

  test('returns a request ID and exposes Prometheus request metrics', async () => {
    const app = express();
    app.use(requestIdMiddleware);
    app.use(requestLoggingMiddleware);
    app.get('/healthz', (_req, res) => res.json({ status: 'ok' }));

    const response = await request(app).get('/healthz').set('X-Request-ID', 'e2e-trace-1').expect(200);
    expect(response.headers['x-request-id']).toBe('e2e-trace-1');

    const metrics = renderPrometheusMetrics();
    expect(metrics).toContain('threatdock_http_requests_total{method="GET",route="/healthz",status_code="200"} 1');
    expect(metrics).toContain('threatdock_http_request_duration_seconds_count{method="GET",route="/healthz"} 1');
  });
});
