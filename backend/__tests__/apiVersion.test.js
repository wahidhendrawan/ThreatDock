/**
 * API versioning tests
 */
jest.mock('jwks-rsa', () => ({
  JwksClient: jest.fn().mockImplementation(() => ({
    getSigningKey: jest.fn().mockResolvedValue({
      getPublicKey: () => '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----'
    })
  }))
}));
jest.mock('../services/oauth', () => ({
  validateToken: jest.fn((req, res, next) => next()),
  exchangeCodeForToken: jest.fn().mockResolvedValue({ id_token: 'mock-id-token' }),
  getUserInfo: jest.fn().mockResolvedValue({ sub: 'test-user' })
}));
const request = require('supertest');
const app = require('../app');

describe('API versioning', () => {
  test('GET /api/version returns version info', async () => {
    const res = await request(app).get('/api/version').expect(200);
    expect(res.body).toHaveProperty('current', 'v1');
    expect(res.body).toHaveProperty('supported');
    expect(res.body.supported).toContain('legacy');
    expect(res.body.supported).toContain('v1');
  });

  test('Legacy /api/alerts returns X-API-Version: legacy header', async () => {
    const res = await request(app).get('/api/alerts').expect(200); // Now 200 due to auth mock
    expect(res.headers['x-api-version']).toBe('legacy');
  });

  test('Versioned /api/v1/alerts returns X-API-Version: v1 header', async () => {
    const res = await request(app).get('/api/v1/alerts').expect(200);
    expect(res.headers['x-api-version']).toBe('v1');
  });

  test('Legacy /api/notify returns legacy version header', async () => {
    const res = await request(app).post('/api/notify').send({ title: 'test' }).expect(200);
    expect(res.headers['x-api-version']).toBe('legacy');
  });

  test('Versioned /api/v1/notify returns v1 version header', async () => {
    const res = await request(app).post('/api/v1/notify').send({ title: 'test' }).expect(200);
    expect(res.headers['x-api-version']).toBe('v1');
  });

  test('Health endpoints do not have version headers', async () => {
    const res = await request(app).get('/healthz').expect(200);
    expect(res.headers['x-api-version']).toBeUndefined();
  });

  test('/auth has no version header (unversioned)', async () => {
    const res = await request(app).get('/auth/login').expect(200);
    expect(res.headers['x-api-version']).toBeUndefined();
  });

  test('/api/v1/auth has version header', async () => {
    const res = await request(app).get('/api/v1/auth/login').expect(200);
    expect(res.headers['x-api-version']).toBe('v1');
  });
});