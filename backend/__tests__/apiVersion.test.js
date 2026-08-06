/**
 * API versioning tests
 */

// Mock database to avoid PostgreSQL dependency in unit tests
const mockDb = {
  query: jest.fn().mockResolvedValue({ rows: [] }),
  get: jest.fn((sql, params, cb) => cb ? cb(null, null) : Promise.resolve(null)),
  all: jest.fn((sql, params, cb) => cb ? cb(null, []) : Promise.resolve([])),
  run: jest.fn((sql, params, cb) => cb ? cb(null) : Promise.resolve()),
  close: jest.fn((cb) => cb && cb())
};
jest.mock('../services/database', () => ({
  createDatabase: jest.fn(() => mockDb),
  initializeDatabase: jest.fn().mockResolvedValue()
}));
jest.mock('../services/settingsStore', () => ({
  getSettings: jest.fn().mockResolvedValue({
    JWT_SECRET: 'test-secret-key-for-testing',
    SSO_ENABLED: 'false',
    OIDC_ISSUER_URL: 'https://issuer.example.com',
    OIDC_CLIENT_ID: 'test-client',
    FRONTEND_URL: 'http://localhost:3000'
  })
}));
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
    const res = await request(app).get('/api/alerts').expect(401);
    expect(res.headers['x-api-version']).toBe('legacy');
  });

  test('Versioned /api/v1/alerts returns X-API-Version: v1 header', async () => {
    const res = await request(app).get('/api/v1/alerts').expect(401);
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
    const res = await request(app).get('/auth/login').expect(302);
    expect(res.headers['x-api-version']).toBeUndefined();
  });

  test('/api/v1/auth has version header', async () => {
    const res = await request(app).get('/api/v1/auth/login').expect(302);
    expect(res.headers['x-api-version']).toBe('v1');
  });
});