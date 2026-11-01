/**
 * Regression tests for authentication, MFA, rate limiting, OIDC and outbound hardening.
 */
const crypto = require('crypto');
const express = require('express');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { generateSecret, generateSync } = require('otplib');

const mockKeys = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

jest.mock('jwks-rsa', () => jest.fn(() => ({
  getSigningKey: jest.fn().mockResolvedValue({ publicKey: mockKeys.publicKey })
})));

jest.mock('dns', () => {
  const nx = () => jest.fn().mockRejectedValue(new Error('ENOTFOUND'));
  return {
    promises: { lookup: jest.fn(), resolve4: nx(), resolve6: nx(), resolveCname: nx(), resolveNs: nx() }
  };
});

const JWT_SECRET = 'security-hardening-test-secret';

function makeDb({ users = [] } = {}) {
  return {
    all: jest.fn((sql, params, cb) => cb(null, [{ key: 'JWT_SECRET', value: JWT_SECRET }])),
    get: jest.fn((sql, params, cb) => {
      const row = users.find(candidate => candidate.match(sql, params));
      cb(null, row ? row.row : null);
    }),
    run: jest.fn((sql, params, cb) => {
      if (typeof cb === 'function') cb.call({ lastID: 1, changes: 1 }, null);
      return Promise.resolve();
    })
  };
}

const wroteMfaSecret = db => db.run.mock.calls.some(([sql]) => sql.includes('SET mfa_secret'));

describe('POST /auth/setup-mfa', () => {
  const authRouter = require('../routes/auth');

  function appFor(db) {
    const app = express();
    app.use(express.json());
    app.use((req, res, next) => { req.db = db; next(); });
    app.use('/auth', authRouter);
    return app;
  }

  const tempToken = jwt.sign({ id: 1, tenant_id: 1, mfaPending: true }, JWT_SECRET);

  it('refuses to replace an enrolled MFA secret with only the post-password token', async () => {
    const db = makeDb({ users: [{ match: () => true, row: { id: 1, tenant_id: 1, username: 'u', mfa_enabled: 1, mfa_secret: 'EXISTING' } }] });
    await request(appFor(db)).post('/auth/setup-mfa').send({ tempToken }).expect(409);
    expect(wroteMfaSecret(db)).toBe(false);
  });

  it('still allows first-time enrollment', async () => {
    const db = makeDb({ users: [{ match: () => true, row: { id: 1, tenant_id: 1, username: 'u', mfa_enabled: 0, mfa_secret: null } }] });
    const res = await request(appFor(db)).post('/auth/setup-mfa').send({ tempToken }).expect(200);
    expect(res.body.secret).toBeTruthy();
    expect(wroteMfaSecret(db)).toBe(true);
  });
});

describe('POST /api/users/:id/mfa/setup step-up', () => {
  const passwordHash = bcrypt.hashSync('right-password', 4);

  function appFor(caller) {
    const db = makeDb({
      users: [
        { match: sql => sql.includes('password_hash'), row: caller },
        { match: () => true, row: { id: 1, username: 'u' } }
      ]
    });
    const app = express();
    app.use(express.json());
    app.use((req, res, next) => {
      req.user = { id: 1, roles: ['viewer'] };
      req.tenant_id = 1;
      next();
    });
    app.use('/api/users', require('../routes/users')(db));
    return { app, db };
  }

  it('requires the current password', async () => {
    const { app, db } = appFor({ password_hash: passwordHash, mfa_enabled: 0, mfa_secret: null });
    await request(app).post('/api/users/1/mfa/setup').send({}).expect(401);
    await request(app).post('/api/users/1/mfa/setup').send({ password: 'wrong' }).expect(401);
    expect(wroteMfaSecret(db)).toBe(false);
  });

  it('requires a current TOTP code when MFA is enrolled', async () => {
    const secret = generateSecret();
    const { app, db } = appFor({ password_hash: passwordHash, mfa_enabled: 1, mfa_secret: secret });
    await request(app).post('/api/users/1/mfa/setup').send({ password: 'right-password' }).expect(401);
    expect(wroteMfaSecret(db)).toBe(false);

    await request(app)
      .post('/api/users/1/mfa/setup')
      .send({ password: 'right-password', code: generateSync({ secret }) })
      .expect(200);
    expect(wroteMfaSecret(db)).toBe(true);
  });
});

describe('auth middleware', () => {
  const auth = require('../middleware/auth');

  it('rejects HTTP Basic credentials even when they are valid', async () => {
    const db = makeDb({
      users: [{ match: () => true, row: { id: 1, tenant_id: 1, username: 'admin', role: 'Admin', roles: '["admin"]', password_hash: bcrypt.hashSync('pw', 4) } }]
    });
    const app = express();
    app.use((req, res, next) => { req.db = db; next(); });
    app.get('/x', auth, (req, res) => res.json({ ok: true }));

    await request(app).get('/x').set('Authorization', `Basic ${Buffer.from('admin:pw').toString('base64')}`).expect(401);
  });

  describe('socketAuth', () => {
    const run = async (db, token) => {
      const socket = { handshake: { auth: token === undefined ? {} : { token } }, join: jest.fn() };
      const next = jest.fn();
      await auth.socketAuth(db)(socket, next);
      return { socket, next };
    };
    const userDb = () => makeDb({ users: [{ match: () => true, row: { id: 3, tenant_id: 7 } }] });

    it('rejects a handshake without a token', async () => {
      const { next } = await run(userDb());
      expect(next).toHaveBeenCalledWith(expect.any(Error));
    });

    it('rejects an MFA-pending token', async () => {
      const { next } = await run(userDb(), jwt.sign({ id: 3, tenant_id: 7, mfaPending: true }, JWT_SECRET));
      expect(next).toHaveBeenCalledWith(expect.any(Error));
    });

    it('accepts a valid access token and joins the tenant room', async () => {
      const { next, socket } = await run(userDb(), jwt.sign({ id: 3, tenant_id: 7 }, JWT_SECRET));
      expect(next).toHaveBeenCalledWith();
      expect(socket.join).toHaveBeenCalledWith('tenant:7');
    });
  });
});

describe('rateLimit client key', () => {
  it('ignores spoofed X-Forwarded-For entries in front of the trusted proxy hop', async () => {
    const rateLimit = require('../middleware/rateLimit');
    const app = express();
    app.set('trust proxy', 1);
    app.get('/x', rateLimit({ windowMs: 60000, max: 1 }), (req, res) => res.send('ok'));

    await request(app).get('/x').set('X-Forwarded-For', '1.1.1.1, 203.0.113.50').expect(200);
    await request(app).get('/x').set('X-Forwarded-For', '2.2.2.2, 203.0.113.50').expect(429);
  });
});

describe('DNS impersonation scan', () => {
  it('caps scans per user', async () => {
    const app = express();
    app.use(express.json());
    app.use((req, res, next) => {
      req.user = { id: 'dns-test', roles: ['viewer'] };
      next();
    });
    app.use('/scan', require('../routes/dns_impersonation')(makeDb()));

    for (let i = 0; i < 5; i += 1) {
      await request(app).post('/scan/scan').send({ domain: 'example.com' }).expect(200);
    }
    await request(app).post('/scan/scan').send({ domain: 'example.com' }).expect(429);
  });
});

describe('OIDC token validation', () => {
  const jwksClient = require('jwks-rsa');
  const { validateToken } = require('../services/oauth');
  const issuer = 'https://idp.example.com/application/o/td';
  const settings = { OIDC_ISSUER_URL: issuer, OIDC_CLIENT_ID: 'threatdock-client' };
  const sign = claims => jwt.sign({ sub: 'user-1', ...claims }, mockKeys.privateKey, { algorithm: 'RS256', issuer, keyid: 'k1' });

  it('accepts a token issued for this client', async () => {
    await expect(validateToken(sign({ aud: 'threatdock-client' }), settings)).resolves.toEqual(expect.objectContaining({ sub: 'user-1' }));
  });

  it('rejects a token issued by the same IdP for a different audience', async () => {
    await expect(validateToken(sign({ aud: 'some-other-app' }), settings)).rejects.toThrow(/audience/);
  });

  it('rejects when no client id is configured to check the audience against', async () => {
    await expect(validateToken(sign({ aud: 'threatdock-client' }), { OIDC_ISSUER_URL: issuer })).rejects.toThrow('OIDC_CLIENT_ID');
  });

  it('joins the JWKS fallback path without depending on a trailing slash', () => {
    expect(jwksClient).toHaveBeenCalledWith(expect.objectContaining({ jwksUri: `${issuer}/jwks/` }));
  });
});

describe('outboundHttp guarded lookup', () => {
  it('returns every address when Node asks for all of them (autoSelectFamily)', done => {
    const dns = require('dns');
    dns.promises.lookup.mockResolvedValue([{ address: '140.82.112.6', family: 4 }]);
    const { httpsAgent } = require('../services/outboundHttp');
    httpsAgent.options.lookup('api.github.com', { all: true }, (err, addresses) => {
      try {
        expect(err).toBeNull();
        expect(addresses).toEqual([{ address: '140.82.112.6', family: 4 }]);
        done();
      } catch (assertion) {
        done(assertion);
      }
    });
  });
});
