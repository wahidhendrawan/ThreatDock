/**
 * Integration tests for settings API — verify secrets never leak and redaction works.
 * Uses Supertest to test HTTP layer end-to-end.
 */
const request = require('supertest');
const express = require('express');
const settingsStore = require('../services/settingsStore');

// Mock database that mimics sqlite3-style callback API used by services/db.js
function createMockDb(initialRows = []) {
  const store = new Map(initialRows.map(r => [r.key, r.value]));
  const auditLogs = [];

  const db = {
    _store: store,
    _auditLogs: auditLogs,
    all: (sql, params, callback) => {
      setImmediate(() => {
        if (sql.includes('FROM settings')) {
          const rows = Array.from(store.entries()).map(([key, value]) => ({ key, value }));
          return callback(null, rows);
        }
        callback(null, []);
      });
    },
    get: (sql, params, callback) => {
      setImmediate(() => callback(null, null));
    },
    run: (sql, params, callback) => {
      // Track audit logs when db.run is called for audit_logs table
      if (sql && sql.includes && sql.includes('audit_logs')) {
        auditLogs.push(params);
      }
      // Support both callback-style (sqlite3) and promise-style (services/database.js) callers
      if (typeof callback === 'function') {
        return setImmediate(() => callback.call({ lastID: 1, changes: 1 }, null));
      }
      return Promise.resolve({ lastID: 1, changes: 1 });
    },
    prepare: (sql, callback) => {
      const stmt = {
        run: (params, cb) => {
          if (sql.includes('INTO settings')) {
            const [key, value] = params;
            store.set(key, value);
          }
          setImmediate(() => cb.call({ lastID: 1, changes: 1 }, null));
        },
        finalize: (cb) => setImmediate(() => cb(null))
      };
      setImmediate(() => callback && callback(null));
      return stmt;
    },
    transaction: async (work) => {
      // Provide same db to the work callback — no real transactional isolation needed for tests
      return work(db);
    }
  };

  return db;
}

function buildApp(mockDb) {
  const app = express();
  app.use(express.json());

  // Mock identity middleware — attach admin user so requireRole passes
  app.use((req, res, next) => {
    req.tenant_id = 'test-tenant';
    req.user = {
      name: 'Test Admin',
      email: 'admin@example.com',
      roles: ['admin']
    };
    next();
  });

  const settingsRouter = require('../routes/settings')(mockDb);
  app.use('/api/settings', settingsRouter);
  return app;
}

describe('Settings API — Secret Redaction', () => {
  describe('GET /api/settings', () => {
    test('does not leak plaintext secrets — returns [redacted]', async () => {
      const encryptedApiKey = settingsStore.prepareSettingValue('SLACK_API_KEY', 'xoxb-secret-token-12345');
      const mockDb = createMockDb([
        { key: 'SLACK_API_KEY', value: encryptedApiKey },
        { key: 'PUBLIC_CONFIG', value: 'public-value' }
      ]);
      const app = buildApp(mockDb);

      const res = await request(app).get('/api/settings').expect(200);

      expect(res.body.SLACK_API_KEY).toBe('[redacted]');
      expect(res.body.PUBLIC_CONFIG).toBe('public-value');
      // Belt-and-suspenders: raw plaintext must not appear anywhere in the response
      expect(JSON.stringify(res.body)).not.toContain('xoxb-secret-token');
    });

    test('masks every secret-like key regardless of encryption state', async () => {
      const mockDb = createMockDb([
        { key: 'DATABASE_PASSWORD', value: settingsStore.prepareSettingValue('DATABASE_PASSWORD', 'pass123') },
        { key: 'VIRUSTOTAL_API_KEY', value: settingsStore.prepareSettingValue('VIRUSTOTAL_API_KEY', 'vt-abc') },
        { key: 'DISCORD_WEBHOOK_URL', value: settingsStore.prepareSettingValue('DISCORD_WEBHOOK_URL', 'https://discord.com/hook/xyz') },
        { key: 'THEME', value: 'dark' }
      ]);
      const app = buildApp(mockDb);

      const res = await request(app).get('/api/settings').expect(200);

      expect(res.body.DATABASE_PASSWORD).toBe('[redacted]');
      expect(res.body.VIRUSTOTAL_API_KEY).toBe('[redacted]');
      expect(res.body.DISCORD_WEBHOOK_URL).toBe('[redacted]');
      expect(res.body.THEME).toBe('dark');
    });

    test('never exposes encrypted ciphertext to the client', async () => {
      const mockDb = createMockDb([
        { key: 'API_TOKEN', value: settingsStore.prepareSettingValue('API_TOKEN', 'real-token-abc') }
      ]);
      const app = buildApp(mockDb);

      const res = await request(app).get('/api/settings').expect(200);

      // Should not contain the encryption prefix — that would leak internal storage format
      expect(JSON.stringify(res.body)).not.toContain('enc:v1:');
    });
  });

  describe('PUT /api/settings', () => {
    test('preserves existing secret when frontend sends [redacted]', async () => {
      const originalCiphertext = settingsStore.prepareSettingValue('SLACK_API_KEY', 'original-secret');
      const mockDb = createMockDb([
        { key: 'SLACK_API_KEY', value: originalCiphertext }
      ]);
      const app = buildApp(mockDb);

      await request(app)
        .put('/api/settings')
        .send({ SLACK_API_KEY: '[redacted]' })
        .expect(200);

      // Original ciphertext must remain untouched
      expect(mockDb._store.get('SLACK_API_KEY')).toBe(originalCiphertext);
      // Verify it still decrypts to the original secret
      expect(settingsStore.decryptValue(mockDb._store.get('SLACK_API_KEY'))).toBe('original-secret');
    });

    test('updates secret when frontend sends a new value', async () => {
      const originalCiphertext = settingsStore.prepareSettingValue('SLACK_API_KEY', 'original-secret');
      const mockDb = createMockDb([
        { key: 'SLACK_API_KEY', value: originalCiphertext }
      ]);
      const app = buildApp(mockDb);

      await request(app)
        .put('/api/settings')
        .send({ SLACK_API_KEY: 'new-rotated-secret' })
        .expect(200);

      const stored = mockDb._store.get('SLACK_API_KEY');
      expect(stored).not.toBe(originalCiphertext);
      // Should be freshly encrypted
      expect(stored.startsWith('enc:v1:')).toBe(true);
      expect(settingsStore.decryptValue(stored)).toBe('new-rotated-secret');
    });

    test('updates non-secret settings normally', async () => {
      const mockDb = createMockDb([
        { key: 'THEME', value: 'light' }
      ]);
      const app = buildApp(mockDb);

      await request(app)
        .put('/api/settings')
        .send({ THEME: 'dark' })
        .expect(200);

      expect(mockDb._store.get('THEME')).toBe('dark');
    });

    test('mixed update: [redacted] preserved, new values applied', async () => {
      const originalCiphertext = settingsStore.prepareSettingValue('API_TOKEN', 'keep-me');
      const mockDb = createMockDb([
        { key: 'API_TOKEN', value: originalCiphertext },
        { key: 'THEME', value: 'light' }
      ]);
      const app = buildApp(mockDb);

      await request(app)
        .put('/api/settings')
        .send({
          API_TOKEN: '[redacted]',
          THEME: 'dark',
          NEW_SETTING: 'hello'
        })
        .expect(200);

      // Secret preserved
      expect(mockDb._store.get('API_TOKEN')).toBe(originalCiphertext);
      expect(settingsStore.decryptValue(mockDb._store.get('API_TOKEN'))).toBe('keep-me');
      // Other fields updated
      expect(mockDb._store.get('THEME')).toBe('dark');
      expect(mockDb._store.get('NEW_SETTING')).toBe('hello');
    });

    test('rejects non-object body', async () => {
      const mockDb = createMockDb();
      const app = buildApp(mockDb);

      await request(app)
        .put('/api/settings')
        .send([{ key: 'value' }])
        .expect(400);
    });
  });
});
