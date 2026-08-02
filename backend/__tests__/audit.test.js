
const { sanitize, auditLog, extractActor } = require('../services/audit');

describe('Audit Service', () => {
  describe('sanitize', () => {
    it('should redact sensitive keys', () => {
      const dirty = {
        username: 'test',
        password: 'password123',
        token: 'abcdef123456',
        data: {
          session_cookie: 'sess-abc',
          api_key: 'key_123',
          nothing: 'visible'
        }
      };
      const clean = sanitize(dirty);
      expect(clean.password).toBe('[REDACTED]');
      expect(clean.token).toBe('[REDACTED]');
      expect(clean.data.session_cookie).toBe('[REDACTED]');
      expect(clean.data.api_key).toBe('[REDACTED]');
      expect(clean.data.nothing).toBe('visible');
    });

    it('should handle nested objects and arrays', () => {
      const dirty = {
        level1: {
          secret: 'l1-secret',
          level2: [{
            auth_token: 'l2-token'
          }]
        }
      };
      const clean = sanitize(dirty);
      expect(clean.level1.secret).toBe('[REDACTED]');
      expect(clean.level1.level2[0].auth_token).toBe('[REDACTED]');
    });

    it('should not modify non-sensitive objects', () => {
      const obj = { user: 'test', action: 'login' };
      expect(sanitize(obj)).toEqual(obj);
    });

    it('should redact api-key variants', () => {
      const dirty = { 'api-key': 'k1', 'api_key': 'k2', apiKey: 'k3' };
      const clean = sanitize(dirty);
      expect(clean['api-key']).toBe('[REDACTED]');
      expect(clean['api_key']).toBe('[REDACTED]');
      expect(clean.apiKey).toBe('[REDACTED]');
    });

    it('should redact authorization headers', () => {
      const dirty = { Authorization: 'Bearer xyz', cookie: 'session=abc' };
      const clean = sanitize(dirty);
      expect(clean.Authorization).toBe('[REDACTED]');
      expect(clean.cookie).toBe('[REDACTED]');
    });

    it('should handle primitives without error', () => {
      expect(sanitize(null)).toBeNull();
      expect(sanitize(undefined)).toBeUndefined();
      expect(sanitize(42)).toBe(42);
      expect(sanitize('hello')).toBe('hello');
    });
  });

  describe('extractActor', () => {
    it('should extract identity from a standard user object', () => {
      const user = { id: 1, email: 'test@test.com', username: 'test' };
      expect(extractActor(user)).toEqual({
        sub: 1,
        email: 'test@test.com',
        name: 'test'
      });
    });

    it('should prefer OIDC subject when present', () => {
      const user = { id: 1, email: 'test@test.com', oidc_subject: 'oidc-sub', oidc_issuer: 'issuer' };
      expect(extractActor(user)).toEqual({
        sub: 'oidc-sub',
        email: 'test@test.com',
        name: null
      });
    });

    it('should return anonymous for null actor', () => {
      expect(extractActor(null)).toEqual({ sub: 'anonymous', email: null, name: null });
    });
  });

  describe('auditLog', () => {
    let mockDb;

    beforeEach(() => {
      mockDb = {
        run: jest.fn().mockResolvedValue(undefined),
      };
    });

    it('should call db.run with correct parameters', async () => {
      const actor = { id: 1, tenant_id: 1, email: 'test@test.com' };
      await auditLog(mockDb, {
        tenant_id: 1,
        actor: actor,
        event_name: 'login',
        status: 'success',
        metadata: { ip: '127.0.0.1' }
      });
      expect(mockDb.run).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO audit_logs'),
        [1, 1, 'test@test.com', 'login', 'success', '{"ip":"127.0.0.1"}']
      );
    });

    it('should sanitize metadata before logging', async () => {
      const actor = { id: 1, tenant_id: 1, email: 'test@test.com' };
      await auditLog(mockDb, {
        tenant_id: 1,
        actor: actor,
        event_name: 'user_update',
        status: 'success',
        metadata: { password: 'new_password', username: 'test' }
      });
      expect(mockDb.run).toHaveBeenCalledWith(
        expect.anything(),
        expect.arrayContaining(['{"password":"[REDACTED]","username":"test"}'])
      );
    });

    it('should skip when required params are missing', async () => {
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      await auditLog(mockDb, { event_name: 'test', status: 'success' });
      expect(mockDb.run).not.toHaveBeenCalled();
      consoleErrorSpy.mockRestore();
    });

    it('should catch and log db errors without throwing', async () => {
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      mockDb.run = jest.fn().mockRejectedValue(new Error('db failure'));
      await expect(auditLog(mockDb, {
        tenant_id: 1,
        actor: { id: 1 },
        event_name: 'login',
        status: 'success'
      })).resolves.toBeUndefined();
      expect(consoleErrorSpy).toHaveBeenCalled();
      consoleErrorSpy.mockRestore();
    });
  });
});
