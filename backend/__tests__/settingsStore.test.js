const crypto = require('crypto');

describe('settingsStore encryption', () => {
  const ORIGINAL_ENV = { ...process.env };

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV };
    process.env.SETTINGS_ENCRYPTION_KEY = 'test-encryption-key-for-jest-only';
  });

  afterAll(() => {
    process.env = { ...ORIGINAL_ENV };
  });

  describe('isSecretKey', () => {
    it('flags keys with API_KEY, TOKEN, SECRET, WEBHOOK_URL, PASSWORD substrings', () => {
      const { isSecretKey } = require('../services/settingsStore');
      expect(isSecretKey('OTX_API_KEY')).toBe(true);
      expect(isSecretKey('GITHUB_TOKEN')).toBe(true);
      expect(isSecretKey('OIDC_CLIENT_SECRET')).toBe(true);
      expect(isSecretKey('SLACK_WEBHOOK_URL')).toBe(true);
      expect(isSecretKey('AUTH_PASSWORD')).toBe(true);
    });

    it('exempts JWT_SECRET because it seeds the encryption key', () => {
      const { isSecretKey } = require('../services/settingsStore');
      expect(isSecretKey('JWT_SECRET')).toBe(false);
    });

    it('leaves non-secret keys untouched', () => {
      const { isSecretKey } = require('../services/settingsStore');
      expect(isSecretKey('FRONTEND_URL')).toBe(false);
      expect(isSecretKey('NOTIFY_THRESHOLD')).toBe(false);
      expect(isSecretKey('RISK_WEIGHTS')).toBe(false);
      expect(isSecretKey('MONITORED_BRANDS')).toBe(false);
    });
  });

  describe('encryptValue / decryptValue round-trip', () => {
    it('encrypts secret values with the enc:v1: prefix', () => {
      const store = require('../services/settingsStore');
      const encrypted = store.prepareSettingValue('OTX_API_KEY', 'super-secret-token');
      expect(encrypted.startsWith('enc:v1:')).toBe(true);
      expect(encrypted).not.toContain('super-secret-token');
    });

    it('decrypts an encrypted secret back to plaintext', () => {
      const store = require('../services/settingsStore');
      const encrypted = store.prepareSettingValue('GITHUB_TOKEN', 'ghp_abcdefghijklmnop');
      expect(store.decryptValue(encrypted)).toBe('ghp_abcdefghijklmnop');
    });

    it('leaves non-secret keys as plaintext', () => {
      const store = require('../services/settingsStore');
      const output = store.prepareSettingValue('FRONTEND_URL', 'https://example.com');
      expect(output).toBe('https://example.com');
    });

    it('never re-encrypts an already encrypted value', () => {
      const store = require('../services/settingsStore');
      const once = store.prepareSettingValue('OTX_API_KEY', 'a-secret');
      const twice = store.prepareSettingValue('OTX_API_KEY', once);
      expect(twice).toBe(once);
    });

    it('returns empty string when decrypting a corrupted ciphertext', () => {
      const store = require('../services/settingsStore');
      const tampered = 'enc:v1:AAAA:BBBB:CCCC';
      expect(store.decryptValue(tampered)).toBe('');
    });

    it('leaves plaintext values untouched when decrypting', () => {
      const store = require('../services/settingsStore');
      expect(store.decryptValue('plain-value')).toBe('plain-value');
    });

    it('handles null and undefined values without throwing', () => {
      const store = require('../services/settingsStore');
      expect(store.prepareSettingValue('OTX_API_KEY', null)).toBe('');
      expect(store.prepareSettingValue('OTX_API_KEY', undefined)).toBe('');
      expect(store.decryptValue(null)).toBe('');
      expect(store.decryptValue(undefined)).toBe('');
    });

    it('produces different ciphertexts for identical plaintext (random IV)', () => {
      const store = require('../services/settingsStore');
      const a = store.prepareSettingValue('OTX_API_KEY', 'same-value');
      const b = store.prepareSettingValue('OTX_API_KEY', 'same-value');
      expect(a).not.toBe(b);
      expect(store.decryptValue(a)).toBe(store.decryptValue(b));
    });
  });

  describe('key derivation', () => {
    it('uses SETTINGS_ENCRYPTION_KEY when set', () => {
      process.env.SETTINGS_ENCRYPTION_KEY = 'primary-key';
      delete process.env.JWT_SECRET;
      const store = require('../services/settingsStore');
      const encrypted = store.prepareSettingValue('OTX_API_KEY', 'value');
      expect(store.decryptValue(encrypted)).toBe('value');
    });

    it('falls back to JWT_SECRET when SETTINGS_ENCRYPTION_KEY is missing', () => {
      delete process.env.SETTINGS_ENCRYPTION_KEY;
      process.env.JWT_SECRET = 'jwt-fallback-key';
      const store = require('../services/settingsStore');
      const encrypted = store.prepareSettingValue('OTX_API_KEY', 'value');
      expect(store.decryptValue(encrypted)).toBe('value');
    });

    it('fails to decrypt when the key has changed', () => {
      process.env.SETTINGS_ENCRYPTION_KEY = 'key-a';
      const storeA = require('../services/settingsStore');
      const ciphertext = storeA.prepareSettingValue('OTX_API_KEY', 'sensitive');

      jest.resetModules();
      process.env.SETTINGS_ENCRYPTION_KEY = 'key-b';
      const storeB = require('../services/settingsStore');
      expect(storeB.decryptValue(ciphertext)).toBe('');
    });
  });

  describe('getSettings', () => {
    it('decrypts secret values loaded from the database', async () => {
      const store = require('../services/settingsStore');
      const ciphertext = store.prepareSettingValue('OTX_API_KEY', 'live-secret');
      const rows = [
        { key: 'OTX_API_KEY', value: ciphertext },
        { key: 'FRONTEND_URL', value: 'https://example.com' }
      ];
      const db = {
        all: (sql, params, callback) => callback(null, rows)
      };
      const settings = await store.getSettings(db);
      expect(settings.OTX_API_KEY).toBe('live-secret');
      expect(settings.FRONTEND_URL).toBe('https://example.com');
    });

    it('rejects when the database query fails', async () => {
      const store = require('../services/settingsStore');
      const db = {
        all: (sql, params, callback) => callback(new Error('boom'))
      };
      await expect(store.getSettings(db)).rejects.toThrow('boom');
    });
  });

  describe('maskSecrets', () => {
    it('redacts values for secret keys', () => {
      const store = require('../services/settingsStore');
      const masked = store.maskSecrets({
        OTX_API_KEY: 'sensitive',
        FRONTEND_URL: 'https://example.com'
      });
      expect(masked.OTX_API_KEY).toBe('[redacted]');
      expect(masked.FRONTEND_URL).toBe('https://example.com');
    });

    it('does not redact empty secret values (nothing to leak)', () => {
      const store = require('../services/settingsStore');
      expect(store.maskSecrets({ OTX_API_KEY: '' })).toEqual({ OTX_API_KEY: '' });
    });

    it('handles null or undefined input safely', () => {
      const store = require('../services/settingsStore');
      expect(store.maskSecrets(null)).toEqual({});
      expect(store.maskSecrets(undefined)).toEqual({});
    });
  });

  describe('AES-256-GCM authentication', () => {
    it('rejects ciphertexts with a tampered authentication tag', () => {
      const store = require('../services/settingsStore');
      const original = store.prepareSettingValue('OTX_API_KEY', 'value');
      const parts = original.slice('enc:v1:'.length).split(':');
      const tamperedTag = Buffer.from(parts[1], 'base64');
      tamperedTag[0] = tamperedTag[0] ^ 0xff;
      const tampered = `enc:v1:${parts[0]}:${tamperedTag.toString('base64')}:${parts[2]}`;
      expect(store.decryptValue(tampered)).toBe('');
    });

    it('rejects ciphertexts with a tampered payload', () => {
      const store = require('../services/settingsStore');
      const original = store.prepareSettingValue('OTX_API_KEY', 'value');
      const parts = original.slice('enc:v1:'.length).split(':');
      const tamperedData = Buffer.from(parts[2], 'base64');
      tamperedData[0] = tamperedData[0] ^ 0xff;
      const tampered = `enc:v1:${parts[0]}:${parts[1]}:${tamperedData.toString('base64')}`;
      expect(store.decryptValue(tampered)).toBe('');
    });
  });
});
