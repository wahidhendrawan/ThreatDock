const crypto = require('crypto');

const ENCRYPTED_PREFIX = 'enc:v1:';
// Decrypt-only: older releases encrypted with this public constant or with JWT_SECRET.
const LEGACY_FALLBACK_KEY = 'threatdock-local-settings-key-change-in-production';

function isSecretKey(key) {
  return /API_KEY|TOKEN|SECRET|WEBHOOK_URL|PASSWORD/i.test(key);
}

function deriveKey(material) {
  return crypto.createHash('sha256').update(material).digest();
}

function encryptionKey() {
  if (!process.env.SETTINGS_ENCRYPTION_KEY) {
    throw new Error(
      'SETTINGS_ENCRYPTION_KEY is not set. Generate one with `openssl rand -hex 32` ' +
      'and set it in the backend environment before storing secret settings.'
    );
  }
  return deriveKey(process.env.SETTINGS_ENCRYPTION_KEY);
}

// Current key first, then the legacy derivations so existing ciphertext stays readable
// until it is re-encrypted on the next write.
function decryptionKeys() {
  return [process.env.SETTINGS_ENCRYPTION_KEY, process.env.JWT_SECRET, LEGACY_FALLBACK_KEY]
    .filter(Boolean)
    .map(deriveKey);
}

function encryptValue(key, value) {
  const text = String(value ?? '');
  if (!isSecretKey(key) || !text || text.startsWith(ENCRYPTED_PREFIX)) return text;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${ENCRYPTED_PREFIX}${iv.toString('base64')}:${tag.toString('base64')}:${encrypted.toString('base64')}`;
}

function decryptValue(value) {
  const text = String(value ?? '');
  if (!text.startsWith(ENCRYPTED_PREFIX)) return text;
  const [ivB64, tagB64, dataB64] = text.slice(ENCRYPTED_PREFIX.length).split(':');
  for (const key of decryptionKeys()) {
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
      decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
      return Buffer.concat([
        decipher.update(Buffer.from(dataB64, 'base64')),
        decipher.final()
      ]).toString('utf8');
    } catch {
      // Wrong key or tampered value: try the next candidate.
    }
  }
  return '';
}

function getSettings(db) {
  return new Promise((resolve, reject) => {
    db.all('SELECT key, value FROM settings', [], (err, rows) => {
      if (err) return reject(err);
      const settings = {};
      rows.forEach(row => {
        settings[row.key] = decryptValue(row.value);
      });
      resolve(settings);
    });
  });
}

function prepareSettingValue(key, value) {
  return encryptValue(key, value);
}

function maskSecrets(values) {
  const masked = {};
  Object.entries(values || {}).forEach(([key, value]) => {
    masked[key] = isSecretKey(key) && value ? '[redacted]' : value;
  });
  return masked;
}

module.exports = {
  decryptValue,
  getSettings,
  isSecretKey,
  maskSecrets,
  prepareSettingValue
};
