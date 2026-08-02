# Credentials Encryption

ThreatDock automatically encrypts sensitive settings (API keys, tokens, secrets, webhook URLs, and passwords) when stored in the database.

## How It Works

- **Automatic detection**: Keys matching `API_KEY`, `TOKEN`, `SECRET`, `WEBHOOK_URL`, or `PASSWORD` (case-insensitive) are encrypted before storage
- **Encryption algorithm**: AES-256-GCM with random IV per value
- **Storage format**: `enc:v1:<iv>:<auth_tag>:<ciphertext>` (all base64-encoded)
- **Transparent decryption**: Values are automatically decrypted when loaded from the database
- **Idempotent**: Already-encrypted values are never re-encrypted

## Configuration

### Encryption Key

Set `SETTINGS_ENCRYPTION_KEY` to a strong, random value (32+ characters):

```bash
# Generate a secure key
openssl rand -hex 32

# Set it in your environment
export SETTINGS_ENCRYPTION_KEY="your-generated-key-here"
```

If not set, ThreatDock falls back to `JWT_SECRET`, then to a built-in key (insecure for production).

**Production warning**: The application logs a security warning on startup if using the insecure fallback key in `NODE_ENV=production`.

### Example .env

```bash
# Required for production
SETTINGS_ENCRYPTION_KEY=a4f3c8e9d2b7f1a6e8c5d9b3a7f2e1c8d6b4a9f7e3c1d8b5a2f6e9c4d7b1a8f3

# Fallback (also used for JWT signing)
JWT_SECRET=your-jwt-secret-here
```

## Re-encrypting Existing Credentials

If you're enabling encryption on an existing installation with plaintext secrets in the database:

1. **Set the encryption key**:
   ```bash
   export SETTINGS_ENCRYPTION_KEY="$(openssl rand -hex 32)"
   ```

2. **Run the migration script**:
   ```bash
   node backend/scripts/migrate-encrypt-credentials.js
   ```

3. **Verify**:
   ```sql
   SELECT key, value FROM settings WHERE key LIKE '%API_KEY%' OR key LIKE '%TOKEN%';
   ```

   All secret values should now start with `enc:v1:`.

## Key Rotation

To rotate the encryption key:

1. **Export all settings** with the old key:
   ```bash
   # Using the old key
   node -e "
   const db = require('./services/database').createDatabase();
   const store = require('./services/settingsStore');
   db.connect().then(async () => {
     const settings = await store.getSettings(db);
     console.log(JSON.stringify(settings, null, 2));
     process.exit(0);
   });
   " > settings-backup.json
   ```

2. **Set the new key**:
   ```bash
   export SETTINGS_ENCRYPTION_KEY="$(openssl rand -hex 32)"
   ```

3. **Clear and re-import**:
   ```bash
   # This requires a custom import script or manual UPDATE via the API
   # For now, update via the UI or API after setting the new key
   ```

**Important**: Store the encryption key securely (e.g., AWS Secrets Manager, HashiCorp Vault). If lost, encrypted credentials cannot be recovered.

## Security Properties

- **Authentication**: GCM mode provides built-in authentication. Tampered ciphertexts are rejected.
- **Randomness**: Each encryption uses a fresh 96-bit IV; identical plaintext produces different ciphertexts.
- **Fail-safe**: Corrupted/tampered values decrypt to empty string rather than crashing.
- **Key derivation**: The encryption key is derived via SHA-256 hash of the configured secret.

## Testing

Run the encryption test suite:

```bash
cd backend
npm test -- __tests__/settingsStore.test.js
```

21 tests cover:
- Secret key detection
- Encrypt/decrypt round-trips
- Key fallback hierarchy
- Tamper detection
- Edge cases (null, empty, re-encryption)

## Audit Trail

Setting changes are logged in `audit_logs` with:
- **before/after values masked**: Secret values show as `[redacted]`
- **actor**: User who made the change
- **timestamp**: When the change occurred

Example:
```json
{
  "event_name": "settings_updated",
  "metadata": {
    "before": { "OTX_API_KEY": "[redacted]" },
    "after": { "OTX_API_KEY": "[redacted]" }
  }
}
```

## Excluded Keys

`JWT_SECRET` is **not** encrypted because:
1. It's used to derive the encryption key when `SETTINGS_ENCRYPTION_KEY` is unset
2. Encrypting it with itself would be circular

Store `JWT_SECRET` via environment variable rather than in the database.
