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

`SETTINGS_ENCRYPTION_KEY` is required: without it the backend refuses to encrypt secrets (and therefore to start). There is no built-in fallback key.

**Upgrading**: older releases derived the key from `JWT_SECRET` or a built-in constant. Those derivations are still tried when decrypting, so existing values stay readable (keep `JWT_SECRET` set if you used it). Any value written afterwards is encrypted with `SETTINGS_ENCRYPTION_KEY`; run the migration script below to re-encrypt everything at once.

### Example .env

```bash
# Required: generate your own with `openssl rand -hex 32`, never reuse an example value
SETTINGS_ENCRYPTION_KEY=<64 hex characters>

# Token signing only (legacy decryption fallback for values written by older releases)
JWT_SECRET=your-jwt-secret-here
```

## Re-encrypting Existing Credentials

If you're upgrading an installation with plaintext secrets, or secrets encrypted with the legacy `JWT_SECRET`/built-in key:

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

   All secret values (including `JWT_SECRET`) should now start with `enc:v1:`.

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
- Legacy key fallback for decryption
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

## JWT_SECRET

`JWT_SECRET` (the token-signing key stored in the settings table) is treated like any other secret: it is encrypted at rest and returned as `[redacted]` by `GET /api/settings`.
