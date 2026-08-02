#!/usr/bin/env node
/**
 * migrate-encrypt-credentials.js
 *
 * Re-encrypts plaintext credentials in the settings table with AES-256-GCM.
 * Run this after setting SETTINGS_ENCRYPTION_KEY if you have existing plaintext secrets.
 *
 * Usage:
 *   node scripts/migrate-encrypt-credentials.js
 *
 * Prerequisites:
 *   - DATABASE_URL or PGHOST/PGDATABASE/PGUSER/PGPASSWORD configured
 *   - SETTINGS_ENCRYPTION_KEY set (or JWT_SECRET as fallback)
 */

const { createDatabase } = require('../services/database');
const settingsStore = require('../services/settingsStore');

async function migrate() {
  console.log('[migrate-encrypt-credentials] Starting credential re-encryption...');

  const db = createDatabase();
  let updated = 0;
  let skipped = 0;

  try {
    const result = await db.query('SELECT key, value FROM settings');
    const rows = result.rows || [];

    console.log(`[migrate-encrypt-credentials] Found ${rows.length} settings.`);

    for (const row of rows) {
      const { key, value } = row;

      // Skip if already encrypted
      if (String(value || '').startsWith('enc:v1:')) {
        skipped += 1;
        continue;
      }

      // Skip non-secret keys
      if (!settingsStore.isSecretKey(key)) {
        continue;
      }

      // Re-encrypt and update
      const encrypted = settingsStore.prepareSettingValue(key, value);
      await db.query(
        'UPDATE settings SET value = $1, updated_at = CURRENT_TIMESTAMP WHERE key = $2',
        [encrypted, key]
      );
      updated += 1;
      console.log(`[migrate-encrypt-credentials] Encrypted: ${key}`);
    }

    console.log(`[migrate-encrypt-credentials] Migration complete.`);
    console.log(`  - Updated: ${updated}`);
    console.log(`  - Skipped (already encrypted): ${skipped}`);
    console.log(`  - Total settings: ${rows.length}`);
  } catch (err) {
    console.error('[migrate-encrypt-credentials] FAILED:', err.message);
    process.exit(1);
  } finally {
    await db.close();
  }
}

migrate();
