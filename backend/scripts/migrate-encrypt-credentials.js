#!/usr/bin/env node
/**
 * migrate-encrypt-credentials.js
 *
 * Encrypts plaintext credentials in the settings table with AES-256-GCM and
 * re-encrypts values written with the legacy JWT_SECRET / built-in key derivation.
 * Run this after setting SETTINGS_ENCRYPTION_KEY.
 *
 * Usage:
 *   node scripts/migrate-encrypt-credentials.js
 *
 * Prerequisites:
 *   - DATABASE_URL or PGHOST/PGDATABASE/PGUSER/PGPASSWORD configured
 *   - SETTINGS_ENCRYPTION_KEY set (keep JWT_SECRET set too if older values used it)
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

      // Skip non-secret keys
      if (!settingsStore.isSecretKey(key)) {
        continue;
      }

      // Empty, or undecryptable with every known key: leave the stored value untouched
      const plaintext = settingsStore.decryptValue(value);
      if (!plaintext) {
        skipped += 1;
        continue;
      }

      // (Re-)encrypt with SETTINGS_ENCRYPTION_KEY and update
      const encrypted = settingsStore.prepareSettingValue(key, plaintext);
      await db.query(
        'UPDATE settings SET value = $1, updated_at = CURRENT_TIMESTAMP WHERE key = $2',
        [encrypted, key]
      );
      updated += 1;
      console.log(`[migrate-encrypt-credentials] Encrypted: ${key}`);
    }

    console.log(`[migrate-encrypt-credentials] Migration complete.`);
    console.log(`  - Updated: ${updated}`);
    console.log(`  - Skipped (empty or undecryptable): ${skipped}`);
    console.log(`  - Total settings: ${rows.length}`);
  } catch (err) {
    console.error('[migrate-encrypt-credentials] FAILED:', err.message);
    process.exit(1);
  } finally {
    await db.close();
  }
}

migrate();
