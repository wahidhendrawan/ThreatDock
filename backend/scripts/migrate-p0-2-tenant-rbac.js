#!/usr/bin/env node
/**
 * Migration script for P0-2 tenant and RBAC baseline.
 * 
 * Idempotent schema updates:
 * - Create tenants table
 * - Add tenant_id, roles, auth_provider, oidc_issuer, oidc_subject to users
 * - Create audit_logs table
 * - Add tenant_id to alert-like tables (alerts, assets, hunt_queries, vendors, osint_findings)
 * - Create indexes for multi-tenant queries and OIDC lookups
 * - Seed default tenant and admin user
 */

const path = require('path');

// Try to load from the app context if available, otherwise require directly
let db;
try {
  // If run from within the app, use the initialized db
  const app = require(path.join(__dirname, '..', 'app'));
  db = app.db || require(path.join(__dirname, '..', 'services', 'database')).getDatabase();
} catch (e) {
  // Otherwise, create a fresh connection
  const database = require(path.join(__dirname, '..', 'services', 'database'));
  db = database.createDatabase(
    process.env.DATABASE_URL || 'postgresql://localhost/threatdock'
  );
}

const bcrypt = require('bcryptjs');

const STATEMENTS = [
  // Tenants table
  `CREATE TABLE IF NOT EXISTS tenants (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
  )`,

  // Add columns to users table
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS roles TEXT DEFAULT '["viewer"]'`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider TEXT DEFAULT 'local'`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_issuer TEXT`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_subject TEXT`,

  // Audit logs table
  `CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    actor_sub TEXT,
    actor_email TEXT,
    event_name TEXT NOT NULL,
    status TEXT NOT NULL,
    metadata TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
  )`,

  // Add tenant_id to tenant-owned tables
  `ALTER TABLE alerts ADD COLUMN IF NOT EXISTS tenant_id INTEGER`,
  `ALTER TABLE assets ADD COLUMN IF NOT EXISTS tenant_id INTEGER`,
  `ALTER TABLE hunt_queries ADD COLUMN IF NOT EXISTS tenant_id INTEGER`,
  `ALTER TABLE vendors ADD COLUMN IF NOT EXISTS tenant_id INTEGER`,
  `ALTER TABLE osint_findings ADD COLUMN IF NOT EXISTS tenant_id INTEGER`,

  // Indexes for multi-tenant queries
  `CREATE INDEX IF NOT EXISTS idx_alerts_tenant_id ON alerts(tenant_id)`,
  `CREATE INDEX IF NOT EXISTS idx_assets_tenant_id ON assets(tenant_id)`,
  `CREATE INDEX IF NOT EXISTS idx_hunt_queries_tenant_id ON hunt_queries(tenant_id)`,
  `CREATE INDEX IF NOT EXISTS idx_vendors_tenant_id ON vendors(tenant_id)`,
  `CREATE INDEX IF NOT EXISTS idx_osint_findings_tenant_id ON osint_findings(tenant_id)`,
  `CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_id ON audit_logs(tenant_id)`,

  // Index for OIDC lookups
  `CREATE UNIQUE INDEX IF NOT EXISTS unique_users_oidc ON users(tenant_id, oidc_issuer, oidc_subject) WHERE oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL`,

  // Seed default tenant
  `INSERT INTO tenants (name, slug) VALUES ('Default', 'default') ON CONFLICT (slug) DO NOTHING`,
];

async function run() {
  try {
    console.log('Starting P0-2 tenant and RBAC migration...');

    // Execute all DDL statements
    for (const stmt of STATEMENTS) {
      console.log(`  Executing: ${stmt.substring(0, 60)}...`);
      await new Promise((resolve, reject) => {
        db.run(stmt, (err) => {
          if (err) return reject(err);
          resolve();
        });
      });
    }

    // Get or create the default tenant
    const defaultTenant = await new Promise((resolve, reject) => {
      db.get("SELECT id FROM tenants WHERE slug = 'default'", (err, row) => {
        if (err) return reject(err);
        if (!row) return reject(new Error('Default tenant was not created'));
        resolve(row);
      });
    });

    console.log(`  Default tenant ID: ${defaultTenant.id}`);

    // Seed default admin user if it doesn't exist
    const adminUsername = process.env.AUTH_USER || 'admin';
    const adminPassword = process.env.AUTH_PASSWORD || 'admin';

    const existingAdmin = await new Promise((resolve, reject) => {
      db.get(
        'SELECT id FROM users WHERE tenant_id = ? AND username = ?',
        [defaultTenant.id, adminUsername],
        (err, row) => {
          if (err) return reject(err);
          resolve(row);
        }
      );
    });

    if (!existingAdmin) {
      console.log(`  Creating default admin user: ${adminUsername}`);
      const passwordHash = bcrypt.hashSync(adminPassword, 10);
      await new Promise((resolve, reject) => {
        db.run(
          `INSERT INTO users (tenant_id, username, password_hash, role, roles, auth_provider)
           VALUES (?, ?, ?, 'Admin', ?, 'local')`,
          [defaultTenant.id, adminUsername, passwordHash, JSON.stringify(['admin'])],
          (err) => {
            if (err) return reject(err);
            resolve();
          }
        );
      });
      console.log(`  Admin user created successfully`);
    } else {
      console.log(`  Admin user already exists`);
    }

    // Backfill tenant_id for existing tenant-owned records to the default tenant
    const tenantTables = ['alerts', 'assets', 'hunt_queries', 'vendors', 'osint_findings'];
    for (const table of tenantTables) {
      await new Promise((resolve, reject) => {
        db.run(
          `UPDATE ${table} SET tenant_id = ? WHERE tenant_id IS NULL`,
          [defaultTenant.id],
          (err) => {
            if (err) return reject(err);
            console.log(`  Backfilled ${table} with default tenant_id`);
            resolve();
          }
        );
      });
    }

    // Backfill tenant_id for existing users to the default tenant (if not already set)
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE users SET tenant_id = ? WHERE tenant_id IS NULL',
        [defaultTenant.id],
        (err) => {
          if (err) return reject(err);
          console.log('  Backfilled users with default tenant_id');
          resolve();
        }
      );
    });

    console.log('\n✓ P0-2 tenant and RBAC migration completed successfully');
    process.exit(0);
  } catch (err) {
    console.error('\n✗ Migration failed:', err.message);
    process.exit(1);
  }
}

run();
