const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const settingsStore = require('./settingsStore');

const DEFAULT_SETTINGS = [
  ['OIDC_ISSUER_URL', process.env.OIDC_ISSUER_URL || ''],
  ['OIDC_CLIENT_ID', process.env.OIDC_CLIENT_ID || ''],
  ['OIDC_CLIENT_SECRET', process.env.OIDC_CLIENT_SECRET || ''],
  ['FRONTEND_URL', process.env.FRONTEND_URL || 'http://localhost:3000'],
  ['JWT_SECRET', process.env.JWT_SECRET || crypto.randomBytes(48).toString('hex')],
  ['SSO_ENABLED', process.env.OIDC_ISSUER_URL ? 'true' : 'false'],
  ['MFA_REQUIRED', 'false'],
  ['ANALYST_MFA_REQUIRED', 'false'],
  ['SECURITYTRAILS_API_KEY', process.env.SECURITYTRAILS_API_KEY || ''],
  ['BREACHDIRECTORY_RAPIDAPI_KEY', process.env.BREACHDIRECTORY_RAPIDAPI_KEY || ''],
  ['BREACHDIRECTORY_RAPIDAPI_HOST', process.env.BREACHDIRECTORY_RAPIDAPI_HOST || 'breachdirectory.p.rapidapi.com'],
  ['INTELX_API_KEY', process.env.INTELX_API_KEY || ''],
  ['OTX_API_KEY', process.env.OTX_API_KEY || ''],
  ['URLSCAN_API_KEY', process.env.URLSCAN_API_KEY || ''],
  ['VIRUSTOTAL_API_KEY', process.env.VIRUSTOTAL_API_KEY || ''],
  ['GITHUB_TOKEN', process.env.GITHUB_TOKEN || ''],
  ['NVD_API_KEY', process.env.NVD_API_KEY || ''],
  ['THREATFOX_AUTH_KEY', process.env.THREATFOX_AUTH_KEY || ''],
  ['MISP_URL', process.env.MISP_URL || ''],
  ['MISP_API_KEY', process.env.MISP_API_KEY || ''],
  ['INTELO_OWL_API_KEY', process.env.INTELO_OWL_API_KEY || ''],
  ['SLACK_WEBHOOK_URL', process.env.SLACK_WEBHOOK_URL || ''],
  ['N8N_WEBHOOK_URL', process.env.N8N_WEBHOOK_URL || ''],
  ['TELEGRAM_BOT_TOKEN', process.env.TELEGRAM_BOT_TOKEN || ''],
  ['TELEGRAM_CHAT_ID', process.env.TELEGRAM_CHAT_ID || ''],
  ['TEAMS_WEBHOOK_URL', process.env.TEAMS_WEBHOOK_URL || ''],
  ['NOTIFY_THRESHOLD', process.env.NOTIFY_THRESHOLD || 'High'],
  ['NOTIFICATION_RULES', process.env.NOTIFICATION_RULES || '[]'],
  ['RISK_WEIGHTS', process.env.RISK_WEIGHTS || JSON.stringify({
    cvssCritical: 30,
    cvssHigh: 22,
    epssHigh: 20,
    epssMedium: 10,
    kev: 30,
    exploitSignal: 15,
    exposedService: 10,
    assetCriticality: 15,
    vendorRiskDivisor: 5
  })],
  ['PUBLIC_DNS_SERVERS', process.env.PUBLIC_DNS_SERVERS || '1.1.1.1,8.8.8.8'],
  ['MONITORED_BRANDS', '[]']
];

const ID_TABLES = new Set([
  'alerts',
  'assets',
  'hunt_queries',
  'vendors',
  'osint_findings',
  'users',
  'alert_comments',
  'audit_logs',
  'ingestion_runs',
  'indicators',
  'correlated_findings'
]);

function normalizeError(err) {
  if (!err) return err;
  if (err.code === '23505' && !String(err.message || '').includes('UNIQUE')) {
    err.message = `${err.message} UNIQUE`;
  }
  return err;
}

function convertQuestionPlaceholders(sql) {
  let output = '';
  let index = 0;
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < sql.length; i += 1) {
    const char = sql[i];
    const next = sql[i + 1];

    if (char === "'" && !inDouble) {
      output += char;
      if (inSingle && next === "'") {
        output += next;
        i += 1;
      } else {
        inSingle = !inSingle;
      }
      continue;
    }

    if (char === '"' && !inSingle) {
      inDouble = !inDouble;
      output += char;
      continue;
    }

    if (char === '?' && !inSingle && !inDouble) {
      index += 1;
      output += `$${index}`;
      continue;
    }

    output += char;
  }

  return output;
}

function replaceIdentifiers(sql) {
  let output = '';
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < sql.length; i += 1) {
    const char = sql[i];
    const next = sql[i + 1];

    if (char === "'" && !inDouble) {
      output += char;
      if (inSingle && next === "'") {
        output += next;
        i += 1;
      } else {
        inSingle = !inSingle;
      }
      continue;
    }

    if (char === '"' && !inSingle) {
      inDouble = !inDouble;
      output += char;
      continue;
    }

    if (!inSingle && !inDouble && /[A-Za-z_]/.test(char)) {
      let token = char;
      while (i + 1 < sql.length && /[A-Za-z0-9_]/.test(sql[i + 1])) {
        i += 1;
        token += sql[i];
      }

      if (token === 'externalId') output += '"externalId"';
      else if (token === 'user') output += '"user"';
      else output += token;
      continue;
    }

    output += char;
  }

  return output;
}

function addReturningId(sql) {
  if (/\bRETURNING\b/i.test(sql)) return sql;
  const match = sql.match(/^\s*INSERT\s+INTO\s+("?[\w]+"?)\b/i);
  if (!match) return sql;

  const table = match[1].replace(/"/g, '').toLowerCase();
  if (!ID_TABLES.has(table)) return sql;

  return `${sql.replace(/;+\s*$/, '')} RETURNING id`;
}

function normalizeSql(sql) {
  let text = String(sql || '').trim();

  text = replaceIdentifiers(text)
    .replace(/datetime\('now'\)/gi, 'CURRENT_TIMESTAMP')
    .replace(/lastID/g, 'last_id');

  const insertIgnore = text.match(/^\s*INSERT\s+OR\s+IGNORE\s+INTO\s+settings\s*\(([^)]+)\)\s+VALUES\s*\(([^)]+)\)\s*;?\s*$/i);
  if (insertIgnore) {
    text = `INSERT INTO settings (${insertIgnore[1]}) VALUES (${insertIgnore[2]}) ON CONFLICT DO NOTHING`;
  }

  text = addReturningId(text);
  return convertQuestionPlaceholders(text);
}

function parseArgs(params, callback) {
  if (typeof params === 'function') {
    return { params: [], callback: params };
  }
  return { params: Array.isArray(params) ? params : [], callback };
}

class PgStatement {
  constructor(db, sql) {
    this.db = db;
    this.sql = sql;
  }

  run(...args) {
    const callback = typeof args[args.length - 1] === 'function' ? args.pop() : undefined;
    const params = args.length === 1 && Array.isArray(args[0]) ? args[0] : args;
    return this.db.run(this.sql, params, callback);
  }

  finalize(callback) {
    if (typeof callback === 'function') process.nextTick(() => callback(null));
  }
}

class PostgresDatabase {
  constructor(config) {
    this.kind = 'postgres';
    this.pool = new Pool({
      ...config,
      max: Number(process.env.PG_POOL_MAX || 25),
      idleTimeoutMillis: Number(process.env.PG_IDLE_TIMEOUT_MS || 30000)
    });
  }

  async query(sql, params = []) {
    return this.pool.query(normalizeSql(sql), params);
  }

  all(sql, params, callback) {
    const args = parseArgs(params, callback);
    const promise = this.query(sql, args.params)
      .then(result => {
        if (args.callback) args.callback(null, result.rows);
        return result.rows;
      })
      .catch(err => {
        if (args.callback) return args.callback(normalizeError(err));
        throw normalizeError(err);
      });
    return promise;
  }

  get(sql, params, callback) {
    const args = parseArgs(params, callback);
    const promise = this.query(sql, args.params)
      .then(result => {
        const row = result.rows[0];
        if (args.callback) args.callback(null, row);
        return row;
      })
      .catch(err => {
        if (args.callback) return args.callback(normalizeError(err));
        throw normalizeError(err);
      });
    return promise;
  }

  run(sql, params, callback) {
    const args = parseArgs(params, callback);
    const promise = this.query(sql, args.params)
      .then(result => {
        const context = {
          lastID: result.rows[0] && result.rows[0].id,
          changes: result.rowCount || 0
        };
        if (args.callback) args.callback.call(context, null);
        return context;
      })
      .catch(err => {
        if (args.callback) return args.callback.call({}, normalizeError(err));
        throw normalizeError(err);
      });
    return promise;
  }

  prepare(sql, callback) {
    const statement = new PgStatement(this, sql);
    if (typeof callback === 'function') process.nextTick(() => callback(null));
    return statement;
  }

  serialize(work) {
    if (typeof work === 'function') work();
  }

  close(callback) {
    return this.pool.end()
      .then(() => {
        if (callback) callback(null);
      })
      .catch(err => {
        if (callback) callback(err);
        else throw err;
      });
  }

  async transaction(work) {
    const client = await this.pool.connect();
    const txDb = Object.create(this);
    txDb.query = (sql, params = []) => client.query(normalizeSql(sql), params);
    txDb.close = (callback) => {
      if (typeof callback === 'function') callback(null);
      return Promise.resolve();
    };

    try {
      await client.query('BEGIN');
      const result = await work(txDb);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }
}

function createDatabase() {
  if (process.env.DATABASE_URL) {
    return new PostgresDatabase({ connectionString: process.env.DATABASE_URL });
  }

  if (process.env.PGHOST || process.env.POSTGRES_HOST) {
    return new PostgresDatabase({
      host: process.env.PGHOST || process.env.POSTGRES_HOST,
      port: Number(process.env.PGPORT || process.env.POSTGRES_PORT || 5432),
      database: process.env.PGDATABASE || process.env.POSTGRES_DB || 'threatdock',
      user: process.env.PGUSER || process.env.POSTGRES_USER || 'threatdock',
      password: process.env.PGPASSWORD || process.env.POSTGRES_PASSWORD || ''
    });
  }

  throw new Error('PostgreSQL settings are required. Configure DATABASE_URL or PGHOST/PGDATABASE/PGUSER/PGPASSWORD.');
}

async function createSchema(db) {
  const statements = [
    `CREATE TABLE IF NOT EXISTS tenants (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS alerts (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
      source TEXT,
      "externalId" TEXT,
      title TEXT,
      severity TEXT,
      date TEXT,
      url TEXT,
      status TEXT DEFAULT 'Open',
      attack_phase TEXT DEFAULT 'Unknown',
      assignee TEXT,
      priority TEXT DEFAULT 'P3',
      sla_due TEXT,
      tags TEXT DEFAULT '[]',
      case_summary TEXT,
      updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(source, "externalId")
    )`,
    `CREATE TABLE IF NOT EXISTS assets (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
      domain TEXT,
      ip TEXT,
      port INTEGER,
      service TEXT,
      tech_stack TEXT,
      status TEXT DEFAULT 'Active',
      risk_score INTEGER DEFAULT 0,
      business_criticality TEXT DEFAULT 'Medium',
      owner TEXT,
      environment TEXT DEFAULT 'Production',
      data_classification TEXT DEFAULT 'Internal',
      last_seen TIMESTAMPTZ,
      notes TEXT,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(tenant_id, domain, ip, port)
    )`,
    `CREATE TABLE IF NOT EXISTS hunt_queries (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
      query_type TEXT,
      query_value TEXT,
      results TEXT,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      "user" TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS vendors (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
      name TEXT,
      category TEXT,
      risk_score INTEGER DEFAULT 0,
      status TEXT DEFAULT 'Active',
      contact TEXT,
      last_assessment TIMESTAMPTZ,
      notes TEXT,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(tenant_id, name)
    )`,
    `CREATE TABLE IF NOT EXISTS osint_findings (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
      category TEXT,
      keyword TEXT,
      provider TEXT,
      type TEXT,
      title TEXT,
      severity TEXT,
      date TEXT,
      url TEXT,
      description TEXT,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT,
      updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
      username TEXT UNIQUE,
      password_hash TEXT,
      email TEXT,
      role TEXT DEFAULT 'Analyst',
      roles TEXT DEFAULT '["viewer"]',
      auth_provider TEXT DEFAULT 'local',
      oidc_issuer TEXT,
      oidc_subject TEXT,
      mfa_secret TEXT,
      mfa_enabled INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS alert_comments (
      id SERIAL PRIMARY KEY,
      alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
      "user" TEXT,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS audit_logs (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
      entity_type TEXT,
      entity_id TEXT,
      "user" TEXT,
      actor_sub TEXT,
      actor_email TEXT,
      action TEXT,
      event_name TEXT,
      status TEXT,
      before_value TEXT,
      after_value TEXT,
      metadata TEXT DEFAULT '{}',
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS source_health (
      source TEXT PRIMARY KEY,
      status TEXT,
      last_success TEXT,
      last_failure TEXT,
      last_error TEXT,
      last_count INTEGER DEFAULT 0,
      last_duration_ms INTEGER DEFAULT 0,
      updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS ingestion_runs (
      id SERIAL PRIMARY KEY,
      source TEXT,
      status TEXT,
      item_count INTEGER DEFAULT 0,
      duration_ms INTEGER DEFAULT 0,
      error TEXT,
      started_at TEXT,
      finished_at TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS indicators (
      id SERIAL PRIMARY KEY,
      value TEXT,
      type TEXT,
      source TEXT,
      "externalId" TEXT,
      severity TEXT DEFAULT 'Unknown',
      confidence INTEGER DEFAULT 50,
      first_seen TEXT,
      last_seen TEXT,
      malware_family TEXT,
      tags TEXT DEFAULT '[]',
      tlp TEXT DEFAULT 'TLP:AMBER',
      metadata TEXT DEFAULT '{}',
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(source, value, type)
    )`,
    `CREATE TABLE IF NOT EXISTS correlated_findings (
      id SERIAL PRIMARY KEY,
      group_key TEXT UNIQUE,
      title TEXT,
      severity TEXT,
      score INTEGER DEFAULT 0,
      confidence INTEGER DEFAULT 0,
      sources TEXT DEFAULT '[]',
      alert_ids TEXT DEFAULT '[]',
      indicator_ids TEXT DEFAULT '[]',
      entity_refs TEXT DEFAULT '[]',
      status TEXT DEFAULT 'Open',
      updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS cve_enrichment (
      cve_id TEXT PRIMARY KEY,
      epss_score REAL,
      epss_percentile REAL,
      kev_known INTEGER DEFAULT 0,
      kev_date_added TEXT,
      kev_due_date TEXT,
      kev_required_action TEXT,
      ransomware_use TEXT,
      updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )`,
    'CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_date ON alerts(date)',
    'CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(value)',
    'CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs(entity_type, entity_id)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_attack_phase ON alerts(attack_phase)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_priority ON alerts(priority)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_assignee ON alerts(assignee)',
    'CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(type)',
    'CREATE INDEX IF NOT EXISTS idx_osint_findings_cat_key ON osint_findings(category, keyword)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_severity_date ON alerts(severity, date)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_source_date ON alerts(source, date)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_status_date ON alerts(status, date)',
    'CREATE INDEX IF NOT EXISTS idx_alert_comments_alert_id ON alert_comments(alert_id)',
    'CREATE INDEX IF NOT EXISTS idx_correlated_findings_score_updated ON correlated_findings(score DESC, updated_at DESC)',
    'CREATE INDEX IF NOT EXISTS idx_ingestion_runs_started_at ON ingestion_runs(started_at DESC)',
    // Compatibility migrations for databases created before tenancy/RBAC.
    'ALTER TABLE alerts ADD COLUMN IF NOT EXISTS tenant_id INTEGER',
    'ALTER TABLE assets ADD COLUMN IF NOT EXISTS tenant_id INTEGER',
    'ALTER TABLE hunt_queries ADD COLUMN IF NOT EXISTS tenant_id INTEGER',
    'ALTER TABLE vendors ADD COLUMN IF NOT EXISTS tenant_id INTEGER',
    'ALTER TABLE osint_findings ADD COLUMN IF NOT EXISTS tenant_id INTEGER',
    'ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id INTEGER',
    'ALTER TABLE users ADD COLUMN IF NOT EXISTS roles TEXT DEFAULT \'["viewer"]\'',
    'ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider TEXT DEFAULT \'local\'',
    'ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_issuer TEXT',
    'ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_subject TEXT',
    'ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS tenant_id INTEGER',
    'ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS actor_sub TEXT',
    'ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS actor_email TEXT',
    'ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS status TEXT',
    'ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS event_name TEXT',
    'ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS metadata TEXT DEFAULT \'{}\'',
    // The default tenant is created before old rows are backfilled.
    "INSERT INTO tenants (name, slug) VALUES ('Default', 'default') ON CONFLICT (slug) DO NOTHING",
    "UPDATE alerts SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default') WHERE tenant_id IS NULL",
    "UPDATE assets SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default') WHERE tenant_id IS NULL",
    "UPDATE hunt_queries SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default') WHERE tenant_id IS NULL",
    "UPDATE vendors SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default') WHERE tenant_id IS NULL",
    "UPDATE osint_findings SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default') WHERE tenant_id IS NULL",
    "UPDATE users SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default') WHERE tenant_id IS NULL",
    "UPDATE users SET roles = '[\"admin\"]' WHERE role IN ('Admin', 'admin') AND (roles IS NULL OR roles = '' OR roles = '[\"viewer\"]')",
    "UPDATE audit_logs SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default') WHERE tenant_id IS NULL",
    'CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id)',
    'CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant ON audit_logs(tenant_id)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant_id)',
    'CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets(tenant_id)',
    'CREATE INDEX IF NOT EXISTS idx_vendors_tenant ON vendors(tenant_id)',
    'CREATE INDEX IF NOT EXISTS idx_hunt_queries_tenant ON hunt_queries(tenant_id)',
    'CREATE INDEX IF NOT EXISTS idx_osint_findings_tenant ON osint_findings(tenant_id)',
    'CREATE UNIQUE INDEX IF NOT EXISTS unique_users_oidc ON users(tenant_id, oidc_issuer, oidc_subject) WHERE oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL'
  ];

  for (const statement of statements) {
    await db.query(statement);
  }
}

async function seedDefaults(db) {
  for (const [key, value] of DEFAULT_SETTINGS) {
    await db.query(
      'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING',
      [key, settingsStore.prepareSettingValue(key, value)]
    );
  }

  const tenant = await db.get("SELECT id FROM tenants WHERE slug = 'default'");
  if (!tenant) throw new Error('Default tenant was not created');

  const adminUser = process.env.AUTH_USER || 'admin';
  const existingAdmin = await db.get(
    'SELECT id FROM users WHERE tenant_id = ? AND username = ?',
    [tenant.id, adminUser]
  );
  if (!existingAdmin) {
    const adminPass = process.env.AUTH_PASSWORD || 'admin';
    const hash = bcrypt.hashSync(adminPass, 10);
    await db.run(
      `INSERT INTO users (tenant_id, username, password_hash, role, roles, auth_provider)
       VALUES (?, ?, ?, 'Admin', ?, 'local')`,
      [tenant.id, adminUser, hash, JSON.stringify(['admin'])]
    );
  }
}

async function migrateSchema(db) {
  await createSchema(db);
}

async function initializeDatabase(db) {
  await migrateSchema(db);
  await seedDefaults(db);
}

module.exports = {
  createDatabase,
  initializeDatabase,
  migrateSchema
};
