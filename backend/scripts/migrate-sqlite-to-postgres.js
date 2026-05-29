require('dotenv').config();

const path = require('path');
const { pathToFileURL } = require('url');
const sqlite3 = require('sqlite3').verbose();
const { createDatabase, initializeDatabase } = require('../services/database');

const SQLITE_DB_PATH = process.env.SQLITE_DB_PATH || process.env.DB_PATH || path.join(__dirname, '..', 'alerts.db');

const TABLES = [
  {
    name: 'alerts',
    columns: ['id', 'source', 'externalId', 'title', 'severity', 'date', 'url', 'status', 'attack_phase', 'assignee', 'priority', 'sla_due', 'tags', 'case_summary', 'updated_at']
  },
  {
    name: 'assets',
    columns: ['id', 'domain', 'ip', 'port', 'service', 'tech_stack', 'status', 'risk_score', 'business_criticality', 'owner', 'environment', 'data_classification', 'last_seen', 'notes', 'created_at']
  },
  {
    name: 'hunt_queries',
    columns: ['id', 'query_type', 'query_value', 'results', 'created_at', 'user']
  },
  {
    name: 'vendors',
    columns: ['id', 'name', 'category', 'risk_score', 'status', 'contact', 'last_assessment', 'notes', 'created_at']
  },
  {
    name: 'osint_findings',
    columns: ['id', 'category', 'keyword', 'provider', 'type', 'title', 'severity', 'date', 'url', 'description', 'created_at']
  },
  {
    name: 'settings',
    columns: ['key', 'value', 'updated_at'],
    conflict: ['key']
  },
  {
    name: 'users',
    columns: ['id', 'username', 'password_hash', 'email', 'role', 'mfa_secret', 'mfa_enabled', 'created_at']
  },
  {
    name: 'alert_comments',
    columns: ['id', 'alert_id', 'user', 'body', 'created_at']
  },
  {
    name: 'audit_logs',
    columns: ['id', 'entity_type', 'entity_id', 'user', 'action', 'before_value', 'after_value', 'created_at']
  },
  {
    name: 'source_health',
    columns: ['source', 'status', 'last_success', 'last_failure', 'last_error', 'last_count', 'last_duration_ms', 'updated_at'],
    conflict: ['source']
  },
  {
    name: 'ingestion_runs',
    columns: ['id', 'source', 'status', 'item_count', 'duration_ms', 'error', 'started_at', 'finished_at']
  },
  {
    name: 'indicators',
    columns: ['id', 'value', 'type', 'source', 'externalId', 'severity', 'confidence', 'first_seen', 'last_seen', 'malware_family', 'tags', 'tlp', 'metadata', 'created_at', 'updated_at']
  },
  {
    name: 'correlated_findings',
    columns: ['id', 'group_key', 'title', 'severity', 'score', 'confidence', 'sources', 'alert_ids', 'indicator_ids', 'entity_refs', 'status', 'updated_at']
  },
  {
    name: 'cve_enrichment',
    columns: ['cve_id', 'epss_score', 'epss_percentile', 'kev_known', 'kev_date_added', 'kev_due_date', 'kev_required_action', 'ransomware_use', 'updated_at'],
    conflict: ['cve_id']
  }
];

const ID_TABLES = TABLES.filter(table => table.columns.includes('id')).map(table => table.name);

function sqliteAll(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

function quoteIdent(value) {
  return `"${String(value).replace(/"/g, '""')}"`;
}

function normalizeValue(column, value) {
  if (value === '' && /(_at|_seen|last_assessment)$/i.test(column)) return null;
  return value;
}

async function existingSqliteColumns(sqliteDb, tableName) {
  const rows = await sqliteAll(sqliteDb, `PRAGMA table_info(${quoteIdent(tableName)})`);
  return new Set(rows.map(row => row.name));
}

async function insertRows(pgDb, table, rows, columns) {
  if (rows.length === 0 || columns.length === 0) return 0;

  const quotedColumns = columns.map(quoteIdent).join(', ');
  const conflictColumns = table.conflict || (columns.includes('id') ? ['id'] : []);
  const updateColumns = columns.filter(column => !conflictColumns.includes(column));
  const conflictClause = conflictColumns.length === 0 || updateColumns.length === 0
    ? 'ON CONFLICT DO NOTHING'
    : `ON CONFLICT (${conflictColumns.map(quoteIdent).join(', ')}) DO UPDATE SET ${updateColumns.map(column => `${quoteIdent(column)} = EXCLUDED.${quoteIdent(column)}`).join(', ')}`;
  let inserted = 0;

  for (const row of rows) {
    const params = columns.map(column => normalizeValue(column, row[column]));
    const placeholders = columns.map((_, index) => `$${index + 1}`).join(', ');
    const sql = `INSERT INTO ${quoteIdent(table.name)} (${quotedColumns}) VALUES (${placeholders}) ${conflictClause}`;
    const result = await pgDb.query(sql, params);
    inserted += result.rowCount || 0;
  }

  return inserted;
}

async function resetSequences(pgDb) {
  for (const tableName of ID_TABLES) {
    await pgDb.query(
      `SELECT setval(pg_get_serial_sequence($1, 'id'), COALESCE((SELECT MAX(id) FROM ${quoteIdent(tableName)}), 1), true)`,
      [tableName]
    );
  }
}

async function main() {
  const sqliteUri = `${pathToFileURL(SQLITE_DB_PATH).href}?mode=ro&immutable=1`;
  const sqliteDb = new sqlite3.Database(sqliteUri, sqlite3.OPEN_READONLY | sqlite3.OPEN_URI);
  const pgDb = createDatabase();

  try {
    await initializeDatabase(pgDb);
    console.log(`Migrating SQLite data from ${SQLITE_DB_PATH}`);

    for (const table of TABLES) {
      const existing = await existingSqliteColumns(sqliteDb, table.name);
      if (existing.size === 0) {
        console.log(`${table.name}: skipped, table not found`);
        continue;
      }

      const columns = table.columns.filter(column => existing.has(column));
      const rows = await sqliteAll(sqliteDb, `SELECT ${columns.map(quoteIdent).join(', ')} FROM ${quoteIdent(table.name)}`);
      const inserted = await insertRows(pgDb, table, rows, columns);
      console.log(`${table.name}: ${inserted}/${rows.length} rows inserted`);
    }

    await resetSequences(pgDb);
    console.log('Migration complete.');
  } finally {
    sqliteDb.close();
    await pgDb.close();
  }
}

main().catch(err => {
  console.error('Migration failed:', err.message);
  process.exit(1);
});
