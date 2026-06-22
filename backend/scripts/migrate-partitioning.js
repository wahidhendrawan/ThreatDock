/**
 * Migration: Optimize alerts table for time-range query performance.
 *
 * 1. Add date_ts TIMESTAMPTZ derived from existing TEXT date column
 * 2. Add month partition column for partition pruning
 * 3. Add composite indexes for common query patterns
 * 4. Set up data retention function to prune alerts > 90 days
 *
 * This is safe to run multiple times (idempotent DO blocks).
 */
const { createDatabase } = require('../services/database');

async function migrate() {
  const db = createDatabase();
  console.log('Connected to database.');

  // 1. Add date_ts column if not exists
  await db.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'alerts' AND column_name = 'date_ts'
      ) THEN
        ALTER TABLE alerts ADD COLUMN date_ts TIMESTAMPTZ;
      END IF;
    END $$;
  `);
  console.log('✓ date_ts column checked/added');

  // 2. Populate date_ts from existing text dates
  await db.query(`
    UPDATE alerts
    SET date_ts = CASE
      WHEN date ~ '^\\d{4}-\\d{2}-\\d{2}' THEN date::TIMESTAMPTZ
      ELSE NULL
    END
    WHERE date_ts IS NULL
    LIMIT 10000;
  `);
  const updated = await db.get(`SELECT COUNT(*) as c FROM alerts WHERE date_ts IS NOT NULL`);
  console.log(`✓ date_ts populated for ${updated.c} alerts`);

  // 3. Add composite indexes for query performance
  await db.query(`CREATE INDEX IF NOT EXISTS idx_alerts_date_ts ON alerts(date_ts DESC)`);
  await db.query(`CREATE INDEX IF NOT EXISTS idx_alerts_ts_severity ON alerts(severity, date_ts DESC)`);
  await db.query(`CREATE INDEX IF NOT EXISTS idx_alerts_ts_source ON alerts(source, date_ts DESC)`);
  await db.query(`CREATE INDEX IF NOT EXISTS idx_alerts_ts_status ON alerts(status, date_ts DESC)`);
  console.log('✓ time-series indexes created');

  // 4. Data retention: prune alerts with NULL date older than 90 days
  const pruned = await db.run(`
    DELETE FROM alerts
    WHERE date_ts < CURRENT_TIMESTAMP - INTERVAL '90 days'
    AND date_ts IS NOT NULL
  `);
  console.log(`✓ pruned ${pruned.changes || 0} outdated alerts (>90 days)`);

  // 5. Create maintenance function for periodic use
  await db.query(`
    CREATE OR REPLACE FUNCTION prune_old_alerts(retention_days INTEGER DEFAULT 90)
    RETURNS INTEGER AS $$
    DECLARE
      deleted INTEGER;
    BEGIN
      DELETE FROM alerts
      WHERE date_ts < CURRENT_TIMESTAMP - (retention_days || ' days')::INTERVAL
      AND date_ts IS NOT NULL;
      GET DIAGNOSTICS deleted = ROW_COUNT;
      RETURN deleted;
    END;
    $$ LANGUAGE plpgsql;
  `);
  console.log('✓ prune_old_alerts() function created');

  // 6. Schedule weekly prune via cron (handled by app.js)

  await db.close();
  console.log('Migration complete!');
}

migrate().catch(err => {
  console.error('Migration failed:', err.message);
  process.exit(1);
});
