/**
 * Dead-letter queue for failed ingestion attempts.
 * Captures items that failed processing after retries for later review or reprocessing.
 */

const DEFAULT_MAX_ATTEMPTS = 8;

class DeadLetterQueue {
  constructor(db, { maxAttempts = DEFAULT_MAX_ATTEMPTS } = {}) {
    this.db = db;
    this.maxAttempts = maxAttempts;
  }

  /** Initialize the schema and idempotent migrations. */
  async initialize() {
    await this.db.query(`
      CREATE TABLE IF NOT EXISTS dead_letter_queue (
        id SERIAL PRIMARY KEY,
        source TEXT NOT NULL,
        item_type TEXT,
        item_data TEXT,
        error_message TEXT,
        attempt_count INTEGER DEFAULT 1,
        first_attempt TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        last_attempt TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        next_attempt_at TIMESTAMPTZ,
        status TEXT DEFAULT 'pending',
        resolved_at TIMESTAMPTZ,
        resolved_by TEXT,
        notes TEXT
      )
    `);
    await this.db.query('ALTER TABLE dead_letter_queue ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ');
    await this.db.query("UPDATE dead_letter_queue SET next_attempt_at = CURRENT_TIMESTAMP WHERE status = 'pending' AND next_attempt_at IS NULL");
    await this.db.query('CREATE INDEX IF NOT EXISTS idx_dlq_source_status ON dead_letter_queue(source, status)');
    await this.db.query('CREATE INDEX IF NOT EXISTS idx_dlq_last_attempt ON dead_letter_queue(last_attempt DESC)');
    await this.db.query('CREATE INDEX IF NOT EXISTS idx_dlq_next_attempt ON dead_letter_queue(status, next_attempt_at)');
  }

  /**
   * Compute the next retry timestamp using capped exponential backoff.
   * Delays are 1m, 2m, 4m, 8m, ... and cap at six hours.
   */
  computeNextAttempt(attemptCount) {
    const baseMs = 60_000;
    const capMs = 6 * 60 * 60 * 1000;
    const exponent = Math.min(Math.max(Number(attemptCount) - 1, 0), 20);
    return new Date(Date.now() + Math.min(baseMs * (2 ** exponent), capMs));
  }

  async add(source, itemType, itemData, errorMessage) {
    try {
      const dataJson = JSON.stringify(itemData);
      const errorText = String(errorMessage).slice(0, 2000);
      await this.db.query(`
        INSERT INTO dead_letter_queue
          (source, item_type, item_data, error_message, attempt_count, first_attempt, last_attempt, next_attempt_at, status)
        VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, 'pending')
      `, [source, itemType, dataJson, errorText, this.computeNextAttempt(1).toISOString()]);
      console.log(`[DLQ] Added ${itemType} from ${source} (error: ${errorText.slice(0, 100)})`);
    } catch (err) {
      // DLQ capture must never replace the original ingestion error.
      console.error('[DLQ] Failed to add item to DLQ:', err.message);
    }
  }

  /**
   * Schedule a claimed or pending item for another attempt, or permanently
   * fail it after the configured retry limit is exhausted.
   */
  async recordRetry(id, errorMessage) {
    const errorText = String(errorMessage).slice(0, 2000);
    const result = await this.db.query('SELECT attempt_count FROM dead_letter_queue WHERE id = ?', [id]);
    const current = result.rows?.[0];
    if (!current) return false;

    const nextCount = Number(current.attempt_count || 0) + 1;
    if (nextCount >= this.maxAttempts) {
      await this.db.query(`
        UPDATE dead_letter_queue
        SET attempt_count = ?, last_attempt = CURRENT_TIMESTAMP, next_attempt_at = NULL,
            error_message = ?, status = 'failed', notes = ?
        WHERE id = ?
      `, [nextCount, errorText, `Automatic retry limit (${this.maxAttempts}) reached.`, id]);
      return false;
    }

    await this.db.query(`
      UPDATE dead_letter_queue
      SET attempt_count = ?, last_attempt = CURRENT_TIMESTAMP, next_attempt_at = ?,
          error_message = ?, status = 'pending'
      WHERE id = ?
    `, [nextCount, this.computeNextAttempt(nextCount).toISOString(), errorText, id]);
    return true;
  }

  async resolve(id, resolvedBy, notes = '') {
    await this.db.query(`
      UPDATE dead_letter_queue
      SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP, resolved_by = ?,
          notes = ?, next_attempt_at = NULL
      WHERE id = ?
    `, [resolvedBy, notes, id]);
    console.log(`[DLQ] Item ${id} resolved by ${resolvedBy}`);
  }

  async markFailed(id, reason) {
    await this.db.query(`
      UPDATE dead_letter_queue
      SET status = 'failed', next_attempt_at = NULL, notes = ?
      WHERE id = ?
    `, [reason, id]);
  }

  async getPending(source, limit = 100) {
    const result = await this.db.query(`
      SELECT id, source, item_type, item_data, error_message, attempt_count,
             first_attempt, last_attempt, next_attempt_at, status
      FROM dead_letter_queue
      WHERE source = ? AND status = 'pending'
      ORDER BY next_attempt_at ASC NULLS LAST, last_attempt ASC
      LIMIT ?
    `, [source, limit]);
    return result.rows || [];
  }

  async getReadyForRetry(limit = 50) {
    const result = await this.db.query(`
      SELECT id, source, item_type, item_data, error_message, attempt_count,
             first_attempt, last_attempt, next_attempt_at, status
      FROM dead_letter_queue
      WHERE status = 'pending' AND next_attempt_at IS NOT NULL
        AND next_attempt_at <= CURRENT_TIMESTAMP
      ORDER BY next_attempt_at ASC
      LIMIT ?
    `, [limit]);
    return result.rows || [];
  }

  /**
   * Atomically claim due work. SKIP LOCKED prevents multiple application
   * instances from replaying the same source failure concurrently.
   */
  async claimReadyForRetry(limit = 50) {
    const result = await this.db.query(`
      WITH candidates AS (
        SELECT id
        FROM dead_letter_queue
        WHERE status = 'pending' AND next_attempt_at IS NOT NULL
          AND next_attempt_at <= CURRENT_TIMESTAMP
        ORDER BY next_attempt_at ASC
        LIMIT ?
        FOR UPDATE SKIP LOCKED
      )
      UPDATE dead_letter_queue AS dlq
      SET status = 'processing', last_attempt = CURRENT_TIMESTAMP
      FROM candidates
      WHERE dlq.id = candidates.id
      RETURNING dlq.id, dlq.source, dlq.item_type, dlq.item_data,
                dlq.error_message, dlq.attempt_count, dlq.first_attempt,
                dlq.last_attempt, dlq.next_attempt_at, dlq.status
    `, [limit]);
    return result.rows || [];
  }

  /** Claim a specific non-resolved item for an operator-requested replay. */
  async claimById(id) {
    const result = await this.db.query(`
      UPDATE dead_letter_queue
      SET status = 'processing', last_attempt = CURRENT_TIMESTAMP
      WHERE id = ? AND status IN ('pending', 'failed')
      RETURNING id, source, item_type, item_data, error_message, attempt_count,
                first_attempt, last_attempt, next_attempt_at, status
    `, [id]);
    return result.rows?.[0] || null;
  }

  /** Release a claimed item without consuming a retry when a worker is busy. */
  async releaseClaim(id, note = 'Replay deferred because another ingestion run is active.') {
    await this.db.query(`
      UPDATE dead_letter_queue
      SET status = 'pending', next_attempt_at = CURRENT_TIMESTAMP, notes = ?
      WHERE id = ? AND status = 'processing'
    `, [String(note).slice(0, 2000), id]);
  }

  /** Mark a replayed item as resolved, keeping history and removing from retry queue. */
  async succeed(id, resolvedBy = 'automatic-retry') {
    await this.db.query(`
      UPDATE dead_letter_queue
      SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP, resolved_by = ?,
          next_attempt_at = NULL, notes = COALESCE(notes, '') || ' Successfully replayed.'
      WHERE id = ? AND status = 'processing'
    `, [resolvedBy, id]);
    console.log(`[DLQ] Item ${id} successfully replayed and resolved by ${resolvedBy}.`);
  }

  /** Requeue claims left by a crashed worker after the safety timeout. */
  async recoverStaleProcessing(minutes = 15) {
    const result = await this.db.query(`
      UPDATE dead_letter_queue
      SET status = 'pending', next_attempt_at = CURRENT_TIMESTAMP,
          notes = COALESCE(notes, '') || ' Requeued after stale processing claim.'
      WHERE status = 'processing'
        AND last_attempt < CURRENT_TIMESTAMP - (? * INTERVAL '1 minute')
    `, [minutes]);
    return result.rowCount || 0;
  }

  async getAll(filters = {}) {
    const { source, status, limit = 100 } = filters;
    let sql = `
      SELECT id, source, item_type, error_message, attempt_count, first_attempt,
             last_attempt, next_attempt_at, status, resolved_at, resolved_by, notes
      FROM dead_letter_queue WHERE 1=1
    `;
    const params = [];
    if (source) { sql += ' AND source = ?'; params.push(source); }
    if (status) { sql += ' AND status = ?'; params.push(status); }
    sql += ' ORDER BY last_attempt DESC LIMIT ?';
    params.push(limit);
    const result = await this.db.query(sql, params);
    return result.rows || [];
  }

  async getStats() {
    const result = await this.db.query(`
      SELECT source, status, COUNT(*) as count, MAX(last_attempt) as latest_attempt
      FROM dead_letter_queue
      GROUP BY source, status
      ORDER BY source, status
    `);
    return result.rows || [];
  }

  async cleanup(daysOld = 30) {
    const result = await this.db.query(`
      DELETE FROM dead_letter_queue
      WHERE status IN ('resolved', 'failed')
        AND last_attempt < CURRENT_TIMESTAMP - (? * INTERVAL '1 day')
    `, [daysOld]);
    const deleted = result.rowCount || 0;
    if (deleted > 0) console.log(`[DLQ] Cleaned up ${deleted} old DLQ items`);
    return deleted;
  }
}

module.exports = { DeadLetterQueue };
