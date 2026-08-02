/**
 * Dead-letter queue for failed ingestion attempts.
 * Captures items that failed processing after retries for later review or reprocessing.
 */

class DeadLetterQueue {
  constructor(db) {
    this.db = db;
  }

  /**
   * Initialize DLQ table schema
   */
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
        status TEXT DEFAULT 'pending',
        resolved_at TIMESTAMPTZ,
        resolved_by TEXT,
        notes TEXT
      )
    `);

    await this.db.query(`
      CREATE INDEX IF NOT EXISTS idx_dlq_source_status ON dead_letter_queue(source, status)
    `);

    await this.db.query(`
      CREATE INDEX IF NOT EXISTS idx_dlq_last_attempt ON dead_letter_queue(last_attempt DESC)
    `);
  }

  /**
   * Add failed item to DLQ
   * @param {string} source - Feed source name
   * @param {string} itemType - Type of item (e.g., 'alert', 'indicator', 'vulnerability')
   * @param {object} itemData - The failed item data
   * @param {string} errorMessage - Error description
   */
  async add(source, itemType, itemData, errorMessage) {
    try {
      const dataJson = JSON.stringify(itemData);
      const errorText = String(errorMessage).slice(0, 2000);

      await this.db.query(`
        INSERT INTO dead_letter_queue 
          (source, item_type, item_data, error_message, attempt_count, first_attempt, last_attempt, status)
        VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'pending')
      `, [source, itemType, dataJson, errorText]);

      console.log(`[DLQ] Added ${itemType} from ${source} (error: ${errorText.slice(0, 100)})`);
    } catch (err) {
      console.error(`[DLQ] Failed to add item to DLQ:`, err.message);
    }
  }

  /**
   * Record retry attempt for a DLQ item
   * @param {number} id - DLQ item ID
   * @param {string} errorMessage - New error message if retry failed
   */
  async recordRetry(id, errorMessage) {
    const errorText = String(errorMessage).slice(0, 2000);
    
    await this.db.query(`
      UPDATE dead_letter_queue
      SET 
        attempt_count = attempt_count + 1,
        last_attempt = CURRENT_TIMESTAMP,
        error_message = ?
      WHERE id = ?
    `, [errorText, id]);
  }

  /**
   * Mark DLQ item as resolved
   * @param {number} id - DLQ item ID
   * @param {string} resolvedBy - User who resolved it
   * @param {string} notes - Resolution notes
   */
  async resolve(id, resolvedBy, notes = '') {
    await this.db.query(`
      UPDATE dead_letter_queue
      SET 
        status = 'resolved',
        resolved_at = CURRENT_TIMESTAMP,
        resolved_by = ?,
        notes = ?
      WHERE id = ?
    `, [resolvedBy, notes, id]);

    console.log(`[DLQ] Item ${id} resolved by ${resolvedBy}`);
  }

  /**
   * Mark DLQ item as permanently failed
   * @param {number} id - DLQ item ID
   * @param {string} reason - Reason for permanent failure
   */
  async markFailed(id, reason) {
    await this.db.query(`
      UPDATE dead_letter_queue
      SET 
        status = 'failed',
        notes = ?
      WHERE id = ?
    `, [reason, id]);
  }

  /**
   * Get pending DLQ items for a source
   * @param {string} source - Feed source name
   * @param {number} limit - Max items to return
   * @returns {Promise<Array>} Pending DLQ items
   */
  async getPending(source, limit = 100) {
    const result = await this.db.query(`
      SELECT id, source, item_type, item_data, error_message, attempt_count, 
             first_attempt, last_attempt, status
      FROM dead_letter_queue
      WHERE source = ? AND status = 'pending'
      ORDER BY last_attempt ASC
      LIMIT ?
    `, [source, limit]);

    return result.rows || [];
  }

  /**
   * Get all DLQ items with filters
   * @param {object} filters - { source?, status?, limit? }
   * @returns {Promise<Array>} DLQ items
   */
  async getAll(filters = {}) {
    const { source, status, limit = 100 } = filters;
    
    let sql = `
      SELECT id, source, item_type, error_message, attempt_count,
             first_attempt, last_attempt, status, resolved_at, resolved_by
      FROM dead_letter_queue
      WHERE 1=1
    `;
    const params = [];

    if (source) {
      sql += ` AND source = ?`;
      params.push(source);
    }

    if (status) {
      sql += ` AND status = ?`;
      params.push(status);
    }

    sql += ` ORDER BY last_attempt DESC LIMIT ?`;
    params.push(limit);

    const result = await this.db.query(sql, params);
    return result.rows || [];
  }

  /**
   * Get DLQ statistics
   * @returns {Promise<object>} Stats by source and status
   */
  async getStats() {
    const result = await this.db.query(`
      SELECT 
        source,
        status,
        COUNT(*) as count,
        MAX(last_attempt) as latest_attempt
      FROM dead_letter_queue
      GROUP BY source, status
      ORDER BY source, status
    `);

    return result.rows || [];
  }

  /**
   * Clean up old resolved/failed items
   * @param {number} daysOld - Delete items older than this many days
   */
  async cleanup(daysOld = 30) {
    const result = await this.db.query(`
      DELETE FROM dead_letter_queue
      WHERE status IN ('resolved', 'failed')
        AND last_attempt < CURRENT_TIMESTAMP - (? * INTERVAL '1 day')
    `, [daysOld]);

    const deleted = result.rowCount || 0;
    if (deleted > 0) {
      console.log(`[DLQ] Cleaned up ${deleted} old DLQ items`);
    }
    return deleted;
  }
}

module.exports = { DeadLetterQueue };
