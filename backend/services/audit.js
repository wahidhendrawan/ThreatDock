/**
 * Audit logging service.
 *
 * Records significant events (login, logout, MFA, mutations) with actor
 * identity, tenant scope, and sanitized metadata.
 */

const crypto = require('crypto');

/**
 * Redact or mask sensitive values in an object tree.
 * @param {any} obj
 * @returns {any}
 */
function sanitize(obj) {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sanitize);

  const sanitized = {};
  for (const [key, value] of Object.entries(obj)) {
    const keyLower = key.toLowerCase();
    if (/(password|passwd|secret|token|authorization|cookie|otp|api[_-]?key)/i.test(keyLower)) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitize(value);
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

/**
 * Extract actor identity from a user object or Express request.
 * @param {object} actor req.user or user record
 * @returns {object} { sub, email, name }
 */
function extractActor(actor) {
  if (!actor) return { sub: 'anonymous', email: null, name: null };
  return {
    sub: actor.oidc_subject || actor.sub || actor.id || 'unknown',
    email: actor.email || null,
    name: actor.name || actor.username || actor.preferred_username || null
  };
}

/**
 * Record an audit log entry with tenant isolation and actor identity.
 * @param {object} db database adapter
 * @param {object} params
 * @param {string} params.tenant_id
 * @param {object} params.actor req.user or user record
 * @param {string} params.event_name login|logout|mfa_enable|create_user|update_user|...
 * @param {string} params.status success|failure
 * @param {object} [params.metadata] additional context (sanitized before storage)
 * @returns {Promise<void>}
 */
async function auditLog(db, params) {
  const { tenant_id, actor, event_name, status, metadata = {} } = params;
  if (!tenant_id || !event_name || !status) {
    console.error('auditLog: missing required params (tenant_id, event_name, status)');
    return;
  }

  const { sub, email } = extractActor(actor);
  const sanitizedMetadata = sanitize(metadata);

  try {
    await db.run(
      `INSERT INTO audit_logs (tenant_id, actor_sub, actor_email, event_name, status, metadata)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [tenant_id, sub, email, event_name, status, JSON.stringify(sanitizedMetadata)]
    );
  } catch (err) {
    console.error('auditLog failed:', err.message);
  }
}

/**
 * Generate a sanitized, stable actor name for legacy audit_logs.user field.
 * @param {object} actor
 * @returns {string}
 */
function actorName(actor) {
  if (!actor) return 'anonymous';
  return actor.name || actor.username || actor.email || actor.preferred_username || actor.sub || 'unknown';
}

/**
 * Delete audit log entries older than the retention window.
 * Intended to be run on a schedule (e.g. weekly) to bound table growth
 * while preserving a compliance-friendly history window.
 * @param {object} db database adapter
 * @param {number} retentionDays days of history to keep (default 90)
 * @returns {Promise<number>} number of rows deleted
 */
async function pruneOldAuditLogs(db, retentionDays = 90) {
  try {
    const result = await db.query(
      `DELETE FROM audit_logs WHERE created_at < CURRENT_TIMESTAMP - (? * INTERVAL '1 day')`,
      [retentionDays]
    );
    const deleted = result.rowCount || 0;
    if (deleted > 0) {
      console.log(`[Audit] Pruned ${deleted} audit log entries older than ${retentionDays} days.`);
    }
    return deleted;
  } catch (err) {
    console.error('pruneOldAuditLogs failed:', err.message);
    return 0;
  }
}

module.exports = {
  sanitize,
  extractActor,
  auditLog,
  actorName,
  pruneOldAuditLogs
};
