const { validateToken } = require('../services/oauth');
const jwt = require('jsonwebtoken');
const settingsStore = require('../services/settingsStore');
const { normalizeRoles } = require('../services/identity');

function userIdentity(row, type, claims = {}) {
  const roles = normalizeRoles(row.roles).length
    ? normalizeRoles(row.roles)
    : normalizeRoles(row.role);
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    name: row.username,
    email: row.email,
    role: row.role,
    roles,
    auth_provider: row.auth_provider || type,
    oidc_issuer: row.oidc_issuer || claims.iss || null,
    oidc_subject: row.oidc_subject || claims.sub || null,
    sub: row.oidc_subject || String(row.id),
    type
  };
}

function getUser(db, sql, params) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => err ? reject(err) : resolve(row || null));
  });
}

module.exports = async function auth(req, res, next) {
  const db = req.db;
  if (!db) return res.status(500).send('Database not initialized');

  try {
    const settings = await settingsStore.getSettings(db);
    const header = req.headers.authorization;

    if (header && header.startsWith('Bearer ')) {
      const token = header.slice('Bearer '.length);

      try {
        const decoded = jwt.verify(token, settings.JWT_SECRET, { algorithms: ['HS256'] });
        if (!decoded || decoded.mfaPending || !decoded.id) {
          return res.status(401).json({ error: 'Invalid or incomplete token' });
        }
        const user = await getUser(
          db,
          `SELECT id, tenant_id, username, email, role, roles, auth_provider, oidc_issuer, oidc_subject
           FROM users WHERE id = ? AND tenant_id = ?`,
          [decoded.id, decoded.tenant_id]
        );
        if (!user) return res.status(401).json({ error: 'User no longer exists' });
        req.user = userIdentity(user, decoded.type || 'local', decoded);
        req.tenant_id = user.tenant_id;
        return next();
      } catch (localErr) {
        // A token that is not a valid local JWT may still be an OIDC access token.
      }

      if (settings.SSO_ENABLED === 'true') {
        try {
          const decoded = await validateToken(token, settings);
          if (!decoded.sub || decoded.iss !== settings.OIDC_ISSUER_URL) {
            return res.status(401).json({ error: 'Invalid OIDC identity' });
          }
          const user = await getUser(
            db,
            `SELECT id, tenant_id, username, email, role, roles, auth_provider, oidc_issuer, oidc_subject
             FROM users WHERE oidc_issuer = ? AND oidc_subject = ?`,
            [decoded.iss, decoded.sub]
          );
          if (!user) return res.status(401).send('Unauthorized SSO user');
          req.user = userIdentity(user, 'sso', decoded);
          req.tenant_id = user.tenant_id;
          return next();
        } catch (oidcErr) {
          console.error('SSO JWT validation error:', oidcErr.message);
        }
      }
      return res.status(401).send('Invalid or expired token');
    }

    return res.status(401).json({ error: 'Authentication required' });
  } catch (err) {
    console.error('Auth middleware error:', err);
    return res.status(500).send('Internal Server Error');
  }
};

module.exports.userIdentity = userIdentity;

// Socket.IO handshake: the client sends the same local access token via `auth.token`.
module.exports.socketAuth = db => async (socket, next) => {
  try {
    const settings = await settingsStore.getSettings(db);
    const token = String((socket.handshake.auth && socket.handshake.auth.token) || '');
    const decoded = jwt.verify(token, settings.JWT_SECRET, { algorithms: ['HS256'] });
    const user = decoded.mfaPending || !decoded.id
      ? null
      : await getUser(db, 'SELECT id, tenant_id FROM users WHERE id = ? AND tenant_id = ?', [decoded.id, decoded.tenant_id]);
    if (!user) return next(new Error('Unauthorized'));
    socket.join(`tenant:${user.tenant_id}`);
    return next();
  } catch {
    return next(new Error('Unauthorized'));
  }
};
