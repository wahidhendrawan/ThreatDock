const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { generateSecret, generateURI, verifySync } = require('otplib');
const qrcode = require('qrcode');
const { exchangeCodeForToken, getUserInfo } = require('../services/oauth');
const settingsStore = require('../services/settingsStore');
const { auditLog } = require('../services/audit');
const { normalizeRoles } = require('../services/identity');

const router = express.Router();
const TEMP_JWT_OPTIONS = { algorithm: 'HS256', expiresIn: '5m' };
const ACCESS_JWT_OPTIONS = { algorithm: 'HS256', expiresIn: '8h' };
const STATE_JWT_OPTIONS = { algorithm: 'HS256', expiresIn: '10m' };

const verifyMfaCode = (code, secret) => {
  if (!/^\d{6}$/.test(String(code || ''))) return false;
  const result = verifySync({ token: String(code), secret, window: 0 });
  return Boolean(result && result.valid === true);
};

const getSettings = db => settingsStore.getSettings(db);
const dbGet = (db, sql, params = []) => new Promise((resolve, reject) => {
  db.get(sql, params, (err, row) => err ? reject(err) : resolve(row || null));
});
const dbRun = (db, sql, params = []) => new Promise((resolve, reject) => {
  db.run(sql, params, function onRun(err) {
    if (err) return reject(err);
    resolve({ lastID: this.lastID, changes: this.changes });
  });
});

function isValidIssuerUrl(url) {
  if (typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' && Boolean(parsed.hostname) && parsed.hostname !== 'localhost' && parsed.hostname.includes('.');
  } catch {
    return false;
  }
}

function userClaims(user, type) {
  const roles = normalizeRoles(user.roles).length ? normalizeRoles(user.roles) : normalizeRoles(user.role);
  return {
    id: user.id,
    tenant_id: user.tenant_id,
    name: user.username,
    email: user.email,
    role: user.role,
    roles,
    type,
    sub: user.oidc_subject || String(user.id),
    oidc_issuer: user.oidc_issuer || null
  };
}

function signAccessToken(user, type, secret) {
  return jwt.sign(userClaims(user, type), secret, ACCESS_JWT_OPTIONS);
}

async function defaultTenant(db) {
  const tenant = await dbGet(db, "SELECT id FROM tenants WHERE slug = 'default'");
  if (!tenant) throw new Error('Default tenant is not configured');
  return tenant;
}

async function completeLogin(req, res, user, type, settings) {
  const roles = normalizeRoles(user.roles).length ? normalizeRoles(user.roles) : normalizeRoles(user.role);
  const globalMfaRequired = settings.MFA_REQUIRED === 'true';
  const analystMfaRequired = settings.ANALYST_MFA_REQUIRED === 'true' && roles.includes('editor');
  const mustUseMfa = Boolean(user.mfa_enabled) || globalMfaRequired || analystMfaRequired;
  const hasConfiguredMfa = Boolean(user.mfa_enabled && user.mfa_secret);

  if (mustUseMfa) {
    const tempToken = jwt.sign(
      { id: user.id, tenant_id: user.tenant_id, type, mfaPending: true },
      settings.JWT_SECRET,
      TEMP_JWT_OPTIONS
    );
    return res.json({ requiresMfa: true, tempToken, setupRequired: !hasConfiguredMfa });
  }

  await auditLog(req.db, {
    tenant_id: user.tenant_id,
    actor: user,
    event_name: 'login',
    status: 'success',
    metadata: { provider: type, ip: req.ip }
  });
  return res.json({
    access_token: signAccessToken(user, type, settings.JWT_SECRET),
    user: { name: user.username, role: user.role, roles }
  });
}

router.get('/login', async (req, res) => {
  try {
    const settings = await getSettings(req.db);
    if (!isValidIssuerUrl(settings.OIDC_ISSUER_URL)) {
      return res.status(400).json({ error: 'Invalid or missing OIDC issuer URL' });
    }
    const redirectUri = `${settings.FRONTEND_URL}/callback`;
    let authorizeEndpoint = `${settings.OIDC_ISSUER_URL.replace(/\/$/, '')}/authorize/`;
    try {
      const { outboundHttp: axios } = require('../services/outboundHttp');
      const discoveryUrl = `${settings.OIDC_ISSUER_URL.replace(/\/$/, '')}/.well-known/openid-configuration`;

      const response = await axios.get(discoveryUrl, { timeout: 3000 });
      if (response.data && isValidIssuerUrl(response.data.authorization_endpoint)) {
        authorizeEndpoint = response.data.authorization_endpoint;
      }
    } catch (err) {
      console.error('OIDC discovery failed, using issuer endpoint:', err.message);
    }

    const state = jwt.sign(
      { purpose: 'oidc-state', nonce: crypto.randomBytes(24).toString('hex') },
      settings.JWT_SECRET,
      STATE_JWT_OPTIONS
    );
    const authorizeUrl = new URL(authorizeEndpoint);
    if (authorizeUrl.protocol !== 'https:') return res.status(400).json({ error: 'Invalid OIDC authorization endpoint' });
    authorizeUrl.searchParams.set('client_id', settings.OIDC_CLIENT_ID);
    authorizeUrl.searchParams.set('response_type', 'code');
    authorizeUrl.searchParams.set('redirect_uri', redirectUri);
    authorizeUrl.searchParams.set('scope', 'openid profile email');
    authorizeUrl.searchParams.set('state', state);
    res.redirect(authorizeUrl.toString());
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

router.post('/callback', async (req, res) => {
  const { code, state } = req.body || {};
  if (!code || !state) return res.status(400).json({ error: 'Authorization code and state are required' });

  try {
    const settings = await getSettings(req.db);
    if (!isValidIssuerUrl(settings.OIDC_ISSUER_URL)) return res.status(400).json({ error: 'Invalid OIDC configuration' });
    const stateClaims = jwt.verify(state, settings.JWT_SECRET, { algorithms: ['HS256'] });
    if (stateClaims.purpose !== 'oidc-state') return res.status(400).json({ error: 'Invalid OIDC state' });

    const redirectUri = `${settings.FRONTEND_URL}/callback`;
    const tokenData = await exchangeCodeForToken(code, redirectUri, settings);
    const userInfo = await getUserInfo(tokenData.access_token, settings);
    if (!userInfo || !userInfo.sub) return res.status(401).json({ error: 'OIDC subject is missing' });

    const issuer = settings.OIDC_ISSUER_URL;
    const tenant = await defaultTenant(req.db);
    let user = await dbGet(
      req.db,
      'SELECT * FROM users WHERE tenant_id = ? AND oidc_issuer = ? AND oidc_subject = ?',
      [tenant.id, issuer, userInfo.sub]
    );

    if (!user) {
      const email = userInfo.email || userInfo.preferred_username || null;
      const baseUsername = String(userInfo.preferred_username || userInfo.name || email || `oidc-${userInfo.sub}`).slice(0, 100);
      const collision = await dbGet(req.db, 'SELECT id FROM users WHERE username = ?', [baseUsername]);
      const username = collision ? `${baseUsername}-${crypto.randomBytes(4).toString('hex')}` : baseUsername;
      const roles = JSON.stringify(['viewer']);
      const inserted = await dbRun(
        req.db,
        `INSERT INTO users (tenant_id, username, email, role, roles, password_hash, auth_provider, oidc_issuer, oidc_subject)
         VALUES (?, ?, ?, 'Viewer', ?, NULL, 'oidc', ?, ?)`,
        [tenant.id, username, email, roles, issuer, userInfo.sub]
      );
      user = await dbGet(req.db, 'SELECT * FROM users WHERE tenant_id = ? AND id = ?', [tenant.id, inserted.lastID]);
      await auditLog(req.db, {
        tenant_id: tenant.id,
        actor: user,
        event_name: 'user_created',
        status: 'success',
        metadata: { provider: 'oidc', self_provisioned: true }
      });
    } else {
      const email = userInfo.email || user.email;
      const username = userInfo.preferred_username || userInfo.name || user.username;
      await dbRun(
        req.db,
        'UPDATE users SET email = ?, username = ? WHERE tenant_id = ? AND id = ?',
        [email, username, tenant.id, user.id]
      );
      user = { ...user, email, username };
    }

    return completeLogin(req, res, user, 'sso', settings);
  } catch (err) {
    console.error('OIDC callback error:', err.message);
    return res.status(401).json({ error: 'Failed to authenticate via SSO' });
  }
});

router.get('/config', async (req, res) => {
  try {
    const settings = await getSettings(req.db);
    res.json({
      ssoEnabled: settings.SSO_ENABLED === 'true',
      clientId: settings.OIDC_CLIENT_ID,
      authorizeUrl: isValidIssuerUrl(settings.OIDC_ISSUER_URL) ? `${settings.OIDC_ISSUER_URL.replace(/\/$/, '')}/authorize/` : '',
      frontendUrl: settings.FRONTEND_URL
    });
  } catch {
    res.status(500).json({ error: 'Failed to load configuration' });
  }
});

router.post('/local-login', async (req, res) => {
  const { username, password } = req.body || {};
  try {
    const settings = await getSettings(req.db);
    const user = await dbGet(req.db, 'SELECT * FROM users WHERE username = ? AND auth_provider = ?', [username, 'local']);
    if (!user || !bcrypt.compareSync(String(password || ''), user.password_hash || '')) {
      if (user && user.tenant_id) {
        await auditLog(req.db, {
          tenant_id: user.tenant_id,
          actor: user,
          event_name: 'login',
          status: 'failure',
          metadata: { provider: 'local', ip: req.ip }
        });
      }
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    return completeLogin(req, res, user, 'local', settings);
  } catch (err) {
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

router.post('/setup-mfa', async (req, res) => {
  const { tempToken } = req.body || {};
  if (!tempToken) return res.status(400).json({ error: 'Missing token' });
  try {
    const settings = await getSettings(req.db);
    const decoded = jwt.verify(tempToken, settings.JWT_SECRET, { algorithms: ['HS256'] });
    if (!decoded.mfaPending || !decoded.tenant_id) return res.status(400).json({ error: 'Invalid token' });
    const user = await dbGet(req.db, 'SELECT id, tenant_id, username FROM users WHERE id = ? AND tenant_id = ?', [decoded.id, decoded.tenant_id]);
    if (!user) return res.status(401).json({ error: 'User not found' });
    const secret = generateSecret();
    const otpauth = generateURI({ accountName: user.username, issuer: 'ThreatDock', secret });
    const qrCodeUrl = await qrcode.toDataURL(otpauth);
    await dbRun(req.db, 'UPDATE users SET mfa_secret = ?, mfa_enabled = 0 WHERE id = ? AND tenant_id = ?', [secret, user.id, user.tenant_id]);
    await auditLog(req.db, { tenant_id: user.tenant_id, actor: user, event_name: 'mfa_setup', status: 'success' });
    return res.json({ secret, qrCodeUrl });
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
});

router.post('/verify-mfa', async (req, res) => {
  const { tempToken, code } = req.body || {};
  if (!tempToken || !code) return res.status(400).json({ error: 'Missing token or code' });
  try {
    const settings = await getSettings(req.db);
    const decoded = jwt.verify(tempToken, settings.JWT_SECRET, { algorithms: ['HS256'] });
    if (!decoded.mfaPending || !decoded.tenant_id) return res.status(400).json({ error: 'Invalid token' });
    const user = await dbGet(req.db, 'SELECT * FROM users WHERE id = ? AND tenant_id = ?', [decoded.id, decoded.tenant_id]);
    if (!user || !user.mfa_secret) return res.status(400).json({ error: 'MFA not configured for this user' });
    if (!verifyMfaCode(code, user.mfa_secret)) {
      await auditLog(req.db, { tenant_id: user.tenant_id, actor: user, event_name: 'mfa_verify', status: 'failure' });
      return res.status(401).json({ error: 'Invalid MFA code' });
    }
    if (!user.mfa_enabled) await dbRun(req.db, 'UPDATE users SET mfa_enabled = 1 WHERE id = ? AND tenant_id = ?', [user.id, user.tenant_id]);
    await auditLog(req.db, { tenant_id: user.tenant_id, actor: user, event_name: 'mfa_verify', status: 'success' });
    await auditLog(req.db, { tenant_id: user.tenant_id, actor: user, event_name: 'login', status: 'success', metadata: { provider: decoded.type || 'local', mfa: true } });
    return res.json({
      access_token: signAccessToken(user, decoded.type || 'local', settings.JWT_SECRET),
      user: { name: user.username, role: user.role, roles: normalizeRoles(user.roles) }
    });
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
});

router.post('/logout', async (req, res) => {
  try {
    const settings = await getSettings(req.db);
    const header = req.headers.authorization || '';
    if (!header.startsWith('Bearer ')) return res.status(401).json({ error: 'Authentication required' });
    const decoded = jwt.verify(header.slice(7), settings.JWT_SECRET, { algorithms: ['HS256'] });
    const user = await dbGet(req.db, 'SELECT * FROM users WHERE id = ? AND tenant_id = ?', [decoded.id, decoded.tenant_id]);
    if (!user) return res.status(401).json({ error: 'Invalid token' });
    await auditLog(req.db, { tenant_id: user.tenant_id, actor: user, event_name: 'logout', status: 'success' });
    return res.status(204).end();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

module.exports = router;
module.exports.isValidIssuerUrl = isValidIssuerUrl;
module.exports.userClaims = userClaims;
