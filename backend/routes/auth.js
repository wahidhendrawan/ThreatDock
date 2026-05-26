const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { generateSecret, generateURI, verifySync } = require('otplib');
const qrcode = require('qrcode');
const { exchangeCodeForToken, getUserInfo } = require('../services/oauth');

const router = express.Router();

const verifyMfaCode = (code, secret) => {
  if (!/^\d{6}$/.test(String(code || ''))) return false;
  const result = verifySync({
    token: String(code),
    secret,
    window: 0
  });
  return Boolean(result && result.valid === true);
};

// Helper to get settings from DB
const getSettings = (db) => {
  return new Promise((resolve, reject) => {
    db.all('SELECT key, value FROM settings', [], (err, rows) => {
      if (err) return reject(err);
      const settings = {};
      rows.forEach(r => { settings[r.key] = r.value; });
      resolve(settings);
    });
  });
};

function isValidIssuerUrl(url) {
  if (typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') return false;
    if (!parsed.hostname || parsed.hostname === 'localhost') return false;
    return parsed.hostname.includes('.');
  } catch {
    return false;
  }
}

// GET /auth/login - Redirects to authorization endpoint via Discovery
router.get('/login', async (req, res) => {
  try {
    const settings = await getSettings(req.db);
    if (!isValidIssuerUrl(settings.OIDC_ISSUER_URL)) {
      return res.status(400).json({ error: 'Invalid or missing OIDC issuer URL' });
    }
    const redirectUri = `${settings.FRONTEND_URL}/callback`;
    
    // Default to a constructed URL
    let authorizeEndpoint = settings.OIDC_ISSUER_URL.endsWith('/') ? 
      `${settings.OIDC_ISSUER_URL}authorize/` : 
      `${settings.OIDC_ISSUER_URL}/authorize/`;

    // Try to discover via well-known configuration
    try {
      const axios = require('axios');
      const discoveryUrl = settings.OIDC_ISSUER_URL.endsWith('/') ? 
        `${settings.OIDC_ISSUER_URL}.well-known/openid-configuration` : 
        `${settings.OIDC_ISSUER_URL}/.well-known/openid-configuration`;
        
      const response = await axios.get(discoveryUrl, { timeout: 3000 });
      if (response.data && typeof response.data.authorization_endpoint === 'string' && isValidIssuerUrl(response.data.authorization_endpoint)) {
        authorizeEndpoint = response.data.authorization_endpoint;
      }
    } catch (discoveryError) {
      console.error('OIDC Discovery failed, using fallback authorize endpoint', discoveryError.message);
    }

    const authorizeUrl = new URL(authorizeEndpoint);
    if (!/^https?:\/\//i.test(authorizeUrl.origin)) {
      return res.status(400).json({ error: 'Invalid OIDC issuer URL' });
    }
    const allowedSchemes = ['https:'];
    if (!allowedSchemes.includes(authorizeUrl.protocol)) {
      return res.status(400).json({ error: 'Invalid OIDC issuer URL protocol' });
    }
    authorizeUrl.searchParams.append('client_id', settings.OIDC_CLIENT_ID);
    authorizeUrl.searchParams.append('response_type', 'code');
    authorizeUrl.searchParams.append('redirect_uri', redirectUri);
    authorizeUrl.searchParams.append('scope', 'openid profile email');
    
    res.redirect(authorizeUrl.toString());
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// POST /auth/callback - Exchanges code for token
router.post('/callback', async (req, res) => {
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ error: 'Authorization code is missing' });
  }

  try {
    const settings = await getSettings(req.db);
    const redirectUri = `${settings.FRONTEND_URL}/callback`;

    const tokenData = await exchangeCodeForToken(code, redirectUri, settings);
    const userInfo = await getUserInfo(tokenData.access_token, settings);

    // Sync SSO user to local database
    const email = userInfo.email || userInfo.preferred_username || userInfo.sub;
    const username = userInfo.preferred_username || userInfo.name || email;
    
    req.db.get('SELECT * FROM users WHERE email = ? OR username = ?', [email, username], (err, user) => {
      if (err) {
        console.error('Database error checking SSO user:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      const generateTokenAndRespond = (dbUser) => {
        const globalMfaRequired = settings.MFA_REQUIRED === 'true';
        const analystMfaRequired = settings.ANALYST_MFA_REQUIRED === 'true' && dbUser.role === 'Analyst';
        const mustUseMfa = dbUser.mfa_enabled || globalMfaRequired || analystMfaRequired;
        const hasConfiguredMfa = Boolean(dbUser.mfa_enabled && dbUser.mfa_secret);

        if (mustUseMfa) {
          const tempToken = jwt.sign({ id: dbUser.id, mfaPending: true }, settings.JWT_SECRET, { expiresIn: '5m' });
          return res.json({
            requiresMfa: true,
            tempToken,
            setupRequired: !hasConfiguredMfa
          });
        }

        const token = jwt.sign(
          { id: dbUser.id, name: dbUser.username, email: dbUser.email, role: dbUser.role, type: 'sso' }, 
          settings.JWT_SECRET, 
          { expiresIn: '8h' }
        );
        res.json({
          access_token: token,
          user: { name: dbUser.username, role: dbUser.role }
        });
      };

      if (user) {
        generateTokenAndRespond(user);
      } else {
        req.db.run(
          'INSERT INTO users (username, email, role, password_hash) VALUES (?, ?, ?, ?)',
          [username, email, 'Analyst', 'sso_managed'],
          function(insertErr) {
            if (insertErr) {
              console.error('Failed to create SSO user:', insertErr);
              return res.status(500).json({ error: 'Failed to create user' });
            }
            generateTokenAndRespond({
              id: this.lastID,
              username,
              email,
              role: 'Analyst'
            });
          }
        );
      }
    });
  } catch (err) {
    console.error('Callback error:', err);
    res.status(500).json({ error: 'Failed to authenticate via SSO' });
  }
});

// GET /auth/config - Return SSO configuration to the frontend
router.get('/config', async (req, res) => {
  try {
    const settings = await getSettings(req.db);
    res.json({
      ssoEnabled: settings.SSO_ENABLED === 'true',
      clientId: settings.OIDC_CLIENT_ID,
      authorizeUrl: `${settings.OIDC_ISSUER_URL}authorize/`,
      frontendUrl: settings.FRONTEND_URL
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load configuration' });
  }
});

// POST /auth/local-login
router.post('/local-login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const settings = await getSettings(req.db);
    req.db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
      if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
      
      if (!bcrypt.compareSync(password, user.password_hash)) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const globalMfaRequired = settings.MFA_REQUIRED === 'true';
      const analystMfaRequired = settings.ANALYST_MFA_REQUIRED === 'true' && user.role === 'Analyst';
      const mustUseMfa = user.mfa_enabled || globalMfaRequired || analystMfaRequired;
      const hasConfiguredMfa = Boolean(user.mfa_enabled && user.mfa_secret);

      if (mustUseMfa) {
        // Return temp token for MFA verification step
        const tempToken = jwt.sign({ id: user.id, mfaPending: true }, settings.JWT_SECRET, { expiresIn: '5m' });
        return res.json({ 
          requiresMfa: true, 
          tempToken, 
          setupRequired: !hasConfiguredMfa
        });
      }

      // No MFA required, generate full token
      const token = jwt.sign(
        { id: user.id, name: user.username, email: user.email, role: user.role, type: 'local' }, 
        settings.JWT_SECRET, 
        { expiresIn: '8h' }
      );
      res.json({ access_token: token, user: { name: user.username, role: user.role } });
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// POST /auth/setup-mfa - Start forced MFA enrollment during login
router.post('/setup-mfa', async (req, res) => {
  const { tempToken } = req.body;
  if (!tempToken) return res.status(400).json({ error: 'Missing token' });

  try {
    const settings = await getSettings(req.db);
    const decoded = jwt.verify(tempToken, settings.JWT_SECRET);
    if (!decoded.mfaPending) return res.status(400).json({ error: 'Invalid token' });

    req.db.get('SELECT id, username FROM users WHERE id = ?', [decoded.id], async (err, user) => {
      if (err || !user) return res.status(401).json({ error: 'User not found' });

      const secret = generateSecret();
      const otpauth = generateURI({ accountName: user.username, issuer: 'ThreatDock', secret });

      try {
        const qrCodeUrl = await qrcode.toDataURL(otpauth);
        req.db.run('UPDATE users SET mfa_secret = ?, mfa_enabled = 0 WHERE id = ?', [secret, user.id], (updateErr) => {
          if (updateErr) return res.status(500).json({ error: 'Failed to save MFA secret' });
          res.json({ secret, qrCodeUrl });
        });
      } catch (qrErr) {
        res.status(500).json({ error: 'Failed to generate QR code' });
      }
    });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
});

// POST /auth/verify-mfa
router.post('/verify-mfa', async (req, res) => {
  const { tempToken, code } = req.body;
  if (!tempToken || !code) return res.status(400).json({ error: 'Missing token or code' });

  try {
    const settings = await getSettings(req.db);
    const decoded = jwt.verify(tempToken, settings.JWT_SECRET);
    if (!decoded.mfaPending) return res.status(400).json({ error: 'Invalid token' });

    req.db.get('SELECT * FROM users WHERE id = ?', [decoded.id], (err, user) => {
      if (err || !user) return res.status(401).json({ error: 'User not found' });
      
      if (!user.mfa_secret) return res.status(400).json({ error: 'MFA not configured for this user' });

      const isValid = verifyMfaCode(code, user.mfa_secret);
      if (!isValid) return res.status(401).json({ error: 'Invalid MFA code' });

      // Ensure MFA is marked enabled since they just successfully logged in
      if (!user.mfa_enabled) {
        req.db.run('UPDATE users SET mfa_enabled = 1 WHERE id = ?', [user.id]);
      }

      const token = jwt.sign(
        { id: user.id, name: user.username, email: user.email, role: user.role, type: 'local' }, 
        settings.JWT_SECRET, 
        { expiresIn: '8h' }
      );
      res.json({ access_token: token, user: { name: user.username, role: user.role } });
    });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
});

module.exports = router;
