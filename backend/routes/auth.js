const express = require('express');
const { exchangeCodeForToken, getUserInfo } = require('../services/oauth');

const router = express.Router();

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

// GET /auth/login - Redirects to Authentik authorization endpoint
router.get('/login', async (req, res) => {
  try {
    const settings = await getSettings(req.db);
    const redirectUri = `${settings.FRONTEND_URL}/callback`;
    const authorizeUrl = new URL(`${settings.OIDC_ISSUER_URL}authorize/`);
    authorizeUrl.searchParams.append('client_id', settings.OIDC_CLIENT_ID);
    authorizeUrl.searchParams.append('response_type', 'code');
    authorizeUrl.searchParams.append('redirect_uri', redirectUri);
    authorizeUrl.searchParams.append('scope', 'openid profile email');
    
    res.redirect(authorizeUrl.toString());
  } catch (err) {
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

    // Provide the access token to the frontend
    res.json({
      access_token: tokenData.access_token,
      id_token: tokenData.id_token,
      user: userInfo
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

module.exports = router;
