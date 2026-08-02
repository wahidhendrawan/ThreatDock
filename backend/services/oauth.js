const { outboundHttp: axios } = require('./outboundHttp');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

// Cache jwks clients by issuer URL to avoid creating a new one on every request
const jwksClients = {};

function getJwksClient(issuerUrl) {
  if (!jwksClients[issuerUrl]) {
    jwksClients[issuerUrl] = jwksClient({
      jwksUri: `${issuerUrl}jwks/`,
      cache: true,
      rateLimit: true
    });
  }
  return jwksClients[issuerUrl];
}

function getKey(issuerUrl) {
  return function(header, callback) {
    const client = getJwksClient(issuerUrl);
    client.getSigningKey(header.kid, function(err, key) {
      if (err) {
        console.error('JWKS error:', err.message);
        return callback(err);
      }
      const signingKey = key.publicKey || key.rsaPublicKey;
      callback(null, signingKey);
    });
  };
}

/**
 * Validates an OIDC JWT access token.
 */
function validateToken(token, settings) {
  return new Promise((resolve, reject) => {
    const issuerUrl = settings.OIDC_ISSUER_URL;
    if (!issuerUrl) return reject(new Error('OIDC_ISSUER_URL not configured'));

    jwt.verify(token, getKey(issuerUrl), { issuer: issuerUrl }, (err, decoded) => {
      if (err) {
        return reject(err);
      }
      resolve(decoded);
    });
  });
}

async function discoverEndpoints(issuerUrl) {
  try {
    const discoveryUrl = issuerUrl.endsWith('/') ? 
      `${issuerUrl}.well-known/openid-configuration` : 
      `${issuerUrl}/.well-known/openid-configuration`;
    const response = await axios.get(discoveryUrl, { timeout: 3000 });
    return response.data;
  } catch (err) {
    console.error('OIDC discovery failed:', err.message);
    return null;
  }
}

/**
 * Exchange Authorization Code for Access Token
 */
async function exchangeCodeForToken(code, redirectUri, settings) {
  let tokenUrl = settings.OIDC_ISSUER_URL.endsWith('/') ? `${settings.OIDC_ISSUER_URL}token/` : `${settings.OIDC_ISSUER_URL}/token/`;
  
  const config = await discoverEndpoints(settings.OIDC_ISSUER_URL);
  if (config && config.token_endpoint) {
    tokenUrl = config.token_endpoint;
  }

  const params = new URLSearchParams();
  params.append('grant_type', 'authorization_code');
  params.append('code', code);
  params.append('redirect_uri', redirectUri);
  params.append('client_id', settings.OIDC_CLIENT_ID);
  
  if (settings.OIDC_CLIENT_SECRET) {
    params.append('client_secret', settings.OIDC_CLIENT_SECRET);
  }

  try {
    const response = await axios.post(tokenUrl, params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 10000
    });
    return response.data;
  } catch (error) {
    console.error('Failed to exchange code:', error.response?.data || error.message);
    throw new Error('Token exchange failed');
  }
}

/**
 * Fetch User Info using Access Token
 */
async function getUserInfo(accessToken, settings) {
  let userInfoUrl = settings.OIDC_ISSUER_URL.endsWith('/') ? `${settings.OIDC_ISSUER_URL}userinfo/` : `${settings.OIDC_ISSUER_URL}/userinfo/`;
  
  const config = await discoverEndpoints(settings.OIDC_ISSUER_URL);
  if (config && config.userinfo_endpoint) {
    userInfoUrl = config.userinfo_endpoint;
  }

  try {
    const response = await axios.get(userInfoUrl, {
      headers: { 'Authorization': `Bearer ${accessToken}` },
      timeout: 10000
    });
    return response.data;
  } catch (error) {
    console.error('Failed to fetch user info:', error.message);
    throw new Error('User info fetch failed');
  }
}

module.exports = { validateToken, exchangeCodeForToken, getUserInfo };
