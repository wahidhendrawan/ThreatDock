/*
 * Authentication Middleware
 *
 * This middleware implements simple HTTP Basic authentication for the
 * ThreatDock API.  If environment variables AUTH_USER and AUTH_PASSWORD
 * are not set, authentication is disabled and all requests are allowed.
 *
 * When enabled, requests must include an Authorization header with
 * credentials encoded in the format `Basic base64(username:password)`.
 */

module.exports = function(req, res, next) {
  const user = process.env.AUTH_USER;
  const pass = process.env.AUTH_PASSWORD;
  // If no credentials configured, allow all requests
  if (!user || !pass) {
    return next();
  }
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="ThreatDock"');
    return res.status(401).send('Authentication required');
  }
  try {
    const encoded = header.substring('Basic '.length);
    const decoded = Buffer.from(encoded, 'base64').toString();
    const [username, password] = decoded.split(':');
    if (username === user && password === pass) {
      return next();
    }
  } catch (err) {
    // fall through to unauthorized response
  }
  res.set('WWW-Authenticate', 'Basic realm="ThreatDock"');
  return res.status(401).send('Invalid credentials');
};