const { validateToken } = require('../services/oauth');
const bcrypt = require('bcryptjs');

module.exports = async function(req, res, next) {
  const db = req.db;
  if (!db) return res.status(500).send('Database not initialized');

  // Load settings into a promise wrapper for convenience
  const getSettings = () => {
    return new Promise((resolve, reject) => {
      db.all('SELECT key, value FROM settings', [], (err, rows) => {
        if (err) return reject(err);
        const settings = {};
        rows.forEach(r => { settings[r.key] = r.value; });
        resolve(settings);
      });
    });
  };

  try {
    const settings = await getSettings();
    const oidcEnabled = settings.SSO_ENABLED === 'true';

    // 1. Check for Bearer Token (SSO / JWT)
    const header = req.headers['authorization'];
    if (header && header.startsWith('Bearer ')) {
      if (!oidcEnabled) {
        return res.status(401).send('SSO is not configured');
      }
      const token = header.substring('Bearer '.length);
      try {
        const decoded = await validateToken(token, settings);
        req.user = { ...decoded, role: 'Analyst' }; // Default role for SSO, could be mapped via claims
        return next();
      } catch (err) {
        console.error('JWT validation error:', err.message);
        return res.status(401).send('Invalid token');
      }
    }

    // 2. Check for Basic Auth (Local Users Table)
    if (header && header.startsWith('Basic ')) {
      const encoded = header.substring('Basic '.length);
      const decoded = Buffer.from(encoded, 'base64').toString();
      const [username, password] = decoded.split(':');

      return db.get('SELECT * FROM users WHERE username = ?', [username], (err, userRow) => {
        if (err || !userRow) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        if (bcrypt.compareSync(password, userRow.password_hash)) {
          req.user = { id: userRow.id, name: userRow.username, email: userRow.email, role: userRow.role };
          return next();
        } else {
          return res.status(401).json({ error: 'Invalid credentials' });
        }
      });
    }

    // No authorization header or unknown format
    return res.status(401).json({ error: 'Authentication required' });
    
  } catch (err) {
    console.error('Auth middleware error:', err);
    return res.status(500).send('Internal Server Error');
  }
};