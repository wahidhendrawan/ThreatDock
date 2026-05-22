const { validateToken } = require('../services/oauth');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

module.exports = async function(req, res, next) {
  const db = req.db;
  if (!db) return res.status(500).send('Database not initialized');

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

    const header = req.headers['authorization'];
    
    // 1. Check for Bearer Token (SSO / Local JWT)
    if (header && header.startsWith('Bearer ')) {
      const token = header.substring('Bearer '.length);
      
      // Try local JWT first
      try {
        const decoded = jwt.verify(token, settings.JWT_SECRET);
        if (decoded) {
          req.user = decoded;
          return next();
        }
      } catch (err) {
        // If it's not a local JWT or expired, we will try SSO validation
      }

      // Try SSO JWT validation
      if (oidcEnabled) {
        try {
          const decoded = await validateToken(token, settings);
          const email = decoded.email || decoded.preferred_username || decoded.sub;
          db.get('SELECT id, username, email, role FROM users WHERE email = ? OR username = ?', [email, decoded.preferred_username || decoded.name || email], (dbErr, userRow) => {
            if (dbErr || !userRow) return res.status(401).send('Unauthorized SSO user');
            req.user = { id: userRow.id, name: userRow.username, email: userRow.email, role: userRow.role, type: 'sso' };
            return next();
          });
          return;
        } catch (err) {
          console.error('SSO JWT validation error:', err.message);
        }
      }
      return res.status(401).send('Invalid or expired token');
    }

    // 2. Check for Basic Auth (Local Users Table - Deprecated but kept for legacy API calls)
    if (header && header.startsWith('Basic ')) {
      const encoded = header.substring('Basic '.length);
      const decoded = Buffer.from(encoded, 'base64').toString();
      const [username, password] = decoded.split(':');

      return db.get('SELECT * FROM users WHERE username = ?', [username], (err, userRow) => {
        if (err || !userRow) return res.status(401).json({ error: 'Invalid credentials' });
        
        if (bcrypt.compareSync(password, userRow.password_hash)) {
          req.user = { id: userRow.id, name: userRow.username, email: userRow.email, role: userRow.role };
          return next();
        } else {
          return res.status(401).json({ error: 'Invalid credentials' });
        }
      });
    }

    return res.status(401).json({ error: 'Authentication required' });
  } catch (err) {
    console.error('Auth middleware error:', err);
    return res.status(500).send('Internal Server Error');
  }
};