const express = require('express');
const bcrypt = require('bcryptjs');

module.exports = function(db) {
  const router = express.Router();

  // Middleware to ensure user is Admin
  const requireAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'Admin') {
      return next();
    }
    return res.status(403).json({ error: 'Requires Admin role' });
  };

  // GET /api/users
  router.get('/', requireAdmin, (req, res) => {
    db.all('SELECT id, username, email, role, created_at FROM users', [], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    });
  });

  // POST /api/users
  router.post('/', requireAdmin, (req, res) => {
    const { username, password, email, role } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    const hash = bcrypt.hashSync(password, 10);
    const userRole = role || 'Analyst';
    
    db.run(
      'INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)',
      [username, hash, email, userRole],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(400).json({ error: 'Username already exists' });
          }
          return res.status(500).json({ error: 'Database error' });
        }
        res.json({ id: this.lastID, username, email, role: userRole });
      }
    );
  });


  // PATCH /api/users/:id
  router.patch('/:id', requireAdmin, (req, res) => {
    const id = parseInt(req.params.id, 10);
    const { username, email, role } = req.body;

    if (!username || username.trim() === '') return res.status(400).json({ error: 'Username is required' });
    if (!['Admin', 'Analyst'].includes(role)) return res.status(400).json({ error: 'Invalid role' });

    db.get('SELECT id FROM users WHERE id = ?', [id], (findErr, user) => {
      if (findErr) return res.status(500).json({ error: 'Database error' });
      if (!user) return res.status(404).json({ error: 'User not found' });

      db.run(
        'UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?',
        [username.trim(), email || null, role, id],
        function(updateErr) {
          if (updateErr) {
            if (updateErr.message.includes('UNIQUE')) return res.status(400).json({ error: 'Username already exists' });
            return res.status(500).json({ error: 'Database error' });
          }
          res.json({ success: true, id, username: username.trim(), email: email || null, role });
        }
      );
    });
  });

  // DELETE /api/users/:id
  router.delete('/:id', requireAdmin, (req, res) => {
    const id = req.params.id;
    db.run('DELETE FROM users WHERE id = ?', [id], function(err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true, deleted: this.changes });
    });
  });

  const { generateSecret, generateURI, verify } = require('otplib');
  const qrcode = require('qrcode');

  // POST /api/users/:id/mfa/setup
  router.post('/:id/mfa/setup', async (req, res) => {
    // Allow users to configure their own MFA, or Admins to configure others
    if (req.user.id !== parseInt(req.params.id) && req.user.role !== 'Admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    db.get('SELECT username, email FROM users WHERE id = ?', [req.params.id], async (err, user) => {
      if (err || !user) return res.status(404).json({ error: 'User not found' });

      const secret = generateSecret();
      const otpauth = generateURI({ accountName: user.username, issuer: 'ThreatDock', secret });
      
      try {
        const qrCodeUrl = await qrcode.toDataURL(otpauth);
        
        // Save secret to database
        db.run('UPDATE users SET mfa_secret = ? WHERE id = ?', [secret, req.params.id], function(updateErr) {
          if (updateErr) return res.status(500).json({ error: 'Failed to save MFA secret' });
          res.json({ secret, qrCodeUrl });
        });
      } catch (qrErr) {
        res.status(500).json({ error: 'Failed to generate QR code' });
      }
    });
  });

  // POST /api/users/:id/mfa/enable
  router.post('/:id/mfa/enable', (req, res) => {
    if (req.user.id !== parseInt(req.params.id) && req.user.role !== 'Admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const { code } = req.body;
    db.get('SELECT mfa_secret FROM users WHERE id = ?', [req.params.id], (err, user) => {
      if (err || !user || !user.mfa_secret) return res.status(400).json({ error: 'MFA not configured' });

      const isValid = verify({ token: code, secret: user.mfa_secret });
      if (isValid) {
        db.run('UPDATE users SET mfa_enabled = 1 WHERE id = ?', [req.params.id], (updateErr) => {
          if (updateErr) return res.status(500).json({ error: 'Database error' });
          res.json({ success: true, message: 'MFA successfully enabled' });
        });
      } else {
        res.status(400).json({ error: 'Invalid verification code' });
      }
    });
  });

  return router;
};
