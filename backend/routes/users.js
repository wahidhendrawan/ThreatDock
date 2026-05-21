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

  // DELETE /api/users/:id
  router.delete('/:id', requireAdmin, (req, res) => {
    const id = req.params.id;
    db.run('DELETE FROM users WHERE id = ?', [id], function(err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true, deleted: this.changes });
    });
  });

  return router;
};
