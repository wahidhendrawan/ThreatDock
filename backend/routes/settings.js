const express = require('express');

module.exports = function(db) {
  const router = express.Router();

  // Middleware to ensure user is Admin
  const requireAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'Admin') {
      return next();
    }
    return res.status(403).json({ error: 'Requires Admin role' });
  };

  // GET /api/settings
  router.get('/', (req, res) => {
    db.all('SELECT key, value FROM settings', [], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      const settings = {};
      rows.forEach(r => { settings[r.key] = r.value; });
      res.json(settings);
    });
  });

  // PUT /api/settings
  router.put('/', requireAdmin, (req, res) => {
    const settings = req.body;
    if (!settings || typeof settings !== 'object') {
      return res.status(400).json({ error: 'Invalid settings format' });
    }

    db.serialize(() => {
      db.run("BEGIN TRANSACTION");
      const stmt = db.prepare(`
        INSERT INTO settings (key, value, updated_at) 
        VALUES (?, ?, datetime('now'))
        ON CONFLICT(key) DO UPDATE SET 
          value = excluded.value, 
          updated_at = datetime('now')
      `);
      for (const [key, value] of Object.entries(settings)) {
        stmt.run(key, String(value));
      }
      stmt.finalize();
      db.run("COMMIT", (err) => {
        if (err) return res.status(500).json({ error: 'Failed to save settings' });
        res.json({ message: 'Settings updated successfully' });
      });
    });
  });

  return router;
};
