/**
 * Simple in-memory rate limiter middleware.
 * Tracks request counts per IP in a sliding window.
 */

const rateStore = new Map();
const CLEANUP_INTERVAL = 60 * 1000; // clean stale entries every 60s

// Periodic cleanup
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateStore.entries()) {
    if (now > entry.resetAt) rateStore.delete(ip);
  }
}, CLEANUP_INTERVAL);

/**
 * Create a rate limiter middleware.
 * @param {number} windowMs - Time window in milliseconds (default 60000)
 * @param {number} max - Max requests per window (default 100)
 * @param {string} message - Error message when rate limited
 */
function rateLimit({ windowMs = 60000, max = 100, message = 'Too many requests' } = {}) {
  return (req, res, next) => {
    // Use X-Forwarded-For when behind proxy, fallback to req.ip
    const forwarded = req.headers['x-forwarded-for'];
    const ip = forwarded ? forwarded.split(',')[0].trim() : (req.ip || req.connection.remoteAddress || 'unknown');
    const now = Date.now();
    let entry = rateStore.get(ip);

    if (!entry || now > entry.resetAt) {
      entry = { count: 1, resetAt: now + windowMs };
      rateStore.set(ip, entry);
      return next();
    }

    entry.count++;
    if (entry.count > max) {
      res.set('Retry-After', Math.ceil((entry.resetAt - now) / 1000).toString());
      return res.status(429).json({ error: message });
    }

    next();
  };
}

module.exports = rateLimit;
