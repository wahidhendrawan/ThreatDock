/**
 * Simple in-memory rate limiter middleware.
 * Tracks request counts per IP in a sliding window.
 */

const rateStore = new Map();
const CLEANUP_INTERVAL = 60 * 1000; // clean stale entries every 60s

// Periodic cleanup (unref so Jest can exit cleanly)
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateStore.entries()) {
    if (now > entry.resetAt) rateStore.delete(ip);
  }
}, CLEANUP_INTERVAL).unref();

/**
 * Create a rate limiter middleware.
 * @param {number} windowMs - Time window in milliseconds (default 60000)
 * @param {number} max - Max requests per window (default 100)
 * @param {string} message - Error message when rate limited
 * @param {function} keyFn - Optional function to generate rate limit key from request (defaults to IP)
 */
function rateLimit({ windowMs = 60000, max = 100, message = 'Too many requests', keyFn } = {}) {
  return (req, res, next) => {
    // Use custom keyFn if provided, otherwise fall back to IP-based limiting
    let key;
    if (typeof keyFn === 'function') {
      key = keyFn(req);
    }
    // Fallback to IP if keyFn not provided or returns falsy
    if (!key) {
      const forwarded = req.headers['x-forwarded-for'];
      key = forwarded ? forwarded.split(',')[0].trim() : (req.ip || req.connection.remoteAddress || 'unknown');
    }
    const now = Date.now();
    let entry = rateStore.get(key);

    if (!entry || now > entry.resetAt) {
      entry = { count: 1, resetAt: now + windowMs };
      rateStore.set(key, entry);
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
