/**
 * Cache abstraction with in-memory fallback and optional Redis backing.
 *
 * When REDIS_URL is set and the `ioredis` package is available, cache
 * operations round-trip through Redis. Otherwise the same API is served
 * by a bounded LRU map so callers can rely on caching in development
 * and single-node deployments without an external dependency.
 */

const DEFAULT_TTL_MS = 60_000;
const MAX_MEMORY_ENTRIES = 1_000;

let redisClient = null;
let redisReady = false;
const memoryStore = new Map();

function evictIfNeeded() {
  while (memoryStore.size > MAX_MEMORY_ENTRIES) {
    const oldest = memoryStore.keys().next().value;
    memoryStore.delete(oldest);
  }
}

function tryInitRedis() {
  if (redisClient || !process.env.REDIS_URL) return;
  try {
    const IORedis = require('ioredis');
    redisClient = new IORedis(process.env.REDIS_URL, {
      lazyConnect: true,
      maxRetriesPerRequest: 2,
      enableOfflineQueue: false
    });
    redisClient.on('ready', () => { redisReady = true; });
    redisClient.on('error', () => { redisReady = false; });
    redisClient.connect().catch(() => { redisReady = false; });
  } catch {
    redisClient = null;
  }
}

tryInitRedis();

async function get(key) {
  if (redisClient && redisReady) {
    try {
      const raw = await redisClient.get(key);
      return raw ? JSON.parse(raw) : null;
    } catch {
      // fall through to memory
    }
  }
  const entry = memoryStore.get(key);
  if (!entry) return null;
  if (entry.expiresAt && Date.now() > entry.expiresAt) {
    memoryStore.delete(key);
    return null;
  }
  return entry.value;
}

async function set(key, value, ttlMs = DEFAULT_TTL_MS) {
  if (redisClient && redisReady) {
    try {
      await redisClient.set(key, JSON.stringify(value), 'PX', ttlMs);
      return;
    } catch {
      // fall through to memory
    }
  }
  memoryStore.set(key, { value, expiresAt: ttlMs ? Date.now() + ttlMs : null });
  evictIfNeeded();
}

async function del(key) {
  if (redisClient && redisReady) {
    try { await redisClient.del(key); } catch { /* ignore */ }
  }
  memoryStore.delete(key);
}

/**
 * Return the cached value for `key`, or produce a fresh one via `loader()`
 * and store it for `ttlMs`. Concurrent callers with the same key still each
 * call `loader` under memory-only mode; when Redis is present, use it for
 * cross-worker sharing.
 */
async function wrap(key, loader, ttlMs = DEFAULT_TTL_MS) {
  const hit = await get(key);
  if (hit !== null && hit !== undefined) return hit;
  const value = await loader();
  await set(key, value, ttlMs);
  return value;
}

function stats() {
  return {
    backend: redisClient && redisReady ? 'redis' : 'memory',
    memory_entries: memoryStore.size,
    redis_ready: !!(redisClient && redisReady)
  };
}

function resetForTest() {
  memoryStore.clear();
}

module.exports = { get, set, del, wrap, stats, resetForTest };
