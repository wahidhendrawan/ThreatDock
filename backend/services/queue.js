/**
 * Job queue with optional Redis backing.
 * Uses in-memory EventEmitter by default; switches to Bull when REDIS_URL is set.
 */

const EventEmitter = require('events');

const redisUrl = process.env.REDIS_URL || '';

// Lazy BullQueue initialization — called on first `.get()` when Redis is configured
let BullQueue = null;
let bullInitAttempted = false;
function getBullQueue() {
  if (bullInitAttempted) return BullQueue;
  bullInitAttempted = true;
  if (!redisUrl) return null;
  try {
    BullQueue = require('bull');
  } catch (e) {
    console.warn('Bull not available, using in-memory queue');
  }
  return BullQueue;
}

// In-memory queue implementation
class MemoryQueue {
  constructor(name) {
    this.name = name;
    this.buffer = [];
    this.handler = null;
    this.active = 0;
    this.concurrency = 5;
  }

  async add(data) {
    if (this.handler) {
      this._run(data);
    } else {
      this.buffer.push(data);
    }
  }

  process(handler) {
    this.handler = handler;
    const pending = this.buffer.splice(0);
    for (const data of pending) {
      this._run(data);
    }
  }

  async _run(data) {
    if (!this.handler || this.active >= this.concurrency) return;
    this.active++;
    try {
      await this.handler({ data });
    } catch (err) {
      console.error(`Queue ${this.name} job failed:`, err.message);
    } finally {
      this.active--;
    }
  }

  onCompleted() {}
  onFailed() {}
  async close() {}
}

// Bull-backed queue wrapper (only constructed when Redis is available)
class RedisJobQueue {
  constructor(name) {
    this.name = name;
    this.queue = new BullQueue(name, redisUrl);
    this.queue.on('error', (err) => {
      if (err.message !== 'connect ECONNREFUSED' && err.message !== 'connect ENETUNREACH') {
        console.error(`Bull queue ${name} error:`, err.message);
      }
    });
  }

  async add(data) {
    await this.queue.add(data, { removeOnComplete: true, attempts: 2, backoff: 5000 });
  }

  process(handler) {
    this.queue.process(async (job) => {
      await handler({ data: job.data });
    });
  }

  onCompleted(callback) {
    this.queue.on('completed', (job) => callback({ data: job.data, result: job.returnvalue }));
  }

  onFailed(callback) {
    this.queue.on('failed', (job, err) => callback({ data: job.data, error: err }));
  }

  async close() {
    await this.queue.close();
  }
}

class JobQueue {
  constructor() {
    this.queues = {};
  }

  get(name) {
    if (!this.queues[name]) {
      const useBull = getBullQueue();
      this.queues[name] = useBull ? new RedisJobQueue(name) : new MemoryQueue(name);
    }
    return this.queues[name];
  }

  async closeAll() {
    for (const q of Object.values(this.queues)) {
      await q.close();
    }
  }
}

// Global in-memory cache
const cacheStore = {};
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

const cache = {
  async get(key) {
    const entry = cacheStore[key];
    if (!entry) return null;
    if (Date.now() > entry.expires) {
      delete cacheStore[key];
      return null;
    }
    return entry.value;
  },

  async set(key, value, ttlMs = CACHE_TTL) {
    cacheStore[key] = { value, expires: Date.now() + ttlMs };
  },

  async del(key) {
    delete cacheStore[key];
  },

  async flush() {
    Object.keys(cacheStore).forEach(k => delete cacheStore[k]);
  }
};

module.exports = { JobQueue, cache };
