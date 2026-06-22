const { cache, JobQueue } = require('../services/queue');

describe('cache', () => {
  beforeEach(async () => {
    await cache.flush();
  });

  test('set and get values', async () => {
    await cache.set('test-key', { foo: 'bar' });
    const result = await cache.get('test-key');
    expect(result).toEqual({ foo: 'bar' });
  });

  test('returns null for missing keys', async () => {
    expect(await cache.get('nonexistent')).toBeNull();
  });

  test('expires entries after TTL', async () => {
    await cache.set('temp', 'value', 10); // 10ms TTL
    expect(await cache.get('temp')).toBe('value');
    await new Promise(r => setTimeout(r, 20));
    expect(await cache.get('temp')).toBeNull();
  });

  test('del removes entries', async () => {
    await cache.set('delete-me', 'value');
    await cache.del('delete-me');
    expect(await cache.get('delete-me')).toBeNull();
  });

  test('flush clears all entries', async () => {
    await cache.set('a', 1);
    await cache.set('b', 2);
    await cache.flush();
    expect(await cache.get('a')).toBeNull();
    expect(await cache.get('b')).toBeNull();
  });
});

describe('JobQueue', () => {
  test('creates memory queues', () => {
    const q = new JobQueue();
    const queue = q.get('test');
    expect(queue).toBeDefined();
    expect(queue.name).toBe('test');
  });

  test('reuses same queue instance for same name', () => {
    const q = new JobQueue();
    expect(q.get('shared')).toBe(q.get('shared'));
  });

  test('processes buffered jobs', (done) => {
    const q = new JobQueue();
    const queue = q.get('buffer-test');
    queue.add({ x: 1 });
    queue.add({ x: 2 });
    const results = [];
    queue.process(async (job) => {
      results.push(job.data.x);
      if (results.length === 2) {
        expect(results).toEqual([1, 2]);
        done();
      }
    });
  });
});
