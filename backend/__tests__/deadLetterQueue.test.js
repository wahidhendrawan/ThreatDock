const { DeadLetterQueue } = require('../services/deadLetterQueue');

// Mock database that captures queries and returns predictable results
function createMockDb() {
  const calls = [];
  return {
    calls,
    query: jest.fn(async (sql, params = []) => {
      calls.push({ sql, params });
      // Simulate DELETE returning rowCount for cleanup
      if (/^\s*DELETE/i.test(sql)) {
        return { rows: [], rowCount: 3 };
      }
      // Simulate SELECT returning sample data
      if (/^\s*SELECT/i.test(sql)) {
        return {
          rows: [
            {
              id: 1,
              source: 'TestSource',
              item_type: 'alert',
              status: 'pending',
              attempt_count: 1
            }
          ]
        };
      }
      return { rows: [], rowCount: 1 };
    })
  };
}

describe('DeadLetterQueue', () => {
  let db;
  let dlq;

  beforeEach(() => {
    db = createMockDb();
    dlq = new DeadLetterQueue(db);
  });

  describe('initialize', () => {
    it('creates dead_letter_queue table and indexes', async () => {
      await dlq.initialize();

      const createTable = db.calls.find(c => /CREATE TABLE IF NOT EXISTS dead_letter_queue/.test(c.sql));
      const idxSourceStatus = db.calls.find(c => /idx_dlq_source_status/.test(c.sql));
      const idxLastAttempt = db.calls.find(c => /idx_dlq_last_attempt/.test(c.sql));

      expect(createTable).toBeTruthy();
      expect(idxSourceStatus).toBeTruthy();
      expect(idxLastAttempt).toBeTruthy();
    });
  });

  describe('add', () => {
    it('inserts a new DLQ item with serialized data', async () => {
      await dlq.add('NVD', 'source_fetch', { retries: 2 }, 'timeout');

      const insertCall = db.calls.find(c => /INSERT INTO dead_letter_queue/.test(c.sql));
      expect(insertCall).toBeTruthy();
      expect(insertCall.params).toContain('NVD');
      expect(insertCall.params).toContain('source_fetch');
      expect(insertCall.params.find(p => typeof p === 'string' && p.includes('retries'))).toBeTruthy();
      expect(insertCall.params).toContain('timeout');
    });

    it('truncates error messages longer than 2000 characters', async () => {
      const longError = 'x'.repeat(3000);
      await dlq.add('TestSource', 'alert', {}, longError);

      const insertCall = db.calls.find(c => /INSERT INTO dead_letter_queue/.test(c.sql));
      const errorParam = insertCall.params.find(p => typeof p === 'string' && p.startsWith('x'));

      expect(errorParam.length).toBe(2000);
    });

    it('does not throw when database query fails', async () => {
      db.query = jest.fn(async () => {
        throw new Error('db connection failed');
      });

      // Should log but not throw
      await expect(dlq.add('TestSource', 'alert', {}, 'error')).resolves.toBeUndefined();
    });
  });

  describe('recordRetry', () => {
    it('increments attempt_count and updates last_attempt', async () => {
      await dlq.recordRetry(42, 'still failing');

      const updateCall = db.calls.find(c => /UPDATE dead_letter_queue/.test(c.sql) && /attempt_count = attempt_count \+ 1/.test(c.sql));
      expect(updateCall).toBeTruthy();
      expect(updateCall.params).toContain('still failing');
      expect(updateCall.params).toContain(42);
    });
  });

  describe('resolve', () => {
    it('marks item as resolved with user and notes', async () => {
      await dlq.resolve(10, 'admin@example.com', 'fixed by operator');

      const updateCall = db.calls.find(c => /UPDATE dead_letter_queue/.test(c.sql) && /status = 'resolved'/.test(c.sql));
      expect(updateCall).toBeTruthy();
      expect(updateCall.params).toContain('admin@example.com');
      expect(updateCall.params).toContain('fixed by operator');
      expect(updateCall.params).toContain(10);
    });
  });

  describe('markFailed', () => {
    it('marks item as permanently failed with reason', async () => {
      await dlq.markFailed(15, 'source deprecated');

      const updateCall = db.calls.find(c => /status = 'failed'/.test(c.sql));
      expect(updateCall).toBeTruthy();
      expect(updateCall.params).toContain('source deprecated');
      expect(updateCall.params).toContain(15);
    });
  });

  describe('getPending', () => {
    it('returns pending items for a source', async () => {
      const results = await dlq.getPending('TestSource', 50);

      const selectCall = db.calls.find(c => /SELECT id, source/.test(c.sql));
      expect(selectCall).toBeTruthy();
      expect(selectCall.params).toContain('TestSource');
      expect(selectCall.params).toContain(50);
      expect(Array.isArray(results)).toBe(true);
    });
  });

  describe('getAll', () => {
    it('applies source and status filters', async () => {
      await dlq.getAll({ source: 'NVD', status: 'pending', limit: 25 });

      const selectCall = db.calls.find(c => /FROM dead_letter_queue/.test(c.sql));
      expect(selectCall).toBeTruthy();
      expect(selectCall.params).toContain('NVD');
      expect(selectCall.params).toContain('pending');
      expect(selectCall.params).toContain(25);
    });

    it('returns items without filters when none provided', async () => {
      await dlq.getAll();

      const selectCall = db.calls.find(c => /FROM dead_letter_queue/.test(c.sql));
      expect(selectCall).toBeTruthy();
      // Only limit should be in params
      expect(selectCall.params).toEqual([100]);
    });
  });

  describe('getStats', () => {
    it('returns grouped statistics', async () => {
      await dlq.getStats();

      const selectCall = db.calls.find(c => /GROUP BY source, status/.test(c.sql));
      expect(selectCall).toBeTruthy();
    });
  });

  describe('cleanup', () => {
    it('deletes old resolved and failed items', async () => {
      const deleted = await dlq.cleanup(30);

      const deleteCall = db.calls.find(c => /DELETE FROM dead_letter_queue/.test(c.sql));
      expect(deleteCall).toBeTruthy();
      expect(deleteCall.params).toContain(30);
      expect(deleted).toBe(3);
    });
  });
});
