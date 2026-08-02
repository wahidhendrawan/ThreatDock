
/**
 * Tenant isolation tests.
 *
 * These tests verify that route handlers scope their database queries by
 * req.tenant_id and that the requireRole middleware enforces access. Because
 * the production database adapter is PostgreSQL, we use a mock db and assert
 * the SQL and parameters passed to it. This gives a portable test that runs
 * anywhere without external services.
 */

const express = require('express');
const { requireRole } = require('../services/identity');

function makeMockDb() {
  return {
    all: jest.fn((sql, params, cb) => cb(null, [])),
    get: jest.fn((sql, params, cb) => cb(null, null)),
    run: jest.fn((sql, params, cb) => {
      if (typeof cb === 'function') cb(null);
    }),
    query: jest.fn().mockResolvedValue({ rows: [] }),
    prepare: jest.fn().mockReturnValue({
      run: jest.fn(),
      finalize: jest.fn()
    })
  };
}

function makeReq(tenantId, roles = ['viewer'], extras = {}) {
  return {
    tenant_id: tenantId,
    user: { id: 1, tenant_id: tenantId, roles },
    query: {},
    body: {},
    params: {},
    ...extras
  };
}

function makeRes() {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  res.send = jest.fn().mockReturnValue(res);
  res.set = jest.fn().mockReturnValue(res);
  return res;
}

describe('Tenant Isolation - alerts route', () => {
  let db;
  let router;

  beforeEach(() => {
    db = makeMockDb();
    router = require('../routes/alerts')(db);
  });

  it('GET /api/alerts should scope query to req.tenant_id', (done) => {
    const req = makeReq(42);
    const res = makeRes();

    // Simulate calling the GET / handler directly via router.handle
    db.all = jest.fn((sql, params, cb) => {
      try {
        expect(sql).toContain('tenant_id = ?');
        expect(params[0]).toBe(42);
        cb(null, []);
        done();
      } catch (err) {
        done(err);
      }
    });

    // Find and invoke the GET / handler
    const layers = router.stack.filter(l => l.route && l.route.path === '/');
    const layer = layers.find(l => l.route.methods.get);
    // requireRole is the first middleware, handler is the last
    const stackHandlers = layer.route.stack;
    // Call requireRole first
    stackHandlers[0].handle(req, res, () => {
      // Then the actual handler
      stackHandlers[1].handle(req, res, () => {});
    });
  });

  it('GET /api/alerts/:id/history should filter audit_logs by tenant_id', (done) => {
    const req = makeReq(99, ['viewer'], { params: { id: '5' } });
    const res = makeRes();

    db.all = jest.fn((sql, params, cb) => {
      try {
        expect(sql).toContain('tenant_id = ?');
        expect(params[0]).toBe(99);
        cb(null, []);
        done();
      } catch (err) {
        done(err);
      }
    });

    const layers = router.stack.filter(l => l.route && l.route.path === '/:id/history');
    const layer = layers.find(l => l.route.methods.get);
    const stackHandlers = layer.route.stack;
    stackHandlers[0].handle(req, res, () => {
      stackHandlers[1].handle(req, res, () => {});
    });
  });
});

describe('Tenant Isolation - vendors route', () => {
  let db;
  let router;

  beforeEach(() => {
    db = makeMockDb();
    router = require('../routes/vendors')(db);
  });

  it('GET /api/vendors should scope query to req.tenant_id', (done) => {
    const req = makeReq(7);
    const res = makeRes();

    db.all = jest.fn((sql, params, cb) => {
      try {
        expect(sql).toContain('tenant_id = ?');
        expect(params).toEqual([7]);
        cb(null, []);
        done();
      } catch (err) {
        done(err);
      }
    });

    const layers = router.stack.filter(l => l.route && l.route.path === '/');
    const layer = layers.find(l => l.route.methods.get);
    const stackHandlers = layer.route.stack;
    stackHandlers[0].handle(req, res, () => {
      stackHandlers[1].handle(req, res, () => {});
    });
  });
});

describe('Tenant Isolation - threatHunting route', () => {
  let db;
  let router;

  beforeEach(() => {
    db = makeMockDb();
    router = require('../routes/threatHunting')(db);
  });

  it('GET /api/hunt/history should filter hunt_queries by tenant_id', (done) => {
    const req = makeReq(3);
    const res = makeRes();

    db.all = jest.fn((sql, params, cb) => {
      try {
        expect(sql).toContain('tenant_id = ?');
        expect(params[0]).toBe(3);
        cb(null, []);
        done();
      } catch (err) {
        done(err);
      }
    });

    const layers = router.stack.filter(l => l.route && l.route.path === '/history');
    const layer = layers.find(l => l.route.methods.get);
    const stackHandlers = layer.route.stack;
    stackHandlers[0].handle(req, res, () => {
      stackHandlers[1].handle(req, res, () => {});
    });
  });
});

describe('RBAC enforcement via requireRole', () => {
  let db;

  beforeEach(() => {
    db = makeMockDb();
  });

  it('rejects viewer trying to mutate vendors (POST requires editor)', () => {
    const router = require('../routes/vendors')(db);
    const req = makeReq(1, ['viewer']);
    req.body = { name: 'Acme' };
    const res = makeRes();

    const layers = router.stack.filter(l => l.route && l.route.path === '/');
    const layer = layers.find(l => l.route.methods.post);
    const stackHandlers = layer.route.stack;
    stackHandlers[0].handle(req, res, () => {});

    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('rejects editor trying to delete a vendor (requires admin)', () => {
    const router = require('../routes/vendors')(db);
    const req = makeReq(1, ['editor'], { params: { id: '1' } });
    const res = makeRes();

    const layers = router.stack.filter(l => l.route && l.route.path === '/:id');
    const layer = layers.find(l => l.route.methods.delete);
    const stackHandlers = layer.route.stack;
    stackHandlers[0].handle(req, res, () => {});

    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('allows admin to delete a vendor', () => {
    const router = require('../routes/vendors')(db);
    const req = makeReq(1, ['admin'], { params: { id: '5' } });
    const res = makeRes();
    let nextCalled = false;

    const layers = router.stack.filter(l => l.route && l.route.path === '/:id');
    const layer = layers.find(l => l.route.methods.delete);
    const stackHandlers = layer.route.stack;
    stackHandlers[0].handle(req, res, () => { nextCalled = true; });

    expect(nextCalled).toBe(true);
    expect(res.status).not.toHaveBeenCalledWith(403);
  });

  it('rejects unauthenticated requests to protected routes', () => {
    const router = require('../routes/alerts')(db);
    const req = { query: {}, body: {}, params: {} }; // no user
    const res = makeRes();

    const layers = router.stack.filter(l => l.route && l.route.path === '/');
    const layer = layers.find(l => l.route.methods.get);
    const stackHandlers = layer.route.stack;
    stackHandlers[0].handle(req, res, () => {});

    expect(res.status).toHaveBeenCalledWith(401);
  });
});

describe('Cross-tenant data leakage prevention', () => {
  it('should not return data from other tenants when tenant_id filter is applied', (done) => {
    // Simulate a mock db that returns different rows depending on tenant_id
    const dataByTenant = {
      1: [{ id: 1, tenant_id: 1, title: 'Alert for tenant 1' }],
      2: [{ id: 2, tenant_id: 2, title: 'Alert for tenant 2' }]
    };

    const db = makeMockDb();
    db.all = jest.fn((sql, params, cb) => {
      // Enforce that tenant_id filter is in the SQL
      expect(sql).toMatch(/tenant_id\s*=\s*\?/);
      const tenantId = params.find(p => Object.keys(dataByTenant).includes(String(p)));
      cb(null, dataByTenant[tenantId] || []);
    });

    const router = require('../routes/alerts')(db);
    const req = makeReq(1);
    const res = makeRes();
    res.json = jest.fn((rows) => {
      try {
        expect(rows).toHaveLength(1);
        expect(rows[0].tenant_id).toBe(1);
        expect(rows[0].title).toBe('Alert for tenant 1');
        done();
      } catch (err) {
        done(err);
      }
    });

    const layers = router.stack.filter(l => l.route && l.route.path === '/');
    const layer = layers.find(l => l.route.methods.get);
    const stackHandlers = layer.route.stack;
    stackHandlers[0].handle(req, res, () => {
      stackHandlers[1].handle(req, res, () => {});
    });
  });
});
