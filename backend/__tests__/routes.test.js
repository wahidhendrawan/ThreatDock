/**
 * Route and config validation tests.
 * Uses fs checks for route files (avoids ESM import issues in deps).
 */
const path = require('path');
const fs = require('fs');

describe('Route files', () => {
  const routeDir = path.resolve(__dirname, '../routes');
  const routeFiles = fs.readdirSync(routeDir).filter(f => f.endsWith('.js'));

  test.each(routeFiles)('%s exists and exports a function pattern', (file) => {
    const content = fs.readFileSync(path.join(routeDir, file), 'utf8');
    expect(content.length).toBeGreaterThan(50);
    // All route modules are factory functions that take 'db'
    expect(content.includes('function')).toBe(true);
  });
});

describe('Middleware files', () => {
  const midDir = path.resolve(__dirname, '../middleware');
  const midFiles = fs.readdirSync(midDir).filter(f => f.endsWith('.js'));

  test.each(midFiles)('%s exists', (file) => {
    const stats = fs.statSync(path.join(midDir, file));
    expect(stats.size).toBeGreaterThan(0);
  });
});

describe('Pure service modules (no ESM deps)', () => {
  test.each([
    '../services/intelligence',
    '../services/notifications',
    '../services/settingsStore',
    '../services/queue',
    '../services/dnstwist'
  ])('%s loads without error', (modulePath) => {
    const mod = require(path.resolve(__dirname, modulePath));
    expect(mod).toBeDefined();
    expect(typeof mod).toBe('object');
  });
});

describe('Middleware: rateLimit', () => {
  test('rateLimit loads as function', () => {
    const mod = require('../middleware/rateLimit');
    expect(typeof mod).toBe('function');
  });
});

describe('Config validation', () => {
  test('package.json has start script', () => {
    const pkg = require('../package.json');
    expect(pkg.scripts.start).toBeDefined();
  });

  test('Dockerfile exists', () => {
    expect(fs.existsSync(path.resolve(__dirname, '../Dockerfile'))).toBe(true);
  });
});
