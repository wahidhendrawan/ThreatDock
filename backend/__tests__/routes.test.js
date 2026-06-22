/**
 * Route module integration tests — validates that route modules
 * can be loaded without errors and return proper factory functions.
 */
const path = require('path');
const fs = require('fs');

describe('Route modules', () => {
  const routeDir = path.resolve(__dirname, '../routes');
  const routeFiles = fs.readdirSync(routeDir).filter(f => f.endsWith('.js'));

  test.each(routeFiles)('%s loads as a function', (file) => {
    const mod = require(path.join(routeDir, file));
    expect(typeof mod).toBe('function');
  });
});

describe('Service modules', () => {
  const svcDir = path.resolve(__dirname, '../services');
  const svcFiles = fs.readdirSync(svcDir).filter(f => f.endsWith('.js') && !f.includes('database'));

  test.each(svcFiles)('%s loads without error', (file) => {
    const mod = require(path.join(svcDir, file));
    expect(mod).toBeDefined();
    expect(typeof mod).toBe('object');
  });
});

describe('Middleware modules', () => {
  const midDir = path.resolve(__dirname, '../middleware');
  const midFiles = fs.readdirSync(midDir).filter(f => f.endsWith('.js'));

  test.each(midFiles)('%s loads without error', (file) => {
    const mod = require(path.join(midDir, file));
    expect(typeof mod).toBe('function');
  });
});

describe('Config validation', () => {
  test('package.json has required scripts', () => {
    const pkg = require('../package.json');
    expect(pkg.scripts).toBeDefined();
    expect(pkg.scripts.start).toBeDefined();
  });

  test('Dockerfile exists', () => {
    expect(fs.existsSync(path.resolve(__dirname, '../Dockerfile'))).toBe(true);
  });
});
