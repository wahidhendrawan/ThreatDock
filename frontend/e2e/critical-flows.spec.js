const { test, expect } = require('@playwright/test');

test('liveness probe is reachable through the frontend proxy', async ({ request }) => {
  const response = await request.get('/healthz');

  expect(response.status()).toBe(200);
  expect(await response.text()).toBe('OK');
  expect(response.headers()['x-request-id']).toBeTruthy();
});

test('unauthenticated users see the local login form', async ({ page }) => {
  await page.goto('/');

  await expect(page.getByRole('heading', { name: 'ThreatDock' })).toBeVisible();
  await expect(page.getByLabel('Username')).toBeVisible();
  await expect(page.getByLabel('Password')).toHaveAttribute('type', 'password');
  await expect(page.getByRole('button', { name: 'Sign In' })).toBeVisible();
});

test('self-hosted Swagger UI and OpenAPI specification are reachable', async ({ page, request }) => {
  const spec = await request.get('/api/docs.json');
  expect(spec.ok()).toBeTruthy();
  expect((await spec.json()).openapi).toBe('3.0.0');

  await page.goto('/api/docs');
  // Swagger UI renders the title inside an <h2> element - wait for it to load
  await expect(page.locator('h2.title, .info h2, .info .title').first()).toBeVisible({ timeout: 10000 });
});

test('configured local administrator can sign in and open settings', async ({ page }) => {
  test.skip(!process.env.E2E_USERNAME || !process.env.E2E_PASSWORD, 'Set E2E_USERNAME and E2E_PASSWORD to run authenticated flow.');

  await page.goto('/');
  await page.getByLabel('Username').fill(process.env.E2E_USERNAME);
  await page.getByLabel('Password').fill(process.env.E2E_PASSWORD);
  await page.getByRole('button', { name: 'Sign In' }).click();

  await expect(page.getByRole('heading', { name: 'Overview Dashboard' })).toBeVisible();
  await page.getByRole('link', { name: 'Settings' }).click();
  await expect(page.getByRole('heading', { name: 'Settings & Management' })).toBeVisible();
});
