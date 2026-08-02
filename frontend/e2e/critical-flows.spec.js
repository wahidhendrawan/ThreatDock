const { test, expect } = require('@playwright/test');

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
  await expect(page.getByText('ThreatDock API', { exact: true })).toBeVisible();
});

test('configured local administrator can sign in and reach the dashboard', async ({ page }) => {
  test.skip(!process.env.E2E_USERNAME || !process.env.E2E_PASSWORD, 'Set E2E_USERNAME and E2E_PASSWORD to run authenticated flow.');

  await page.goto('/');
  await page.getByLabel('Username').fill(process.env.E2E_USERNAME);
  await page.getByLabel('Password').fill(process.env.E2E_PASSWORD);
  await page.getByRole('button', { name: 'Sign In' }).click();

  await expect(page.getByRole('heading', { name: 'Overview Dashboard' })).toBeVisible();
});
