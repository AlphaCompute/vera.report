import { test as base, expect, type Page, type BrowserContext } from '@playwright/test';

type StorageState = Awaited<ReturnType<BrowserContext['storageState']>>;

/** Fresh Universal Login; successful return must match the configured application origin. */
export async function loginAsAdminViaUniversalLogin(page: Page, baseURL: string): Promise<void> {
  const email = process.env.QA_ADMIN_EMAIL;
  const password = process.env.QA_ADMIN_PASSWORD;
  if (!email || !password) {
    throw new Error('QA_ADMIN_EMAIL / QA_ADMIN_PASSWORD are required for admin tests');
  }
  const target = new URL('/legal/organizations', baseURL);
  const isAdmin = () => {
    const current = new URL(page.url());
    return current.origin === target.origin && current.pathname === target.pathname;
  };
  await page.goto(new URL('/auth/login?returnTo=/legal/organizations', baseURL).href, { waitUntil: 'domcontentloaded' });
  await page.locator('input[name="username"], input[type="email"]').filter({ visible: true }).first().fill(email);
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  await page.locator('input[name="password"], input[type="password"]').filter({ visible: true }).first().fill(password);
  await page.getByRole('button', { name: /^(continue|log ?in|sign ?in)$/i }).first().click();

  const consent = page.getByRole('button', { name: /^(accept|authorize|allow)$/i });
  await expect.poll(async () => isAdmin() || await consent.isVisible(), {
    timeout: 30_000, message: 'Login must return to this application or present consent',
  }).toBe(true);
  if (!isAdmin()) await consent.click();
  await page.waitForURL(url => url.origin === target.origin && url.pathname === target.pathname, { timeout: 30_000 });
  const response = await page.context().request.get(new URL('/api/admin/me', baseURL).href);
  expect(response.status(), 'The authenticated admin API must accept the fresh session').toBe(200);
  const identity = await response.json();
  expect(Array.isArray(identity.roles), 'Admin roles must be an array').toBe(true);
  expect(identity.roles, 'The authenticated account must have the exact admin role').toContain('admin');
  expect(typeof identity.email, 'The authenticated account must include an email').toBe('string');
  expect(identity.email.trim().toLowerCase(), 'The session must belong to the requested QA account').toBe(email.trim().toLowerCase());
}

type AdminTestFixtures = { adminContext: BrowserContext; adminPage: Page };
type AdminWorkerFixtures = { adminStorageState: StorageState };

export const test = base.extend<AdminTestFixtures, AdminWorkerFixtures>({
  adminStorageState: [async ({ browser }, use, workerInfo) => {
    const baseURL = workerInfo.project.use.baseURL;
    if (!baseURL) throw new Error('Admin tests require a configured baseURL');
    const context = await browser.newContext({ baseURL, ignoreHTTPSErrors: false });
    try {
      await loginAsAdminViaUniversalLogin(await context.newPage(), baseURL);
      await use(await context.storageState());
    } finally {
      await context.close();
    }
  }, { scope: 'worker' }],
  adminContext: async ({ browser, adminStorageState, baseURL }, use) => {
    const context = await browser.newContext({ baseURL, storageState: adminStorageState, ignoreHTTPSErrors: false });
    try { await use(context); } finally { await context.close(); }
  },
  adminPage: async ({ adminContext }, use) => { await use(await adminContext.newPage()); },
});
export { expect };
