import { expect, test } from '@playwright/test';

// The local config builds with confidential mode on. Pages keep their security
// headers, and protected data still requires identity and organization-key authorization.
const paths = ['/legal', '/legal/keys', '/legal/administration', '/legal/enroll', '/legal/report'];
for (const path of paths) {
  test(`${path} retains strict headers in confidential mode`, async ({ page }) => {
    await page.route('**/api/monitoring/client', route => route.fulfill({ status: 204 }));
    const response = await page.goto(path);
    const headers = response!.headers();
    expect(headers['content-security-policy']).toMatch(/script-src 'self' 'nonce-[A-Za-z0-9+/=]+'/);
    expect(headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(headers['content-security-policy']).toContain("object-src 'none'");
    if (process.env.VERA_QA_PRODUCTION === '1') expect(headers['cache-control']).toBe('private, no-store');
    expect(headers['referrer-policy']).toBe('no-referrer');
    await expect(page.getByText('The legal portal is not available on this site.')).toHaveCount(0);
    await expect(page.getByRole('heading').first()).toBeVisible();
    await expect(page.getByRole('button', { name: 'Open report', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /^Download file/ })).toHaveCount(0);
  });
}

test('an invitation secret is consumed locally without leaking into requests', async ({ page }) => {
  const token = 'q'.repeat(43), sent: string[] = [];
  page.on('request', request => sent.push(request.url(), request.postData() ?? ''));
  await page.route('**/api/monitoring/client', route => route.fulfill({ status: 204 }));
  await page.goto(`/legal/enroll#invitation=${token}`);
  await expect(page).toHaveURL(/\/legal\/enroll$/);
  expect(sent.join('\n')).not.toContain(token);
  await expect(page.getByRole('button', { name: 'Open report', exact: true })).toHaveCount(0);
});
