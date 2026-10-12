import { acknowledgeReportEntry, enterTestContact } from '../support/report-entry';
import { test, expect } from '@playwright/test';
import type { Page, Route } from '@playwright/test';
import { randomBytes } from 'node:crypto';
import { createCaseOwner, createOwnerRecovery } from '../../enclave/src/confidential/recovery';
import { signOwnerStatement } from '../../enclave/src/confidential/authorization';

// Each failure the owner can meet while opening a confidential report gets its
// own message and next step. The backend is synthetic: these checks cover what
// the page tells the reporter, not Nitro attestation itself.
test.beforeEach(async ({ page }) => {
  await page.route('**/api/monitoring/client', route => route.fulfill({ status: 204 }));
});

async function recoveryCode() {
  const owner = await createCaseOwner();
  const checkpoint = await signOwnerStatement({ kind: 'checkpoint', caseId: owner.trust.caseId, revision: 1, keyEpoch: 1,
    previousDigest: null, listingDigest: null, manifestDigest: null, grantDigests: [], releaseDigests: [], issuedAt: Date.now() }, owner.privateKey);
  return (await createOwnerRecovery(owner, checkpoint)).recoveryCode;
}
async function open(page: Page, handler: (route: Route) => Promise<void>) {
  const code = await recoveryCode();
  const sent: string[] = [];
  page.on('request', request => { sent.push(request.url(), request.postData() ?? ''); });
  await page.route('**/api/confidential/**', handler);
  await page.goto('/status');
  await page.locator('#report-id').fill(code);
  await page.getByRole('button', { name: 'Retrieve report status' }).click();
  return { code, sent };
}

test('maintenance: the relay answers but the secure service does not', async ({ page }) => {
  const { code, sent } = await open(page, route => route.fulfill({ status: 503, contentType: 'application/json',
    body: JSON.stringify({ error: 'Secure connection unavailable' }) }));
  const alert = page.getByRole('alert').filter({ hasText: 'temporarily unavailable' });
  await expect(alert.getByRole('heading', { name: 'VERA’s secure service is temporarily unavailable' })).toBeVisible();
  await expect(alert).toContainText('maintenance or an update');
  await expect(alert).not.toContainText('Possible security problem');
  await expect(alert.getByRole('button', { name: 'Try again' })).toBeVisible();
  expect(sent.join('\n')).not.toContain(code.split('.').pop()!);
});

test('offline: nothing reached VERA, and it retries when the connection returns', async ({ page, context }) => {
  let calls = 0;
  await open(page, async route => { calls++; await route.abort('internetdisconnected'); });
  const alert = page.getByRole('alert').filter({ hasText: 'offline' });
  await expect(alert.getByRole('heading', { name: 'You’re offline' })).toBeVisible();
  await expect(alert).toContainText('Check your internet connection');
  const before = calls;
  await context.setOffline(true);
  await context.setOffline(false);
  await expect.poll(() => calls).toBeGreaterThan(before);
});

test('failed attestation is presented as a possible attack with different next steps', async ({ page }) => {
  const { code, sent } = await open(page, async route => {
    if (route.request().url().endsWith('/channel/open')) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
        document: randomBytes(512).toString('base64'), publicKey: randomBytes(32).toString('base64') }) });
    } else await route.fulfill({ status: 503, body: '{}' });
  });
  const alert = page.getByRole('alert').filter({ hasText: 'Possible security problem' });
  await expect(alert.getByRole('heading', { name: 'We could not verify VERA’s secure service' })).toBeVisible();
  await expect(alert).toContainText('someone is interfering with your connection');
  await expect(alert).toContainText('different network');
  await expect(alert.getByRole('button', { name: 'Try again' })).toHaveCount(0);
  // Nothing past the failed check was sent: no channel call, no code.
  expect(sent.filter(item => item.endsWith('/channel/call'))).toEqual([]);
  expect(sent.join('\n')).not.toContain(code.split('.').pop()!);
});

test('failure states fit a phone screen without horizontal scrolling', async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 780 });
  await open(page, async route => {
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
      document: randomBytes(512).toString('base64'), publicKey: randomBytes(32).toString('base64') }) });
  });
  await expect(page.getByRole('heading', { name: 'We could not verify VERA’s secure service' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('before Submit the reporter sees who can see what; a failed verification keeps the editable draft', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const sent: string[] = [];
  page.on('request', request => { sent.push(request.url()); });
  await page.route('**/api/whistleblower/**', route => route.abort());
  await page.route('**/api/confidential/**', async route => {
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
      document: randomBytes(512).toString('base64'), publicKey: randomBytes(32).toString('base64') }) });
  });
  await page.goto('/report');
  await acknowledgeReportEntry(page);
  const description = page.getByPlaceholder('Describe what happened');
  await description.fill('Synthetic confidential QA report.');
  await description.press('Enter');
  await page.getByRole('button', { name: 'Skip', exact: true }).click();
  await page.getByLabel('Email', { exact: true }).fill('synthetic-reporter@example.com');
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  const summary = 'A synthetic summary without identifying details.';
  await page.getByLabel('Summary for legal review').fill(summary);
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  const review = page.getByRole('region', { name: 'Review your report', exact: true });
  await expect(review.getByText('VERA administrators and legal organizations can read this text.', { exact: true })).toBeVisible();
  await expect(review.getByRole('heading', { name: 'Who can see what' })).toBeVisible();
  const table = review.getByRole('table');
  await expect(table.getByRole('row', { name: /Your summary, submission time and whether attachments were included/ })).toContainText('Yes');
  await expect(table.getByRole('row', { name: /Your full report/ })).toContainText('Only if you allow');
  await expect(review.getByLabel('What happened, full text')).toHaveValue('Synthetic confidential QA report.');
  await expect(review.getByLabel('Summary for legal review')).toHaveValue(summary);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.getByRole('button', { name: 'Submit Report', exact: true }).click();
  const alert = page.locator('[data-failure="verification"]');
  await expect(alert).toContainText('Possible security problem');
  await expect(alert).toContainText('different network');
  await expect(page.getByRole('button', { name: 'Submit Report', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await expect(page.getByLabel('Summary for legal review')).toHaveValue(summary);
  expect(sent.filter(url => url.includes('/api/confidential/objects') || url.endsWith('/channel/call'))).toEqual([]);
  expect(sent.filter(url => url.includes('/api/whistleblower/submit'))).toEqual([]);
});
