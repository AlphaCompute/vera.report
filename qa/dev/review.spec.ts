import { test, expect } from '@playwright/test';

// Run against `npm run dev:review`: real encryption and local persistence,
// synthetic attestation. No intercepted relay or disabled browser verifier.
for (const width of [1280, 390]) test(`editable review and encrypted submission at ${width}px`, async ({ page }) => {
  await page.setViewportSize({ width, height: 900 });
  const bodies: string[] = [];
  const legacy: string[] = [];
  page.on('request', request => {
    bodies.push(request.postData() || '');
    if (request.url().includes('/api/whistleblower/')) legacy.push(request.url());
  });
  await page.goto('/report');
  await expect(page.getByRole('note')).toContainText('simulated secure service');
  await page.getByPlaceholder('Describe what happened').fill('PRIVATE-SENTINEL: records show invoices for undelivered work.');
  await page.getByPlaceholder('Describe what happened').press('Enter');
  await page.getByRole('button', { name: 'Skip', exact: true }).click();
  await page.getByLabel('Email', { exact: true }).fill('private-sentinel@example.test');
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  const summary = page.getByLabel('Summary for legal review');
  await summary.fill('My manager Tom Reed called me at 419-555-0144.');
  await expect(page.locator('q').filter({ hasText: 'Tom Reed' })).toBeVisible();
  await summary.fill('A company approved invoices for undelivered work. Records are available.');
  await expect(page.getByText('No obvious identifying details detected.', { exact: false })).toBeVisible();
  await expect(page.getByText('Your summary will appear here.', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  const review = page.getByRole('region', { name: 'Review your report', exact: true });
  await expect(review).toBeVisible();
  await expect(page.getByPlaceholder('Describe what happened')).toHaveCount(0);
  await expect(review.getByRole('heading', { name: 'Who can see what' })).toBeVisible();
  await review.getByLabel('What happened, full text').fill('PRIVATE-SENTINEL: edited report with supporting records.');
  await review.getByLabel('Signal', { exact: true }).fill('private_sentinel.123');
  const notice = review.getByText('VERA administrators and legal organizations can read this text.', { exact: true });
  await expect(notice).toHaveCSS('font-weight', '700');
  await expect(review.getByRole('button', { name: 'Submit Report', exact: true })).toBeEnabled();
  await page.screenshot({ path: `/tmp/vera-review-${width}.png`, fullPage: true });
  await review.getByRole('button', { name: 'Submit Report', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Report Submitted', exact: true })).toBeVisible();
  await expect(page.getByText('Your report has been submitted. Registered legal organizations can now request to view your evidence. Only the legal organizations you approve can see your confidential information.', { exact: true })).toBeVisible();
  // The receipt counts as saved only after the downloaded file is checked.
  await expect(page.getByLabel('Select your saved recovery file')).toBeVisible();
  await expect(page.getByText('Check your backup before leaving', { exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'Go to the status page', exact: true }).click();
  await expect(page.getByRole('button', { name: 'I saved my recovery code, leave' })).toBeVisible();
  await page.getByRole('button', { name: 'Stay on this page' }).click();
  expect(legacy).toEqual([]);
  expect(bodies.join('\n')).not.toContain('PRIVATE-SENTINEL');
  expect(bodies.join('\n')).not.toContain('private-sentinel@example.test');
  await page.screenshot({ path: `/tmp/vera-dev-submitted-${width}.png`, fullPage: true });
});
