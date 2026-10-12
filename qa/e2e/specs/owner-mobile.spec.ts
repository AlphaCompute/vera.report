import { test, expect, devices } from '@playwright/test';
import type { Page } from '@playwright/test';
import { newParticipant, recordTraffic } from '../support/browser';
import { leakedSecrets, recoveryFileSecrets } from '../support/leaks';
import { sweptFromHost } from '../support/state';
import { openWithRecoveryCode, submitConfidentialReport } from '../support/owner';
import type { SubmittedReport } from '../support/owner';

// Owner restore on phones: the recovery file from a phone's file picker, and
// the typed recovery code on a small screen. Same local stack as the journey.
test.describe.configure({ mode: 'serial' });

const SUMMARY = 'A hospital supplier appears to have invoiced for equipment that was never delivered.';
let report: SubmittedReport;
/** Everything the phones sent: the recovery code and file must never be in it. */
const traffic: string[] = [];
const expectNoRecoveryLeak = () => {
  expect(traffic.length).toBeGreaterThan(0);
  expect(leakedSecrets(traffic, sweptFromHost(['MOBILE-SENTINEL', ...recoveryFileSecrets(report.recoveryFile, report.recoveryCode)]))).toEqual([]);
};

async function fitsScreen(page: Page) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(0);
}

test('reporter submits on a phone', async ({ browser }) => {
  const context = await newParticipant(browser, { ...devices['Pixel 7'] });
  recordTraffic(context, traffic);
  const page = await context.newPage();
  report = await submitConfidentialReport(page, { narrative: 'MOBILE-SENTINEL: deliveries were signed for but never arrived.',
    summary: SUMMARY, files: [{ name: 'delivery-notes.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.4\nMOBILE\n%%EOF\n') }] });
  await fitsScreen(page);
  expectNoRecoveryLeak();
  await context.close();
});

test('owner restores from the recovery file on a phone', async ({ browser }) => {
  const context = await newParticipant(browser, { ...devices['Pixel 7'] });
  recordTraffic(context, traffic);
  const page = await context.newPage();
  await page.goto('/status');
  await expect(page.getByRole('button', { name: 'Open recovery file' })).toBeVisible();
  await fitsScreen(page);
  const chooser = page.waitForEvent('filechooser');
  await page.getByRole('button', { name: 'Open recovery file' }).click();
  await (await chooser).setFiles({ name: 'vera-private-recovery.txt', mimeType: 'text/plain', buffer: Buffer.from(report.recoveryFile) });
  await expect(page.getByRole('button', { name: 'Check for updates' })).toBeVisible({ timeout: 180_000 });
  await expect(page.getByRole('region', { name: 'Summary for legal review' }).getByText(SUMMARY)).toBeVisible();
  await expect(page.getByRole('region', { name: 'Your files' }).getByText('delivery-notes.pdf')).toBeVisible();
  await fitsScreen(page);
  expectNoRecoveryLeak();
  await context.close();
});

test('owner restores with the typed recovery code on a small phone', async ({ browser }) => {
  const context = await newParticipant(browser, { viewport: { width: 375, height: 667 }, isMobile: true, hasTouch: true, deviceScaleFactor: 2 });
  recordTraffic(context, traffic);
  const page = await context.newPage();
  // Typed without group separators, as people often do on phones.
  await openWithRecoveryCode(page, report.recoveryCode.replace(/-/g, '').toLowerCase());
  await expect(page.getByRole('region', { name: 'Summary for legal review' }).getByText(SUMMARY)).toBeVisible();
  await fitsScreen(page);
  const recovery = page.getByRole('region', { name: 'Recovery code and file' });
  await recovery.getByText('Show recovery code and printable sheet').click();
  await expect(recovery.getByRole('button', { name: 'Copy' })).toBeVisible();
  await expect(recovery.getByRole('button', { name: 'Print recovery sheet' })).toBeVisible();
  await fitsScreen(page);
  expectNoRecoveryLeak();
  await context.close();
});
