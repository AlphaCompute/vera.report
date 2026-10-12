import { test, expect } from '@playwright/test';
import type { Page } from '@playwright/test';
import { newParticipant, recordTraffic } from '../support/browser';
import { leakedSecrets, recoveryFileSecrets } from '../support/leaks';
import { sweptFromHost } from '../support/state';
import { submitConfidentialReport } from '../support/owner';
import type { SubmittedReport } from '../support/owner';

// "Approve update": after VERA ships a new release, a report stays closed on that
// release until its reporter approves it. The browser that submitted the report
// ran the current release; the reporter then returns with a browser that received
// the next one (same measured enclave image, a new declared source commit, so a
// new release ID the reporter has not approved). Same local stack as the journey.
test.describe.configure({ mode: 'serial' });

const NARRATIVE = 'RELEASE-SENTINEL: the maintenance contract was renewed without the required tender.';
const SUMMARY = 'A maintenance contract appears to have been renewed without the tender the rules require.';
let report: SubmittedReport;

async function openOnNextRelease(page: Page, recoveryCode: string) {
  await page.goto('/status');
  await page.getByLabel('Recovery code').fill(recoveryCode);
  await page.getByRole('button', { name: 'Retrieve report status' }).click();
}

test('reporter submits on the current release', async ({ browser }) => {
  const context = await newParticipant(browser);
  const page = await context.newPage();
  report = await submitConfidentialReport(page, { narrative: NARRATIVE, summary: SUMMARY });
  await context.close();
});

test('on the next release the report waits for the reporter to approve the update; "Not now" changes nothing', async ({ browser }) => {
  const context = await newParticipant(browser, { release: 'next' });
  const page = await context.newPage();
  const traffic = recordTraffic(page);
  await openOnNextRelease(page, report.recoveryCode);
  const approval = page.getByRole('region', { name: 'Approve update' });
  await expect(approval).toBeVisible({ timeout: 180_000 });
  await expect(approval.getByText('VERA replaced the secure service software that handles your encrypted report.', { exact: false })).toBeVisible();
  await expect(approval.getByText('This new version cannot open your report until you approve it.', { exact: false })).toBeVisible();
  // Nothing of the report is shown before the approval.
  await expect(page.getByRole('button', { name: 'Check for updates' })).toHaveCount(0);
  await expect(page.getByText(SUMMARY)).toHaveCount(0);
  await approval.getByText('Technical details', { exact: true }).click();
  await expect(approval.getByText('Release ID')).toBeVisible();
  await approval.getByRole('button', { name: 'Not now' }).click();
  await expect(approval).toHaveCount(0);
  await expect(page.getByLabel('Recovery code')).toBeVisible();
  expect(leakedSecrets(traffic, sweptFromHost(['RELEASE-SENTINEL', ...recoveryFileSecrets(report.recoveryFile, report.recoveryCode)]))).toEqual([]);
  await context.close();
});

test('the reporter approves the update and the report opens on the next release', async ({ browser }) => {
  const context = await newParticipant(browser, { release: 'next' });
  const page = await context.newPage();
  await openOnNextRelease(page, report.recoveryCode);
  const approval = page.getByRole('region', { name: 'Approve update' });
  await expect(approval).toBeVisible({ timeout: 180_000 });
  await approval.getByRole('button', { name: 'Approve update' }).click();
  await expect(page.getByText('Update approved. Your report is open.')).toBeVisible({ timeout: 180_000 });
  await expect(page.getByRole('button', { name: 'Check for updates' })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Summary for legal review' }).getByText(SUMMARY)).toBeVisible();
  await context.close();

  // A later visit on the same release opens directly: the approval is part of the signed report state.
  const again = await newParticipant(browser, { release: 'next' });
  const next = await again.newPage();
  await openOnNextRelease(next, report.recoveryCode);
  await expect(next.getByRole('button', { name: 'Check for updates' })).toBeVisible({ timeout: 180_000 });
  await expect(next.getByRole('region', { name: 'Approve update' })).toHaveCount(0);
  await again.close();
});
