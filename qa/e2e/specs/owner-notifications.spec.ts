import { test, expect } from '@playwright/test';
import { newParticipant, recordTraffic } from '../support/browser';
import { leakedSecrets, recoveryFileSecrets } from '../support/leaks';
import { sweptFromHost } from '../support/state';
import { openWithRecoveryCode, submitConfidentialReport } from '../support/owner';

// Reporter contact belongs only in encrypted case scopes, never in a host email subscription.
test('receipt and restored private inbox do not offer host-readable reporter email', async ({ browser }) => {
  const context = await newParticipant(browser);
  const traffic: string[] = [];
  recordTraffic(context, traffic);
  const page = await context.newPage();
  const report = await submitConfidentialReport(page, {
    narrative: 'NOTIFY-SENTINEL: a regulator was sent altered test results.',
    summary: 'A laboratory appears to have sent a regulator altered test results.',
  });
  await expect(page.getByRole('region', { name: 'Email me when something needs me' })).toHaveCount(0);
  await expect(page.getByLabel('Separate email address')).toHaveCount(0);
  await openWithRecoveryCode(page, report.recoveryCode);
  await expect(page.getByRole('region', { name: 'Email me when something needs me' })).toHaveCount(0);
  await expect(page.getByLabel('Separate email address')).toHaveCount(0);
  expect(traffic.length).toBeGreaterThan(0);
  expect(leakedSecrets(traffic, sweptFromHost(['NOTIFY-SENTINEL',
    ...recoveryFileSecrets(report.recoveryFile, report.recoveryCode)]))).toEqual([]);
  await context.close();
});
