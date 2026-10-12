import { test, expect } from '@playwright/test';
import { newParticipant, recordTraffic } from '../support/browser';
import { leakedSecrets, recoveryFileSecrets } from '../support/leaks';
import { sweptFromHost } from '../support/state';
import { openWithRecoveryCode, submitConfidentialReport } from '../support/owner';
import { displayedRecoveryCodeProblem } from '../support/recoveryCode';

const SUMMARY = 'A contractor appears to have billed for work that was never delivered.';

test('smoke: confidential submit reaches the recovery receipt and the code restores', async ({ browser }) => {
  const context = await newParticipant(browser);
  const page = await context.newPage();
  const traffic = recordTraffic(context);
  const report = await submitConfidentialReport(page, { narrative: 'SMOKE-SENTINEL narrative for the local stack.',
    summary: SUMMARY });
  // Exactly the grouped format the restore flow reads, with a valid checksum:
  // not just any text scraped from the receipt.
  expect(await displayedRecoveryCodeProblem(report.recoveryCode)).toBeNull();
  await context.close();

  // A fresh device opens the report with the recovery code alone.
  const restored = await newParticipant(browser);
  recordTraffic(restored, traffic);
  const restoredPage = await restored.newPage();
  await openWithRecoveryCode(restoredPage, report.recoveryCode);
  await expect(restoredPage.getByRole('region', { name: 'Summary for legal review' }).getByText(SUMMARY)).toBeVisible();
  await restored.close();

  // The recovery code and file never leave either device, in any form (URL, header, body).
  expect(traffic.length).toBeGreaterThan(0);
  expect(leakedSecrets(traffic, sweptFromHost(['SMOKE-SENTINEL', ...recoveryFileSecrets(report.recoveryFile, report.recoveryCode)]))).toEqual([]);
});
