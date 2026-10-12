import { acknowledgeReportEntry } from '../../support/report-entry';
import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { sweptFromHost } from './state';

export type SubmittedReport = { recoveryCode: string; recoveryFile: string };

/** The confidential intake as a reporter clicks through it. */
export async function submitConfidentialReport(page: Page, input: {
  narrative: string; summary: string; files?: { name: string; mimeType: string; buffer: Buffer }[]; contact?: string;
}): Promise<SubmittedReport> {
  await page.goto('/report');
  await acknowledgeReportEntry(page);
  const description = page.getByPlaceholder('Describe what happened');
  await expect(description).toBeVisible();
  await description.fill(input.narrative);
  await description.press('Enter');
  await expect(page.getByRole('button', { name: 'Attach files', exact: true })).toBeVisible();
  if (input.files?.length) {
    await page.locator('input[type="file"]').setInputFiles(input.files);
    for (const file of input.files) await expect(page.getByText(file.name, { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Continue', exact: true }).click();
  } else {
    await page.getByRole('button', { name: 'Skip', exact: true }).click();
  }
  const contact = input.contact ?? 'sentinel-default-reporter@example.com';
  sweptFromHost([contact]);
  await page.getByLabel('Email', { exact: true }).fill(contact);
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  await page.getByLabel('Summary for legal review').fill(input.summary);
  await expect(page.getByText(/NOT CONFIDENTIAL. Legal organizations read this/)).toBeVisible();
  await page.screenshot({ path: test.info().outputPath('summary-disclosure.png'), fullPage: true });
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  const review = page.getByRole('region', { name: 'Review your report', exact: true });
  await expect(review).toBeVisible();
  await expect(review.getByRole('textbox', { name: 'What happened, full text' })).toHaveValue(input.narrative);
  await expect(review.getByLabel('Email', { exact: true })).toHaveValue(contact);
  await expect(review.getByLabel('Summary for legal review')).toHaveValue(input.summary);
  await expect(review.getByText('VERA administrators and legal organizations can read this text.', { exact: true })).toBeVisible();
  await review.getByRole('button', { name: 'Submit Report', exact: true }).click();

  await expect(page.getByText('Report Submitted', { exact: true })).toBeVisible({ timeout: 240_000 });
  const code = page.getByRole('list', { name: /Recovery code, \d+ groups of four characters/ }).first();
  await expect(code).toBeVisible();
  const groups = await code.locator('li > span:last-child').allInnerTexts();
  const recoveryCode = groups.map(group => group.trim()).join('-');

  // Save the recovery file, then prove the backup opens this report.
  // This journey covers browser downloads; participant-workspaces separately
  // exercises the native Save As path, cancellation and write failures.
  await page.evaluate(() => { Object.defineProperty(window, 'showSaveFilePicker', { value: undefined, configurable: true }); });
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download recovery file' }).click();
  const saved = await download;
  expect(saved.suggestedFilename()).toBe('vera-private-recovery.txt');
  const recoveryFile = readFileSync((await saved.path())!, 'utf8');
  await page.getByLabel('Select your saved recovery file').setInputFiles({ name: 'vera-private-recovery.txt', mimeType: 'text/plain', buffer: Buffer.from(recoveryFile) });
  await expect(page.getByText('Backup verified.', { exact: false })).toBeVisible();
  return { recoveryCode, recoveryFile };
}

/** Fresh device: open the report with the recovery code only. */
export async function openWithRecoveryCode(page: Page, recoveryCode: string) {
  await page.goto('/status');
  await page.getByLabel('Recovery code').fill(recoveryCode);
  await page.getByRole('button', { name: 'Retrieve report status' }).click();
  await expect(page.getByRole('button', { name: 'Check for updates' })).toBeVisible({ timeout: 180_000 });
}
