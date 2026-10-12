import { expect, type Page } from '@playwright/test';

export async function acknowledgeReportEntry(page: Page) {
  // Direct report visits have no introduction; homepage reporting actions do.
  if (new URL(page.url()).pathname === '/report') return;
  await page.getByRole('dialog').getByRole('checkbox', { name: /I consent to VERA processing/ }).check();
  await page.getByRole('dialog').getByRole('button', { name: 'Agree and continue', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
}

export async function enterTestContact(page: Page, value = 'reporter@example.invalid') {
  await page.getByLabel('Email', { exact: true }).fill(value);
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
}
