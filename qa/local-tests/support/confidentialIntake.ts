import { expect, type Page } from '@playwright/test';

export const narrative = 'SYNTHETIC PRIVATE NARRATIVE: invoices approved without delivered work.';
export const contact = 'synthetic-private-contact@example.org';
export const summary = 'Invoices appear to have been approved for work that was not delivered.';
export const evidence = { name: 'evidence.csv', mimeType: 'text/csv', buffer: Buffer.from('synthetic-private-evidence,42\n') };

export async function watchIntake(page: Page) {
  const traffic: string[] = [], legacy: string[] = [];
  page.on('request', request => {
    traffic.push(request.url(), request.postData() ?? '');
    if (new URL(request.url()).pathname.startsWith('/api/whistleblower/')) legacy.push(request.url());
  });
  await page.route('**/api/monitoring/client', route => route.fulfill({ status: 204 }));
  await page.route('**/api/whistleblower/**', route => route.abort());
  await page.route('**/api/confidential/**', route => route.fulfill({ status: 503, body: 'Synthetic unavailable service' }));
  return { traffic, legacy };
}

export async function describeReport(page: Page, attach = true) {
  await page.goto('/report');
  const description = page.getByPlaceholder('Describe what happened');
  await description.fill(narrative);
  await description.press('Enter');
  if (attach) {
    await page.locator('input[type="file"]').setInputFiles(evidence);
    await expect(page.getByText(evidence.name, { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Continue', exact: true }).click();
  } else await page.getByRole('button', { name: 'Skip', exact: true }).click();
}

export async function reviewReport(page: Page, attach = true) {
  await describeReport(page, attach);
  await page.getByLabel('Email', { exact: true }).fill(contact);
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  await page.getByLabel('Summary for legal review').fill(summary);
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Submit Report', exact: true })).toBeVisible();
}

export function expectNoPlaintext(seen: { traffic: string[]; legacy: string[] }) {
  expect(seen.legacy).toEqual([]);
  for (const secret of [narrative, contact, summary, 'synthetic-private-evidence']) expect(seen.traffic.join('\n')).not.toContain(secret);
}
