import { test, expect } from '@playwright/test';
import { watchIntake, describeReport, expectNoPlaintext } from './support/confidentialIntake';

test('contact validation precedes confidential review without retired reward questions', async ({ page }) => {
  const seen = await watchIntake(page);
  await describeReport(page, false);
  const next = page.getByRole('button', { name: 'Continue', exact: true });
  await next.click();
  await expect(page.getByRole('alert').filter({ hasText: 'Add at least one contact method.' })).toBeVisible();
  await page.getByLabel('Email', { exact: true }).fill('invalid-address');
  await next.click();
  await expect(page.getByLabel('Email', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Summary for legal review')).toHaveCount(0);
  await page.getByLabel('Email', { exact: true }).fill('synthetic-private-contact@example.org');
  await next.click();
  await expect(page.getByLabel('Summary for legal review')).toBeVisible();
  await expect(page.getByText(/compensation|reward/i)).toHaveCount(0);
  expectNoPlaintext(seen);
});
