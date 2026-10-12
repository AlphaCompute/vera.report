import { test, expect } from '@playwright/test';
import { watchIntake, reviewReport, expectNoPlaintext } from './support/confidentialIntake';

test('a nominally successful response without valid attestation cannot yield a receipt', async ({ page }) => {
  const seen = await watchIntake(page);
  await page.route('**/api/confidential/**', route => route.fulfill({ status: 200,
    json: { success: true, trackingId: 'VRA-1234567890ABCDEF', proofStatus: 'verified' } }));
  await reviewReport(page, false);
  await page.getByRole('button', { name: 'Submit Report', exact: true }).click();
  await expect(page.locator('[data-failure="unavailable"]')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Submit Report', exact: true })).toBeEnabled();
  await expect(page.getByText('VRA-1234567890ABCDEF', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Download recovery file', exact: true })).toHaveCount(0);
  expectNoPlaintext(seen);
});
