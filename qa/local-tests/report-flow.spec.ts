import { test, expect } from '@playwright/test';
import { narrative, evidence, watchIntake, reviewReport, expectNoPlaintext } from './support/confidentialIntake';

// Successful encrypted upload and recovery are exercised against the real
// enclave fixture in qa/e2e. An unavailable secure service must never fall back
// to the retired plaintext intake, even when its old response would succeed.
for (const width of [1280, 390]) {
  test(`${width}px: confidential report keeps evidence private when the service is unavailable`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    const seen = await watchIntake(page);
    await reviewReport(page);
    const review = page.getByRole('region', { name: /Review your report/ });
    await expect(review.getByLabel('What happened, full text')).toHaveValue(narrative);
    await expect(review.getByText(evidence.name, { exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.getByRole('button', { name: 'Submit Report', exact: true }).click();
    await expect(page.locator('[data-failure="unavailable"]')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Download recovery file', exact: true })).toHaveCount(0);
    expectNoPlaintext(seen);
  });
}

test('a blank narrative cannot advance to evidence', async ({ page }) => {
  await watchIntake(page);
  await page.goto('/report');
  const description = page.getByPlaceholder('Describe what happened');
  await description.fill('   '); await description.press('Enter');
  await expect(description).toBeVisible();
  await expect(page.getByRole('button', { name: 'Attach files', exact: true })).toHaveCount(0);
});
