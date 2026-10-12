import { test, expect } from '@playwright/test';
import { narrative, evidence, watchIntake, reviewReport, expectNoPlaintext } from './support/confidentialIntake';

test('failed secure submission keeps its draft and attachment through retries', async ({ page }) => {
  const seen = await watchIntake(page);
  let attempts = 0;
  await page.route('**/api/confidential/**', route => {
    attempts++;
    return route.fulfill({ status: 503, body: 'Synthetic outage' });
  });
  await reviewReport(page);
  for (let attempt = 0; attempt < 2; attempt++) {
    const before = attempts;
    await page.getByRole('button', { name: 'Submit Report', exact: true }).click();
    await expect.poll(() => attempts).toBeGreaterThan(before);
    await expect(page.locator('[data-failure="unavailable"]')).toBeVisible();
    const review = page.getByRole('region', { name: /Review your report/ });
    await expect(review.getByLabel('What happened, full text')).toHaveValue(narrative);
    await expect(review.getByText(evidence.name, { exact: true })).toBeVisible();
  }
  expectNoPlaintext(seen);
});
