import { test, expect } from '@playwright/test';
import { watchIntake, reviewReport, expectNoPlaintext } from './support/confidentialIntake';

for (const width of [1280, 390]) {
  test(`${width}px: pending secure verification cannot report success and recovers from service failure`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    const seen = await watchIntake(page);
    let release!: () => void;
    const blocked = new Promise<void>(resolve => { release = resolve; });
    let attempts = 0;
    await page.route('**/api/confidential/**', async route => {
      attempts++; await blocked;
      await route.fulfill({ status: 503, body: 'Synthetic unavailable service' });
    });
    await reviewReport(page);
    await page.getByRole('button', { name: 'Submit Report', exact: true }).click();
    await expect.poll(() => attempts).toBeGreaterThan(0);
    await expect(page.getByRole('button', { name: 'Download recovery file', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Submit Report', exact: true })).toHaveCount(0);
    release();
    await expect(page.locator('[data-failure="unavailable"]')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Submit Report', exact: true })).toBeEnabled();
    expectNoPlaintext(seen);
  });
}
