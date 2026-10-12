import { test, expect } from '@playwright/test';
import { narrative, contact, summary, evidence, watchIntake, reviewReport } from './support/confidentialIntake';

for (const width of [1280, 390]) {
  test(`${width}px: confidential back navigation preserves summary, contact, evidence and narrative`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    await watchIntake(page); await reviewReport(page);
    const back = page.getByRole('button', { name: 'Back', exact: true });
    await back.click(); await expect(page.getByLabel('Summary for legal review')).toHaveValue(summary);
    await back.click(); await expect(page.getByLabel('Email', { exact: true })).toHaveValue(contact);
    await back.click(); await expect(page.getByText(evidence.name, { exact: true })).toBeVisible();
    await back.click(); await expect(page.getByPlaceholder('Describe what happened')).toHaveValue(narrative);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
}
