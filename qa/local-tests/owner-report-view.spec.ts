import { test, expect } from '@playwright/test';
import { bundleFixture, openFixturePage } from './support/fixtureBundle';

let bundle: string;
test.beforeAll(async () => {
  bundle = await bundleFixture({ entry: 'components/vera/confidential/OwnerReportView.tsx',
    render: `const root = require('react-dom/client').createRoot(document.getElementById('root'));
      window.fixture.unmount = () => root.unmount();
      root.render(require('react').createElement(subject.OwnerReportView, { session: {}, inbox: {} }));`,
    stubs: { 'lib/confidential/ownerCase.ts': `exports.readOwnerReport = async () => {
      if (window.fixture.fail) throw new Error('Unavailable');
      return window.fixture.report;
    };` },
  });
});

test('reporter reads their account, facts and private contact details without exposing them as markup', async ({ page }) => {
  const refused = await openFixturePage(page);
  await page.evaluate(() => { (window as any).fixture = { report: {
    narrative: { description: 'My submitted account\nSecond paragraph', dateOfIncident: '2026-09-20',
      location: 'Example workplace', extraDetail: '<img src=x onerror="window.leaked=true">' },
    records: [{ scope: 'contact', fields: { contactValue: 'reporter@example.invalid' } }],
  } }; });
  await page.addScriptTag({ content: bundle });
  const report = page.getByRole('article', { name: 'Your submitted report' });
  await expect(report.getByText('My submitted account\nSecond paragraph', { exact: true })).toBeVisible();
  await expect(report.getByText('September 20, 2026')).toBeVisible();
  await expect(report.getByText('Example workplace')).toBeVisible();
  await expect(report.getByText('<img src=x onerror="window.leaked=true">')).toBeVisible();
  await expect(report.locator('img')).toHaveCount(0);
  await expect(report.getByText('reporter@example.invalid')).not.toBeVisible();
  await report.getByText('Your contact details', { exact: true }).click();
  await expect(report.getByText('reporter@example.invalid')).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.evaluate(() => (window as any).fixture.unmount());
  await expect(page.getByText('My submitted account', { exact: false })).toHaveCount(0);
  expect(refused).toEqual([]);
});

test('failed private report load explains the problem and retries without changing the report', async ({ page }) => {
  await openFixturePage(page);
  await page.evaluate(() => { (window as any).fixture = { fail: true,
    report: { narrative: { description: 'Recovered original account' }, records: [] } }; });
  await page.addScriptTag({ content: bundle });
  await expect(page.getByRole('alert')).toContainText('Your saved report has not changed');
  await page.evaluate(() => { (window as any).fixture.fail = false; });
  await page.getByRole('button', { name: 'Try opening the report again' }).click();
  await expect(page.getByText('Recovered original account')).toBeVisible();
  await expect(page.getByRole('alert')).toHaveCount(0);
});
