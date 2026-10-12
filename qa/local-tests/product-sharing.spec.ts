import { test, expect } from '@playwright/test';
import { bundleFixture, openFixturePage } from './support/fixtureBundle';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
let bundle: string;
test.beforeAll(async () => {
  bundle = await bundleFixture({ entry: 'components/vera/confidential/DirectSharing.tsx', stubs: {}, render: `
    const React = require('react'); const { createRoot } = require('react-dom/client');
    const organizations = [{ organizationId: 'a', displayName: 'Example Legal Aid', domain: 'aid.example', profile: null },
      { organizationId: 'b', displayName: 'Example Counsel', domain: 'counsel.example', profile: null }];
    window.submissions = [];
    createRoot(document.getElementById('root')).render(React.createElement(subject.DirectSharing, {
      organizations, requested: ['b'], existingOrganizationIds: [], busy: false, published: true, revision: 3, panel: 'm-6 border border-black/20 p-6',
      onVerify: async id => organizations.find(org => org.organizationId === id),
      onShare: async (id, decision) => { window.submissions.push({ id, decision }); return true; }
    }));` });
});
test('cards show requesting organizations, keep direct sharing available, and cancel grants nothing', async ({ page }) => {
  await openFixturePage(page);
  // Use the built site's stylesheet for visual inspection when available.
  const cssDir = join(__dirname, '../../.next/static/chunks');
  for (const name of (existsSync(cssDir) ? readdirSync(cssDir) : []).filter(name => name.endsWith('.css'))) await page.addStyleTag({ content: readFileSync(join(cssDir, name), 'utf8') });
  await page.addScriptTag({ content: bundle });
  await expect(page.getByRole('listitem').first()).toContainText('Example Counsel');
  const requesting = page.getByRole('listitem').filter({ hasText: 'Example Counsel' });
  const other = page.getByRole('listitem').filter({ hasText: 'Example Legal Aid' });
  await expect(requesting.getByRole('link', { name: 'Review request' })).toBeVisible();
  // A pending request does not hide direct sharing with that organization.
  await expect(requesting.getByRole('button', { name: 'Select organization' })).toBeVisible();
  await expect(other.getByRole('link', { name: 'Review request' })).toHaveCount(0);
  await expect(page.getByRole('combobox')).toHaveCount(0);
  await other.getByRole('button', { name: 'Select organization' }).click();
  await expect(other.getByText('Shares the current report for 30 days. Contact details and files added later stay private.')).toBeVisible();
  await page.screenshot({ path: '/tmp/vera-organization-cards.png', fullPage: true });
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  expect(await page.evaluate(() => (window as any).submissions)).toEqual([]);
  await page.setViewportSize({ width: 375, height: 812 });
  await other.getByRole('button', { name: 'Select organization' }).click();
  await other.getByLabel('Also share all current files').check();
  await page.screenshot({ path: '/tmp/vera-organization-cards-mobile.png', fullPage: true });
  await other.getByRole('button', { name: 'Submit', exact: true }).click();
  const submissions = await page.evaluate(() => (window as any).submissions);
  expect(submissions).toEqual([{ id: 'a', decision: expect.objectContaining({ scopes: ['narrative', 'evidence'], objectRevisionLimit: 3 }) }]);
  // Contact details keep their own separate sharing action.
  expect(submissions[0].decision.shareContact).toBeUndefined();
  await expect(page.getByRole('button', { name: 'Cancel', exact: true })).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});
