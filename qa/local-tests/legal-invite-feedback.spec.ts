import { test, expect } from '@playwright/test';
import { bundleFixture, openFixturePage } from './support/fixtureBundle';

let bundle: string;
test.beforeAll(async () => {
  bundle = await bundleFixture({
    entry: 'components/vera/confidential/AddLawyer.tsx',
    render: `require('react-dom/client').createRoot(document.getElementById('root')).render(
      require('react').createElement(subject.AddLawyer, { session: {
        firm: { organizationId: 'synthetic', domain: 'firm.example' },
        accessToken: async () => { window.fixture.preflights++; if (window.fixture.expired) throw new Error('Please sign in again to continue.'); return 'synthetic'; }
      } }));`,
    stubs: {
      'components/vera/confidential/LegalPortal.tsx': `exports.panel = ''; exports.secondaryButton = '';
        exports.failureMessage = (error, fallback) => error.message || fallback;`,
      'lib/confidential/firmMemberDevices.ts': `exports.joinLink = () => 'http://localhost:9/legal/enroll';
        exports.inviteOrganizationMember = async (_session, email) => {
          window.fixture.calls.push(email);
          if (window.fixture.failInvite) throw new Error('The secure connection could not be verified.');
        };`,
    },
  });
});

test.beforeEach(async ({ page }) => {
  await openFixturePage(page);
  await page.evaluate(() => { (window as any).fixture = { calls: [], preflights: 0, expired: false, failInvite: false }; });
  await page.addScriptTag({ content: bundle });
});

test('wrong-domain email is rejected before authentication or sending and can be corrected immediately', async ({ page }) => {
  await page.getByLabel("Colleague's work email").fill('qa@other.example');
  await page.getByRole('button', { name: 'Add colleague', exact: true }).click();
  await expect(page.getByText("Use a colleague's work email at firm.example. Nothing was sent.")).toBeVisible();
  expect(await page.evaluate(() => (window as any).fixture)).toMatchObject({ calls: [], preflights: 0 });
  await page.getByLabel("Colleague's work email").fill('qa@firm.example');
  await page.getByRole('button', { name: 'Add colleague', exact: true }).click();
  await expect(page.getByText(/Colleague added/)).toBeVisible();
});

test('expired sign-in before sending allows the same email to be retried after renewal', async ({ page }) => {
  await page.evaluate(() => { (window as any).fixture.expired = true; });
  await page.getByLabel("Colleague's work email").fill('qa@firm.example');
  await page.getByRole('button', { name: 'Add colleague', exact: true }).click();
  await expect(page.getByText(/Please sign in again.*Nothing was sent/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Add colleague', exact: true })).toBeEnabled();
  expect(await page.evaluate(() => (window as any).fixture.calls)).toEqual([]);
  await page.evaluate(() => { (window as any).fixture.expired = false; });
  await page.getByRole('button', { name: 'Add colleague', exact: true }).click();
  await expect(page.getByText(/Colleague added/)).toBeVisible();
  expect(await page.evaluate(() => (window as any).fixture.calls)).toEqual(['qa@firm.example']);
});

test('uncertain operation failure retains the cooldown, explains why, and permits retry after ten minutes', async ({ page }) => {
  await page.clock.install();
  await page.evaluate(() => { (window as any).fixture.failInvite = true; });
  await page.getByLabel("Colleague's work email").fill('QA@FIRM.EXAMPLE');
  await page.getByRole('button', { name: 'Add colleague', exact: true }).click();
  await expect(page.getByText(/could not confirm whether your colleague was added/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Wait before retrying' })).toBeDisabled();
  await page.clock.fastForward(60_000);
  await expect(page.getByText('Retry this email in 9:00.')).toBeVisible();
  expect(await page.evaluate(() => (window as any).fixture.calls)).toEqual(['qa@firm.example']);
  await page.clock.fastForward(540_000);
  await expect(page.getByRole('button', { name: 'Add colleague', exact: true })).toBeEnabled();
  await page.evaluate(() => { (window as any).fixture.failInvite = false; });
  await page.getByRole('button', { name: 'Add colleague', exact: true }).click();
  await expect(page.getByText(/Colleague added/)).toBeVisible();
});

test('confirmed success clears the email but prevents an immediate duplicate to the same normalized address', async ({ page }) => {
  await page.getByLabel("Colleague's work email").fill('QA@firm.example');
  await page.getByRole('button', { name: 'Add colleague', exact: true }).click();
  await expect(page.getByText(/Colleague added/)).toBeVisible();
  await expect(page.getByLabel("Colleague's work email")).toHaveValue('');
  await page.getByLabel("Colleague's work email").fill('qa@firm.example');
  await expect(page.getByRole('button', { name: 'Wait before retrying' })).toBeDisabled();
  expect(await page.evaluate(() => (window as any).fixture.calls)).toEqual(['qa@firm.example']);
});
