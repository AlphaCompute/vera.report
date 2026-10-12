import { test, expect } from '@playwright/test';
import type { Page } from '@playwright/test';
import { randomBytes } from 'node:crypto';
import { exportFirmIdentity, generateFirmIdentity, generateFirmRecoveryCode, firmBindingDocument } from '../../lib/confidential/firmKey';
import { bundleFixture, openFixturePage } from './support/fixtureBundle';

// Actual Next pages. Identity responses, the firm's domain and an unavailable
// confidential backend are fixtures; no private material reaches a server.
const secret = randomBytes(32).toString('base64url');

// Mount the real checklist and deliberately interleave a membership/setup read
// with an unfinished terms form. Protocol validation has separate unit/stack tests.
async function termsFixture(page: Page) {
  const refused = await openFixturePage(page);
  const bundle = await bundleFixture({
    entry: 'components/vera/confidential/FirmOnboarding.tsx',
    render: `const React = require('react');
      const root = require('react-dom/client').createRoot(document.getElementById('root'));
      const fixture = window.fixture = {
        firm: { domain: 'counsel.example', organizationId: 'a'.repeat(64), recipientKeyId: 'b'.repeat(64) },
        setup: { active: false, status: null, error: null, busy: false,
          record: async () => { fixture.recorded++; return true; }, refresh: () => {} },
        accepted: 0, recorded: 0,
      };
      fixture.render = () => root.render(React.createElement(subject.FirmOnboardingChecklist, {
        firm: fixture.firm, keySaved: true, domain: {}, membership: {}, setup: fixture.setup,
        onboarding: { record: { terms: null, custody: null }, confirmCustody: () => {},
          acceptTerms: () => { fixture.accepted++; } },
      }));
      fixture.render();`,
    stubs: {
      'lib/confidential/firmOnboarding.ts': `exports.FIRM_ONBOARDING_TERMS_VERSION = 1;
        exports.FIRM_ONBOARDING_TERMS = [{ id: 'terms', title: 'Terms', text: 'Synthetic onboarding terms.' }];
        exports.onboardingChecklist = () => ({ complete: false, steps: [
          { id: 'terms', label: 'Onboarding terms acknowledged', detail: 'Read and acknowledge.', done: false }
        ] });`,
      'lib/confidential/legalAuth.ts': 'exports.LegalSignInRequired = class extends Error {};',
      'lib/confidential/client.ts': 'exports.fetchRelay = () => { throw new Error("Unexpected channel request"); };',
      'lib/confidential/firmSetup.ts': 'exports.readFirmSetup = () => { throw new Error("Unexpected setup request"); };',
      'next/link': `exports.__esModule = true; exports.default = ({ children, ...props }) => require('react').createElement('a', props, children);`,
    },
  });
  await page.addScriptTag({ content: bundle });
  return refused;
}

for (const viewport of [{ width: 1280, height: 900 }, { width: 390, height: 844 }]) {
  test(`terms selection survives setup loading and retry at ${viewport.width}px`, async ({ page }) => {
    await page.setViewportSize(viewport);
    const refused = await termsFixture(page);
    const agreed = page.getByRole('checkbox', { name: 'I have read these and my organization will follow them.' });
    const acknowledge = page.getByRole('button', { name: 'Acknowledge', exact: true });
    await agreed.check();
    await expect(acknowledge).toBeEnabled();
    await page.evaluate(() => {
      const fixture = (window as any).fixture;
      fixture.setup.active = true;
      fixture.render();
    });
    await expect(agreed).toBeChecked();
    await expect(acknowledge).toBeDisabled();
    // A pending or failed verification must not accept or sign terms, even if
    // a form-submit event is dispatched without clicking the disabled button.
    await acknowledge.locator('..').dispatchEvent('submit');
    await page.evaluate(() => {
      const fixture = (window as any).fixture;
      fixture.setup.error = 'Temporarily unavailable';
      fixture.render();
    });
    await expect(agreed).toBeChecked();
    await expect(acknowledge).toBeDisabled();
    expect(await page.evaluate(() => [(window as any).fixture.accepted, (window as any).fixture.recorded])).toEqual([0, 0]);
    await page.evaluate(() => {
      const fixture = (window as any).fixture;
      fixture.setup.status = { terms: null };
      fixture.setup.error = null;
      fixture.render();
    });
    await expect(agreed).toBeChecked();
    await expect(acknowledge).toBeEnabled();
    await page.evaluate(() => {
      const fixture = (window as any).fixture;
      fixture.setup.busy = true;
      fixture.render();
    });
    await expect(acknowledge).toBeDisabled();
    await acknowledge.locator('..').dispatchEvent('submit');
    expect(await page.evaluate(() => (window as any).fixture.recorded)).toBe(0);
    await page.evaluate(() => {
      const fixture = (window as any).fixture;
      fixture.setup.busy = false;
      fixture.render();
    });
    await agreed.uncheck();
    await expect(acknowledge).toBeDisabled();
    await agreed.check();
    await acknowledge.click();
    expect(await page.evaluate(() => [(window as any).fixture.accepted, (window as any).fixture.recorded])).toEqual([1, 1]);
    expect(refused).toEqual([]);
  });
}

for (const identity of ['organizationId', 'recipientKeyId']) {
  test(`terms selection is reset when ${identity} changes`, async ({ page }) => {
    const refused = await termsFixture(page);
    const agreed = page.getByRole('checkbox', { name: 'I have read these and my organization will follow them.' });
    await agreed.check();
    await page.evaluate(identity => {
      const fixture = (window as any).fixture;
      fixture.firm = { ...fixture.firm, [identity]: 'c'.repeat(64) };
      fixture.render();
    }, identity);
    await expect(agreed).not.toBeChecked();
    await expect(page.getByRole('button', { name: 'Acknowledge', exact: true })).toBeDisabled();
    expect(await page.evaluate(() => (window as any).fixture.accepted)).toBe(0);
    expect(refused).toEqual([]);
  });
}

async function fixtures(page: Page, domain: string, published: () => string | null) {
  await page.route('**/api/monitoring/client', route => route.fulfill({ status: 204 }));
  await page.route('https://identity.example/oauth/token', route => route.fulfill({ status: 200,
    headers: { 'Access-Control-Allow-Origin': '*' }, contentType: 'application/json',
    body: JSON.stringify({ access_token: 'synthetic-browser-identity-only', token_type: 'Bearer', expires_in: 300 }) }));
  await page.route('**/api/confidential/**', route => route.fulfill({ status: 503, body: 'Backend unavailable in this test' }));

}
async function signIn(page: Page) {
  await page.evaluate(() => sessionStorage.setItem('vera-legal-auth-pending',
    JSON.stringify({ state: 'test-state', verifier: 'test-verifier', returnPath: '/legal', binding: JSON.stringify([location.origin, 'identity.example', 'legal-test-client', 'https://legal.example']), organization: null })));
  await page.goto('/legal?code=synthetic&state=test-state');
}
const unlockedText = 'Organization key unlocked on this device';

test('only an encrypted key file with its separate code is accepted, and membership must verify before the workspace opens', async ({ page }) => {
  const firm = await generateFirmIdentity({ organizationId: 'd'.repeat(64), domain: 'returning.example' });
  const code = generateFirmRecoveryCode();
  const oldFile = await exportFirmIdentity(firm, code);
  // An unencrypted key file is not an accepted format and must never open.
  const plaintextFile = JSON.stringify({ format: 'vera-firm-private-key/v1', organizationId: firm.organizationId, domain: firm.domain,
    recipientKeyId: firm.recipientKeyId, privateKey: firm.privateKey.armor(), bindingDocument: await firmBindingDocument(firm, Date.now()) });
  const sent: string[] = [];
  page.on('request', request => sent.push(request.url(), request.postData() || ''));
  await fixtures(page, firm.domain, () => null);
  await page.goto('/legal');
  // Possession of the file never removes the sign-in gate.
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expect(page.getByLabel('Encrypted private key file', { exact: true })).toHaveCount(0);
  await signIn(page);
  const fileInput = page.getByLabel('Encrypted private key file', { exact: true });
  const keyForm = page.getByRole('region', { name: 'Open your organization', exact: true });
  const open = page.getByRole('button', { name: 'Open organization', exact: true });
  const passphrase = page.getByLabel('Recovery passphrase or code', { exact: true });
  // A file alone, of any format, never enables opening the organization.
  await fileInput.setInputFiles({ name: 'unprotected.txt', mimeType: 'text/plain', buffer: Buffer.from(plaintextFile) });
  await expect(open).toBeDisabled();
  await passphrase.fill(generateFirmRecoveryCode());
  await open.click();
  await expect(keyForm.getByRole('alert')).toContainText('do not match');
  await expect(page.getByText(unlockedText, { exact: true })).toHaveCount(0);
  await fileInput.setInputFiles({ name: 'private-key.txt', mimeType: 'text/plain', buffer: Buffer.from(oldFile) });
  await passphrase.fill(generateFirmRecoveryCode());
  await open.click();
  await expect(keyForm.getByRole('alert')).toContainText('do not match');
  await passphrase.fill(code);
  await open.click();
  // This fixture deliberately has no enclave. File possession must not expose
  // a workspace when its signed-in membership cannot be verified.
  await expect(keyForm.getByRole('alert')).toContainText(/secure connection/i);
  await expect(page.getByText(unlockedText, { exact: true })).toHaveCount(0);
  const stored = await page.evaluate(() => [...Object.values(sessionStorage), ...Object.values(localStorage)].join('\n'));
  for (const value of [code, oldFile, plaintextFile, firm.privateKey.armor(), JSON.stringify(firm.privateKey.armor()).slice(1, -1)]) {
    expect(sent.join('\n')).not.toContain(value);
    expect(stored).not.toContain(value);
  }
});

// A new encrypted backup and PRF/passkey return visits run against enrolled
// firms in confidential-two-firms, including the membership check.

test('Auth0 invitation opens the approved organization and returns to enrollment', async ({ page }) => {
  let authorization: URL | null = null;
  await page.route('https://identity.example/authorize?**', route => {
    authorization = new URL(route.request().url());
    return route.fulfill({ status: 200, contentType: 'text/html', body: '<p>Synthetic organization sign-in</p>' });
  });
  await fixtures(page, 'onboarding.example', () => null);
  await page.goto('/legal?invitation=synthetic-ticket&organization=org_approved&organization_name=ignored');
  await expect.poll(() => authorization?.pathname).toBe('/authorize');
  // Observing the authorization request does not mean its navigation committed.
  // Finish loading the synthetic provider before starting its return callback.
  await expect(page.getByText('Synthetic organization sign-in', { exact: true })).toBeVisible();
  const params = authorization!.searchParams;
  expect(params.get('organization')).toBe('org_approved');
  expect(params.get('invitation')).toBe('synthetic-ticket');
  expect(params.get('code_challenge_method')).toBe('S256');
  expect(params.get('redirect_uri')).toBe(new URL('/legal', test.info().project.use.baseURL as string).href);
  await page.goto(`/legal?code=synthetic&state=${encodeURIComponent(params.get('state')!)}`);
  await expect(page).toHaveURL(/\/legal\/enroll$/);
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toHaveCount(0);
  const stored = await page.evaluate(() => Object.values(sessionStorage).join(' '));
  expect(stored).not.toContain('synthetic-ticket');
  expect(stored).not.toContain('synthetic-browser-identity-only');
});
