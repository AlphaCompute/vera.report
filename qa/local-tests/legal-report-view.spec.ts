import { test, expect } from '@playwright/test';
import { bundleFixture, openFixturePage } from './support/fixtureBundle';

// Real report rendering and download boundary; protocol responses are synthetic.
// Cryptographic authorization is independently tested by firmCase and the browser verifier.
// Every import of the real component resolves as in the app; only I/O is stubbed.
let bundle: string;
test.beforeAll(async () => {
  bundle = await bundleFixture({
    entry: 'components/vera/confidential/LegalReportView.tsx',
    render: `const root = require('react-dom/client').createRoot(document.getElementById('root')); window.fixture.unmount = () => root.unmount(); root.render(require('react').createElement(subject.CaseView, {
      session: { firm: { organizationId: 'synthetic' }, pins: new Map(window.fixture.pinned ? [['synthetic', {}]] : []),
        owners: new Map(window.fixture.ownerPinned ? [['synthetic', {}]] : []) }, caseId: 'synthetic' }));`,
    stubs: {
      'components/vera/confidential/LegalPortal.tsx': `exports.panel = ''; exports.primaryButton = ''; exports.secondaryButton = '';
        exports.failureMessage = (_error, fallback) => fallback;
        exports.Banner = ({ title, children }) => require('react').createElement('section', null, title, children);
        exports.StatusBadge = ({ label }) => require('react').createElement('span', null, label);
        exports.downloadBytes = (bytes, name) => { window.fixture.delivered = { bytes: Array.from(bytes), name }; };`,
      'lib/confidential/firmPortal.ts': `const request = { caseId: 'synthetic', requestId: 'request', summary: 'Approved public summary', requestedAt: Date.now() };
        exports.rememberedRequests = () => [request];
        exports.rememberRequest = async () => ({});
        exports.resolveCaseRequest = async () => ({ request, pinned: true });
        exports.recordRequestGranted = async () => {};
        exports.persistFirmWorkspace = async () => { if (window.fixture.deferSave) await new Promise(resolve => { window.fixture.resolveSave = resolve; }); if (window.fixture.failSave) throw new Error('disk full'); };`,
      'lib/confidential/firmCase.ts': `exports.openFirmCase = async (_session, _id, _now, options) => { window.fixture.options = options;
          window.fixture.caseOpens = (window.fixture.caseOpens ?? 0) + 1;
          if (window.fixture.signInRequired) { window.fixture.signInRequired--; throw new (require('@/lib/confidential/legalAuth').LegalSignInRequired)(); }
          if (window.fixture.refused) throw new exports.FirmCaseError(window.fixture.refused);
          if (window.fixture.failure) throw new Error(window.fixture.failure);
          return window.fixture.opened; };
        exports.openFirmEvidence = async () => { window.fixture.fileReads++; if (window.fixture.revoked) throw new Error('not-granted');
          const bytes = new Uint8Array([1,2,3]); window.fixture.lastBytes = bytes; if (window.fixture.deferRead) await new Promise(resolve => { window.fixture.resolveRead = resolve; }); return { bytes, name: 'evidence.txt' }; };
        exports.acknowledgeReportOpen = async () => { window.fixture.acknowledgements = (window.fixture.acknowledgements ?? 0) + 1;
          if (!document.getElementById('report-details')) throw new Error('Acknowledged before rendering');
          if (window.fixture.failReceipt) throw new Error('Receipt unavailable'); };
        exports.openFirmChunkedEvidence = async () => { throw new Error('No chunked files in this fixture'); };
        exports.readFirmMessages = async () => { window.fixture.messageReads = (window.fixture.messageReads ?? 0) + 1; throw new Error('Unshared messages must not be read'); };
        exports.readRequestStatus = async () => { window.fixture.statusReads = (window.fixture.statusReads ?? 0) + 1;
          if (window.fixture.status) return window.fixture.status; throw new Error('Status is not read for an open report'); };
        exports.FirmCaseError = class extends Error { constructor(code) { super(code); this.code = code; } };`,
      'lib/confidential/legalAuth.ts': `exports.LegalSignInRequired = class extends Error {}; exports.LegalPopupBlocked = class extends Error {};
        exports.legalSignedIn = () => window.fixture.signedIn !== false;
        exports.legalAuthConfig = () => window.fixture.renewals === undefined ? null : {};
        exports.renewLegalSignIn = async () => { if (window.fixture.renewals === undefined) throw new Error('No sign-in in this fixture');
          window.fixture.renewals++;
          if (window.fixture.blockPopup) { window.fixture.blockPopup = false; throw new exports.LegalPopupBlocked('Allow pop-ups for this site, then sign in again.'); } };`,
      // Reached only through lazy imports this fixture never triggers: the chunked
      // download path and the renewal form's domain check.
      'lib/confidential/evidenceTransfer.ts': `exports.startEvidenceDownload = () => { throw new Error('No chunked files in this fixture'); };`,
      'lib/confidential/firmOnboarding.ts': `exports.checkFirmDomain = async () => { throw new Error('No domain check in this fixture'); };`,
      // Setup guidance is shown only for a refused report, which this fixture never is.
      'lib/confidential/firmSetup.ts': 'exports.setupNextSteps = () => [];',
      'next/link': `exports.__esModule = true; exports.default = ({ children, ...props }) => require('react').createElement('a', props, children);`,
    },
  });
});

test('report renders authorized records as text and delivers lazy evidence only after saving its pin', async ({ page }) => {
  page.on('pageerror', error => console.error('Report fixture page error:', error.message));
  const refused = await openFixturePage(page);
  await page.evaluate(() => {
    (window as any).fixture = { fileReads: 0, failSave: false, opened: {
      scopes: ['contact', 'evidence'], narrative: null,
      records: [{ scope: 'contact', fields: { contactValue: '<img src=x onerror="window.leaked=true">' } }],
      grants: [{ issuedAt: Date.now(), expiresAt: Date.now() + 86400000, scopes: ['contact', 'evidence'] }],
      releaseApprovedAt: null, deferredEvidence: Array.from({ length: 16 }, (_, i) => ({ objectId: `file-${i}`, encryptedBytes: 4096 })),
    } };
  });
  await page.addScriptTag({ content: bundle });
  await expect(page.getByText('The reporter has not shared the full report with your organization.')).toBeVisible();
  await expect(page.getByText('<img src=x onerror="window.leaked=true">', { exact: true })).toBeVisible();
  await expect(page.locator('img')).toHaveCount(0);
  // Private messaging is retired: no thread or composer is rendered.
  await expect(page.getByRole('heading', { name: 'Messages', exact: true })).toHaveCount(0);
  await expect(page.getByRole('textbox')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /^Download file/ })).toHaveCount(16);
  expect(await page.evaluate(() => ({ reads: (window as any).fixture.fileReads, options: { deferEvidence: (window as any).fixture.options.deferEvidence, hasProgress: typeof (window as any).fixture.options.onProgress === 'function' } })))
    .toEqual({ reads: 0, options: { deferEvidence: true, hasProgress: true } });
  // A delayed callback from a completed load must not replace the report with a spinner.
  await page.evaluate(() => (window as any).fixture.options.onProgress('unlocking'));
  await expect(page.getByText('The reporter has not shared the full report with your organization.')).toBeVisible();
  await page.evaluate(() => { (window as any).fixture.failSave = true; });
  await page.getByRole('button', { name: 'Download file 1', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('file was not downloaded');
  expect(await page.evaluate(() => (window as any).fixture.delivered)).toBeUndefined();
  expect(await page.evaluate(() => Array.from((window as any).fixture.lastBytes))).toEqual([0, 0, 0]);
  await page.evaluate(() => { (window as any).fixture.failSave = false; (window as any).fixture.revoked = true; });
  await page.getByRole('button', { name: 'Download file 1', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Access may have ended');
  expect(await page.evaluate(() => (window as any).fixture.delivered)).toBeUndefined();
  await page.evaluate(() => { (window as any).fixture.revoked = false; });
  await page.getByRole('button', { name: 'Download file 1', exact: true }).click();
  await expect(page.getByText('Downloaded files stay on your device', { exact: false })).toBeVisible();
  expect(await page.evaluate(() => (window as any).fixture.delivered)).toEqual({ bytes: [1, 2, 3], name: 'evidence.txt' });
  expect(await page.evaluate(() => Array.from((window as any).fixture.lastBytes))).toEqual([0, 0, 0]);
  expect(await page.evaluate(() => (window as any).fixture.messageReads)).toBeUndefined();
  expect(await page.evaluate(() => (window as any).fixture.acknowledgements)).toBeUndefined();
  expect(refused).toEqual([]);
});


for (const stage of ['Read', 'Save'] as const) {
  test(`locking during evidence ${stage.toLowerCase()} discards bytes without downloading`, async ({ page }) => {
    const refused = await openFixturePage(page);
    await page.evaluate(() => {
      (window as any).fixture = { fileReads: 0, opened: {
        scopes: ['evidence'], narrative: null, records: [],
        grants: [{ issuedAt: Date.now(), expiresAt: Date.now() + 86400000, scopes: ['evidence'] }],
        releaseApprovedAt: null, deferredEvidence: [{ objectId: 'file-1', encryptedBytes: 4096 }],
      } };
    });
    await page.addScriptTag({ content: bundle });
    const button = page.getByRole('button', { name: 'Download file 1', exact: true });
    await expect(button).toBeVisible();
    await page.evaluate(stage => { (window as any).fixture[`defer${stage}`] = true; }, stage);
    await button.click();
    await expect.poll(() => page.evaluate(stage => typeof (window as any).fixture[`resolve${stage}`], stage)).toBe('function');
    await page.evaluate(stage => {
      const fixture = (window as any).fixture;
      fixture.unmount();
      fixture[`resolve${stage}`]();
    }, stage);
    await expect.poll(() => page.evaluate(() => Array.from((window as any).fixture.lastBytes))).toEqual([0, 0, 0]);
    expect(await page.evaluate(() => (window as any).fixture.delivered)).toBeUndefined();
    expect(refused).toEqual([]);
  });
}

const signedOutReport = () => ({ scopes: ['contact'], narrative: null,
  records: [{ scope: 'contact', fields: { contactValue: 'renewed contact' } }],
  grants: [{ issuedAt: Date.now(), expiresAt: Date.now() + 86400000, scopes: ['contact'] }],
  releaseApprovedAt: null, deferredEvidence: [] });

test('an expired sign-in reopens the report on its own once it is renewed elsewhere', async ({ page }) => {
  const refused = await openFixturePage(page);
  await page.evaluate(opened => { (window as any).fixture = { signInRequired: 1, signedIn: false, opened }; }, signedOutReport());
  await page.addScriptTag({ content: bundle });
  await expect(page.getByText('Your sign-in has expired.', { exact: false })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in again' })).toBeVisible();
  // Still signed out: polling must not reopen the report.
  await page.waitForTimeout(1500);
  expect(await page.evaluate(() => (window as any).fixture.caseOpens)).toBe(1);
  // Renewed by the portal's own prompt: no click here.
  await page.evaluate(() => { (window as any).fixture.signedIn = true; });
  await expect(page.getByText('renewed contact', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => (window as any).fixture.caseOpens)).toBe(2);
  expect(refused).toEqual([]);
});

test('Sign in again renews in a separate window and reopens the report', async ({ page }) => {
  const refused = await openFixturePage(page);
  // Signed in locally but refused by the service: only the button reopens, never the poll.
  await page.evaluate(opened => { (window as any).fixture = { signInRequired: 1, signedIn: true, opened, renewals: 0, blockPopup: true }; }, signedOutReport());
  await page.addScriptTag({ content: bundle });
  const button = page.getByRole('button', { name: 'Sign in again' });
  await button.click();
  await expect(page.getByRole('alert')).toHaveText('Allow pop-ups for this site, then sign in again.');
  await page.waitForTimeout(1500);
  expect(await page.evaluate(() => (window as any).fixture.caseOpens)).toBe(1);
  await button.click();
  await expect(page.getByText('renewed contact', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => ({ renewals: (window as any).fixture.renewals, opens: (window as any).fixture.caseOpens }))).toEqual({ renewals: 2, opens: 2 });
  expect(refused).toEqual([]);
});

// A locked report whose grant lapsed: the enclave refuses this organization's own
// state key (unlock-case answers not-granted, surfaced as FirmCaseError), while
// request-status can only say `unknown` because the grants are sealed.
test('a lapsed grant on a locked report shows no access with Access ended and renewal, not a retryable error', async ({ page }) => {
  const refused = await openFixturePage(page);
  await page.evaluate(() => { (window as any).fixture = { refused: 'not-granted', pinned: true, ownerPinned: true,
    status: { access: 'unknown', request: 'approved', requestExpiresAt: null } }; });
  await page.addScriptTag({ content: bundle });
  // The stubbed Banner renders its title and body in one element.
  await expect(page.getByText('Your organization does not have access to this report')).toBeVisible();
  await expect(page.getByText('Access ended', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Ask to renew' })).toBeVisible();
  await expect(page.getByText('Access not yet checked')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Try again' })).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).fixture.statusReads)).toBe(1);
  expect(refused).toEqual([]);
});

test('a channel failure while opening stays a retryable error and never reads as no access', async ({ page }) => {
  const refused = await openFixturePage(page);
  await page.evaluate(() => { (window as any).fixture = { failure: 'relay unavailable', pinned: true, ownerPinned: true,
    status: { access: 'unknown', request: 'approved', requestExpiresAt: null } }; });
  await page.addScriptTag({ content: bundle });
  await expect(page.getByRole('alert').filter({ has: page.getByRole('button', { name: 'Try again' }) })).toBeVisible();
  await expect(page.getByText('Your organization does not have access to this report')).toHaveCount(0);
  await expect(page.getByText('Access ended')).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).fixture.statusReads)).toBeUndefined();
  expect(refused).toEqual([]);
});


test('legacy message permission cannot restore the conversation or start polling', async ({ page }) => {
  const refused = await openFixturePage(page);
  await page.evaluate(() => {
    (window as any).fixture = { opened: {
      scopes: ['narrative', 'messages'], narrative: { description: 'Previously shared report' }, records: [],
      grants: [{ issuedAt: Date.now(), expiresAt: null, scopes: ['narrative', 'messages'] }],
      releaseApprovedAt: null, deferredEvidence: [],
    } };
  });
  await page.addScriptTag({ content: bundle });
  await expect(page.getByText('Previously shared report', { exact: true })).toBeVisible();
  await expect(page.getByText('The reporter can see that your organization opened this report.')).toBeVisible();
  expect(await page.evaluate(() => (window as any).fixture.acknowledgements)).toBe(1);
  await expect(page.getByRole('link', { name: 'Conversation', exact: true })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Messages with the reporter' })).toHaveCount(0);
  await expect(page.getByRole('textbox')).toHaveCount(0);
  await expect(page.getByText('The reporter shared the report.', { exact: false })).toBeVisible();
  expect(await page.evaluate(() => (window as any).fixture.messageReads)).toBeUndefined();
  expect(refused).toEqual([]);
});


test('opening confirmation failure keeps the report readable and can be retried', async ({ page }) => {
  await openFixturePage(page);
  await page.evaluate(() => { (window as any).fixture = { failReceipt: true, opened: {
    scopes: ['narrative'], narrative: { description: 'Still readable while confirmation is offline' }, records: [],
    grants: [{ issuedAt: Date.now(), expiresAt: null, scopes: ['narrative'] }], releaseApprovedAt: null, deferredEvidence: [],
  } }; });
  await page.addScriptTag({ content: bundle });
  await expect(page.getByRole('button', { name: 'Retry confirmation' })).toBeVisible();
  await expect(page.getByText('Still readable while confirmation is offline')).toBeVisible();
  await page.evaluate(() => { (window as any).fixture.failReceipt = false; });
  await page.getByRole('button', { name: 'Retry confirmation' }).click();
  await expect(page.getByText('The reporter can see that your organization opened this report.')).toBeVisible();
  expect(await page.evaluate(() => (window as any).fixture.acknowledgements)).toBe(2);
});
