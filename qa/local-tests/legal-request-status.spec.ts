import { test, expect } from '@playwright/test';
import type { Page } from '@playwright/test';
import { bundleFixture, openFixturePage } from './support/fixtureBundle';

// Exercise the real portal's request list, directory, request form and status
// logic with synthetic transports. Every import resolves as in the app; only
// modules with I/O are stubbed. Protocol and membership authorization are
// covered separately; this is not hardware evidence.
let bundle: string;
test.beforeAll(async () => {
  bundle = await bundleFixture({
    entry: 'pages/legal/index.tsx',
    expose: ['RequestsAndDirectory'],
    render: `require('react-dom/client').createRoot(document.getElementById('root')).render(
      require('react').createElement(subject.RequestsAndDirectory, {
        session: { firm: { organizationId: 'synthetic', domain: 'firm.example', recipientKeyId: 'key' }, pins: new Map(), owners: new Map() } }));`,
    stubs: {
      'components/vera/confidential/AutomaticApplicationActivation.tsx': 'exports.AutomaticApplicationActivation = () => null;',
      // Encrypted workspace and shared list storage.
      'lib/confidential/firmWorkspace.ts': 'exports.assertFirmWorkspaceCapacity = () => {};',
      'lib/confidential/firmPortal.ts': `exports.rememberedRequests = () => window.fixture.requests;
        exports.currentSharedList = () => null;
        exports.loadSharedRequests = async () => { throw new Error('offline'); };
        exports.ownerFromRequest = async () => ({});
        exports.rememberRequest = async (_org, record) => { const { expiresAt, ownerPublicKey, ...saved } = record;
          window.fixture.requests = [saved]; return null; };
        exports.clearRequest = async () => { window.fixture.requests = []; return null; };`,
      // Attested channel.
      'lib/confidential/firmCase.ts': `exports.assertFirmSetupComplete = async () => {};
        exports.readLegalDirectory = async () => {
          if (window.fixture.waitForDirectory) await new Promise(resolve => { window.fixture.finishDirectory = resolve; });
          return { listings: window.fixture.listings ?? [window.fixture.listing], next: null };
        };
        exports.checkReportAccess = async (_session, caseId, requestId, _now, owner) => {
          window.fixture.unlockChecks = (window.fixture.unlockChecks ?? 0) + 1;
          window.fixture.checks.push({ caseId, requestId });
          if (window.fixture.offline) throw new Error('offline');
          const result = structuredClone(window.fixture.requireOwner && !owner
            ? { ...window.fixture.status, access: 'unknown' } : window.fixture.status);
          if (window.fixture.delay) return new Promise(resolve => window.fixture.pendingChecks.push(() => resolve(result)));
          return result;
        };
        exports.checkReportAccessBatch = async (_session, targets) => {
          window.fixture.batches = (window.fixture.batches ?? 0) + 1;
          window.fixture.checks.push(...targets.map(({ caseId, requestId }) => ({ caseId, requestId })));
          if (window.fixture.failBatch === window.fixture.batches) {
            await new Promise(resolve => { window.fixture.failPendingBatch = resolve; });
            throw new Error('503 Service Unavailable');
          }
          if (window.fixture.offline) throw new Error('offline');
          const result = new Map(targets.map(({ caseId, owner }) => [caseId, structuredClone(window.fixture.requireOwner && !owner
            ? { ...window.fixture.status, access: 'unknown' } : window.fixture.status)]));
          if (window.fixture.delay) return new Promise(resolve => window.fixture.pendingChecks.push(() => resolve(result)));
          return result;
        };
        exports.withdrawCaseRequest = async () => { window.fixture.withdrawAttempts = (window.fixture.withdrawAttempts ?? 0) + 1; throw new Error('unconfirmed'); };
        exports.requestCaseAccess = async (_session, _listing, input, now, beforeSend) => {
          window.fixture.sentInput = input;
          await beforeSend({ requestId: 'new-request', expiresAt: now + 86400000 });
          if (window.fixture.sendFailure) throw new Error('unconfirmed');
          window.fixture.sent = true; return { requestId: 'new-request' }; };`,
      // Identity provider, domain checks and membership (their own onboarding tests render them).
      'components/vera/confidential/LegalPortal.tsx': `exports.failureMessage = (_error, fallback) => fallback;
        exports.panel = ''; exports.primaryButton = ''; exports.secondaryButton = '';
        exports.Banner = ({ title, children }) => require('react').createElement('section', null, title, children);
        exports.StatusBadge = ({ label }) => require('react').createElement('span', null, label);
        exports.LegalGate = () => null; exports.LegalPortalLayout = () => null;`,
      'components/vera/confidential/FirmOnboarding.tsx': `exports.AddLawyersHint = () => null; exports.FirmOnboardingChecklist = () => null;
        exports.useFirmSetup = () => ({ active: false, status: null, error: null, busy: false });
        exports.OrganizationProfile = () => null; exports.useDomainCheck = () => ({}); exports.useMembershipStatus = () => ({ status: null });
        exports.useOnboardingRecord = () => ({ record: { custody: null, terms: null } });`,
      'lib/confidential/firmOnboarding.ts': `exports.checkFirmDomain = async () => ({ state: 'unreachable' });
        exports.onboardingChecklist = () => ({ complete: true }); exports.portalView = () => 'reports';
        exports.membershipEndDate = () => ''; exports.membershipLease = () => ({ kind: 'none' }); exports.membershipNotice = () => null;`,
      'lib/confidential/firmSetup.ts': 'exports.setupNextSteps = () => [];',
      // Record navigation instead of routing; legalCaseLink itself is the real module.
      'next/router': `exports.useRouter = () => ({ push: async url => { window.fixture.pushed.push(url); return true; } });`,
      'next/link': `exports.__esModule = true; exports.default = ({ children, ...props }) => require('react').createElement('a', props, children);`,
    },
  });
});

const CASE_ID = 'a'.repeat(64);

async function render(page: Page, state: string, offline = false, hasRequest = true, access = 'none', waitForDirectory = false): Promise<string[]> {
  page.on('pageerror', (error: Error) => console.error('Synthetic portal page error:', error.message));
  const refused = await openFixturePage(page);
  await page.evaluate(({ state, offline, hasRequest, access, waitForDirectory }) => {
    const caseId = 'a'.repeat(64);
    (window as any).fixture = { offline, pushed: [], checks: [], pendingChecks: [], waitForDirectory, requireOwner: waitForDirectory,
      status: { access, request: state, requestExpiresAt: state === 'pending' ? Date.now() + 86400000 : null,
        ...(access === 'granted' ? { expiresAt: null, contactShared: false, releaseApproved: true } : {}) },
      requests: hasRequest ? [{ caseId, requestId: 'old-request', summary: 'Synthetic saved case', requestedAt: Date.now() }] : [],
      listing: { caseId, summary: hasRequest ? 'Synthetic saved case' : 'Synthetic available case', owner: { ownerFingerprint: '1'.repeat(64), ownerPublicKey: { armor: () => 'synthetic-key' } } } };
  }, { state, offline, hasRequest, access, waitForDirectory });
  await page.addScriptTag({ content: bundle });
  await expect(page.getByRole('heading', { name: "Your organization's requests", exact: true })).toBeVisible({ timeout: 10000 });
  return refused;
}

test('a terminal request can be retried without losing its saved report reference', async ({ page }) => {
  await render(page, 'declined');
  await expect(page.getByText('Declined', { exact: true }).first()).toBeVisible();
  // The saved reference stays until the organization removes it.
  await expect(page.getByText('Synthetic saved case')).toBeVisible();
  await page.getByRole('button', { name: 'Request access again', exact: true }).click();
  // The real structured request form: message, conflicts, fees and reply time.
  await page.getByLabel('Message to the reporter').fill('Please review this narrower request.');
  await page.getByLabel('We have checked and found no conflict').check();
  await page.getByLabel('Fees').selectOption({ label: 'No fee (pro bono)' });
  await page.getByLabel('Expected reply').selectOption({ label: 'Within a week' });
  await page.getByRole('button', { name: 'Send request', exact: true }).click();
  await expect(page.getByText('Request sent.', { exact: false })).toBeVisible();
  // Saved before sending, and the saved reference now points at the new request.
  expect(await page.evaluate(() => (window as any).fixture.sent)).toBe(true);
  expect(await page.evaluate(() => (window as any).fixture.requests[0].requestId)).toBe('new-request');
  expect(await page.evaluate(() => (window as any).fixture.requests[0].caseId)).toBe('a'.repeat(64));
  expect(await page.evaluate(() => (window as any).fixture.sentInput.purpose)).toBe('Please review this narrower request.');
});

test('an unavailable status keeps the saved reference and does not enable a duplicate request', async ({ page }) => {
  const refused = await render(page, 'pending', true);
  await expect(page.getByText('Status unavailable').first()).toBeVisible();
  await expect(page.getByRole('button', { name: /^Request access/ })).toHaveCount(0);
  // Opening the report selects it in this tab and navigates to a URL with no identifier.
  await expect(page.getByRole('link', { name: 'Open report' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Open report', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Check report access', exact: true }).click();
  expect(await page.evaluate(() => (window as any).fixture.pushed)).toEqual(['/legal/report']);
  expect(await page.evaluate(() => sessionStorage.getItem('vera-legal-open-case'))).toBe(CASE_ID);
  expect(refused).toEqual([]);
});

test('pending withdrawal requires confirmation and failure retains the saved reference', async ({ page }) => {
  await render(page, 'pending');
  await page.getByRole('button', { name: 'Withdraw request', exact: true }).click();
  expect(await page.evaluate(() => (window as any).fixture.withdrawAttempts ?? 0)).toBe(0);
  await page.getByRole('button', { name: 'Yes, withdraw', exact: true }).click();
  await expect(page.getByText('Withdrawal was not confirmed.', { exact: false })).toBeVisible();
  await expect(page.getByText('Synthetic saved case')).toBeVisible();
  expect(await page.evaluate(() => (window as any).fixture.withdrawAttempts)).toBe(1);
});

test('a reporter-initiated share shows access before opening and refresh picks up revocation without inventing a request', async ({ page }) => {
  await render(page, 'unknown', false, false, 'granted');
  const organization = page.getByRole('region', { name: "Your organization's requests" });
  const shared = page.getByRole('region', { name: 'Shared with you' }).getByRole('listitem').filter({ hasText: 'Synthetic available case' });
  await expect(shared.getByText('Access allowed', { exact: true })).toBeVisible();
  await expect(shared.getByText('Shared directly by the reporter', { exact: true })).toBeVisible();
  await shared.getByRole('button', { name: 'Open report', exact: true }).click();
  await expect.poll(() => page.evaluate(() => (window as any).fixture.pushed)).toEqual(['/legal/report']);
  expect(await page.evaluate(() => sessionStorage.getItem('vera-legal-open-case'))).toBe(CASE_ID);
  await expect(shared.getByRole('button', { name: /Request access|Withdraw|Remove/ })).toHaveCount(0);
  await expect(organization.getByRole('listitem')).toHaveCount(1);
  expect(await page.evaluate(() => (window as any).fixture.requests)).toEqual([]);
  expect(await page.evaluate(() => (window as any).fixture.checks)).toEqual([{ caseId: CASE_ID, requestId: null }]);
  await page.evaluate(() => { (window as any).fixture.status = { access: 'none', request: 'unknown', requestExpiresAt: null, ended: 'revoked' }; });
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(shared).toHaveCount(0);
  await expect(page.getByText('Synthetic available case')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Request access', exact: true })).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).fixture.requests)).toEqual([]);
});

test('an unshared directory report is hidden, then shows a later direct grant on refresh', async ({ page }) => {
  await render(page, 'unknown', false, false);
  const available = page.getByRole('region', { name: 'Available reports' });
  await expect(available).toHaveCount(0);
  await expect(page.getByText('Synthetic available case')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Request access', exact: true })).toHaveCount(0);
  await page.evaluate(() => { (window as any).fixture.status = { access: 'granted', request: 'unknown', releaseApproved: true, expiresAt: null, contactShared: false }; });
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(page.getByText('Access allowed', { exact: true }).first()).toBeVisible();
  await expect(page.getByRole('button', { name: /^Request access/ })).toHaveCount(0);
});

test('an unavailable or locked direct-share check never reveals an unshared report', async ({ page }) => {
  await render(page, 'unknown', true, false);
  const organization = page.getByRole('region', { name: 'Shared with you' });
  await expect(organization.getByRole('listitem')).toHaveCount(0);
  await expect(page.getByRole('status').filter({ hasText: '1 report access check is unavailable.' })).toBeVisible();
  await expect(page.getByText('Synthetic available case')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Request access', exact: true })).toHaveCount(0);
  await page.evaluate(() => {
    (window as any).fixture.offline = false;
    (window as any).fixture.status.access = 'unknown';
  });
  await page.getByRole('button', { name: 'Retry unavailable checks', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry unavailable checks', exact: true })).toHaveCount(0);
  await expect(organization.getByRole('listitem')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Open.*report|Check report access/ })).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).fixture.unlockChecks ?? 0)).toBe(0);
});

test('a report with a saved request is listed once even when it also has current access', async ({ page }) => {
  await render(page, 'approved', false, true, 'granted');
  const organization = page.getByRole('region', { name: "Your organization's requests" });
  await expect(organization.getByText('Access allowed', { exact: true })).toBeVisible();
  await expect(organization.getByRole('listitem')).toHaveCount(1);
  await expect(organization.getByText('Shared directly by the reporter')).toHaveCount(0);
});

test('refresh discovers a newly published direct share and still rejects a changed reporter key', async ({ page }) => {
  await render(page, 'unknown', false, false);
  const organization = page.getByRole('region', { name: 'Shared with you' });
  await expect(page.getByText('Synthetic available case')).toHaveCount(0);
  await page.evaluate(() => {
    const fixture = (window as any).fixture;
    fixture.listings = [{ ...fixture.listing, caseId: 'b'.repeat(64), summary: 'New direct share' }];
    fixture.status = { access: 'granted', request: 'unknown', releaseApproved: true, expiresAt: null, contactShared: false };
  });
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(organization.getByText('New direct share')).toBeVisible();
  await page.evaluate(() => { (window as any).fixture.listings[0].ownerKeyChanged = true; });
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(organization.getByText('New direct share')).toHaveCount(0);
});

test('a late access check cannot overwrite a newer revocation check', async ({ page }) => {
  await render(page, 'unknown', false, false, 'granted');
  await expect(page.getByText('Access allowed', { exact: true }).first()).toBeVisible();
  await page.evaluate(() => { (window as any).fixture.delay = true; });
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect.poll(() => page.evaluate(() => (window as any).fixture.pendingChecks.length)).toBe(1);
  await expect(page.getByRole('button', { name: 'Request access', exact: true })).toHaveCount(0);
  await page.evaluate(() => {
    (window as any).fixture.delay = false;
    (window as any).fixture.status = { access: 'none', request: 'unknown', requestExpiresAt: null, ended: 'revoked' };
  });
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(page.getByRole('group', { name: 'Legal report board' }).getByRole('listitem')).toHaveCount(0);
  await page.evaluate(() => { (window as any).fixture.pendingChecks.shift()(); });
  await expect(page.getByRole('group', { name: 'Legal report board' }).getByRole('listitem')).toHaveCount(0);
  await expect(page.getByText('Access allowed', { exact: true })).toHaveCount(0);
});

test('saved requests wait for directory keys and join a single initial batch', async ({ page }) => {
  await render(page, 'unknown', false, true, 'granted', true);
  await expect(page.getByRole('region', { name: 'Needs attention' }).getByText('Checking…', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => (window as any).fixture.checks)).toEqual([]);
  await expect(page.getByRole('region', { name: 'Shared with you' }).getByRole('listitem')).toHaveCount(0);
  await page.evaluate(() => { (window as any).fixture.finishDirectory(); });
  await expect(page.getByRole('region', { name: 'Shared with you' }).getByText('Access allowed', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => (window as any).fixture.batches)).toBe(1);
});

test('completed status pages stay visible after a later 503, and retry checks only unavailable reports', async ({ page }) => {
  await render(page, 'unknown', false, false, 'granted', true);
  await page.evaluate(() => {
    const fixture = (window as any).fixture;
    fixture.listings = Array.from({ length: 120 }, (_, i) => ({ ...fixture.listing,
      caseId: i.toString(16).padStart(64, '0'), summary: `Synthetic report ${i}` }));
    fixture.failBatch = 2;
    fixture.waitForDirectory = false;
    fixture.finishDirectory();
  });
  const shared = page.getByRole('region', { name: 'Shared with you' });
  // Publish the first page while the second page is still waiting for its response.
  await expect(shared.getByRole('listitem')).toHaveCount(50);
  await page.evaluate(() => { (window as any).fixture.failPendingBatch(); });
  await expect(shared.getByRole('listitem')).toHaveCount(70);
  await expect(page.getByRole('status').filter({ hasText: '50 report access checks are unavailable.' })).toBeVisible();
  expect(await page.evaluate(() => (window as any).fixture.batches)).toBe(3);
  await page.getByRole('button', { name: 'Retry unavailable checks', exact: true }).click();
  await expect(shared.getByRole('listitem')).toHaveCount(120);
  await expect(page.getByRole('button', { name: 'Retry unavailable checks', exact: true })).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).fixture.checks.slice(120).map((item: any) => item.caseId)))
    .toEqual(Array.from({ length: 50 }, (_, i) => (i + 50).toString(16).padStart(64, '0')));
  expect(await page.evaluate(() => (window as any).fixture.unlockChecks ?? 0)).toBe(0);
});

test('each status page gets its own deadline instead of timing out the entire directory', async ({ page }) => {
  await render(page, 'unknown', false, false, 'granted', true);
  await page.clock.install();
  await page.evaluate(() => {
    const fixture = (window as any).fixture;
    fixture.listings = Array.from({ length: 70 }, (_, i) => ({ ...fixture.listing,
      caseId: i.toString(16).padStart(64, '0'), summary: `Synthetic report ${i}` }));
    fixture.delay = true;
    fixture.waitForDirectory = false;
    fixture.finishDirectory();
  });
  await expect.poll(() => page.evaluate(() => (window as any).fixture.pendingChecks.length)).toBe(1);
  await page.clock.fastForward(35_000);
  await page.evaluate(() => { (window as any).fixture.pendingChecks.shift()(); });
  const shared = page.getByRole('region', { name: 'Shared with you' });
  await expect(shared.getByRole('listitem')).toHaveCount(50);
  await expect.poll(() => page.evaluate(() => (window as any).fixture.pendingChecks.length)).toBe(1);
  await page.clock.fastForward(35_000);
  await expect(page.getByText('Status unavailable', { exact: true })).toHaveCount(0);
  await page.evaluate(() => { (window as any).fixture.pendingChecks.shift()(); });
  await expect(shared.getByRole('listitem')).toHaveCount(70);
});

test('refresh cancels the old pass before it can check another page or publish stale grants', async ({ page }) => {
  await render(page, 'unknown', false, false, 'granted', true);
  await page.evaluate(() => {
    const fixture = (window as any).fixture;
    fixture.listings = Array.from({ length: 70 }, (_, i) => ({ ...fixture.listing,
      caseId: i.toString(16).padStart(64, '0'), summary: `Synthetic report ${i}` }));
    fixture.delay = true;
    fixture.waitForDirectory = false;
    fixture.finishDirectory();
  });
  await expect.poll(() => page.evaluate(() => (window as any).fixture.pendingChecks.length)).toBe(1);
  await page.evaluate(() => {
    const fixture = (window as any).fixture;
    fixture.delay = false;
    fixture.status = { access: 'none', request: 'unknown', requestExpiresAt: null, ended: 'revoked' };
  });
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect.poll(() => page.evaluate(() => (window as any).fixture.batches)).toBe(3);
  await expect(page.getByRole('group', { name: 'Legal report board' }).getByRole('listitem')).toHaveCount(0);
  await page.evaluate(() => { (window as any).fixture.pendingChecks.shift()(); });
  await expect(page.getByRole('region', { name: 'Shared with you' }).getByRole('listitem')).toHaveCount(0);
  expect(await page.evaluate(() => ({ batches: (window as any).fixture.batches, checks: (window as any).fixture.checks.length })))
    .toEqual({ batches: 3, checks: 120 });
});

test('89 direct shares use two bounded status pages and refresh checks each once', async ({ page }) => {
  await render(page, 'unknown', false, false, 'granted', true);
  await page.evaluate(() => {
    const fixture = (window as any).fixture;
    fixture.listings = Array.from({ length: 89 }, (_, i) => ({ ...fixture.listing,
      caseId: i.toString(16).padStart(64, '0'), summary: `Synthetic report ${i}` }));
    fixture.waitForDirectory = false;
    fixture.finishDirectory();
  });
  await expect(page.getByRole('region', { name: 'Shared with you' }).getByRole('listitem')).toHaveCount(89);
  expect(await page.evaluate(() => ({ batches: (window as any).fixture.batches, checks: (window as any).fixture.checks.length })))
    .toEqual({ batches: 2, checks: 89 });
  await expect(page.getByRole('searchbox')).toHaveCount(0);
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect.poll(() => page.evaluate(() => (window as any).fixture.batches)).toBe(4);
  expect(await page.evaluate(() => (window as any).fixture.checks.length)).toBe(178);
  expect(await page.evaluate(() => (window as any).fixture.unlockChecks ?? 0)).toBe(0);
});

test('a stalled access check ends with a retry and its late response cannot restore stale access', async ({ page }) => {
  await render(page, 'unknown', false, false, 'granted');
  await expect(page.getByText('Access allowed', { exact: true })).toBeVisible();
  await page.clock.install();
  await page.evaluate(() => { (window as any).fixture.delay = true; });
  await page.getByRole('button', { name: 'Refresh' }).click();
  await expect.poll(() => page.evaluate(() => (window as any).fixture.pendingChecks.length)).toBe(1);
  await page.clock.fastForward(61_000);
  await expect(page.getByRole('status').filter({ hasText: '1 report access check is unavailable.' })).toBeVisible();
  await expect(page.getByText('Checking…', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Request access', exact: true })).toHaveCount(0);
  await page.evaluate(() => {
    (window as any).fixture.delay = false;
    (window as any).fixture.status = { access: 'none', request: 'unknown', requestExpiresAt: null };
  });
  await page.getByRole('button', { name: 'Retry unavailable checks', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry unavailable checks', exact: true })).toHaveCount(0);
  await expect(page.getByText('Synthetic available case')).toHaveCount(0);
  await page.evaluate(() => { (window as any).fixture.pendingChecks.shift()(); });
  await expect(page.getByText('Synthetic available case')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Request access', exact: true })).toHaveCount(0);
  await expect(page.getByText('Access allowed', { exact: true })).toHaveCount(0);
});


test('the board moves a request only when its verified status changes', async ({ page }) => {
  await render(page, 'pending');
  const waiting = page.getByRole('region', { name: 'Waiting for a reply' });
  const shared = page.getByRole('region', { name: 'Shared with you' });
  const attention = page.getByRole('region', { name: 'Needs attention' });
  await expect(waiting.getByText('Synthetic saved case')).toBeVisible();
  await expect(shared.getByRole('listitem')).toHaveCount(0);
  await page.evaluate(() => { (window as any).fixture.status = {
    access: 'granted', request: 'approved', releaseApproved: true, expiresAt: null, contactShared: false }; });
  await page.getByRole('button', { name: 'Refresh' }).click();
  await expect(shared.getByText('Synthetic saved case')).toBeVisible();
  await expect(waiting.getByRole('listitem')).toHaveCount(0);
  await expect(page.getByRole('region', { name: 'Available reports' })).toHaveCount(0);
  await page.evaluate(() => { (window as any).fixture.offline = true; });
  await page.getByRole('button', { name: 'Refresh' }).click();
  await expect(attention.getByText('Status unavailable')).toBeVisible();
  await expect(shared.getByRole('listitem')).toHaveCount(0);
  await expect(attention.getByRole('button', { name: /Request access|Withdraw request/ })).toHaveCount(0);
});

test('the legal board shows only its three remaining columns and no public-report browser', async ({ page }) => {
  const refused = await render(page, 'unknown', false, false);
  const board = page.getByRole('group', { name: 'Legal report board' });
  await expect(board.getByRole('heading', { level: 2 })).toHaveText([
    'Waiting for a reply', 'Shared with you', 'Needs attention',
  ]);
  await expect(board.getByRole('listitem')).toHaveCount(0);
  await expect(page.getByRole('region', { name: 'Available reports' })).toHaveCount(0);
  await expect(page.getByRole('searchbox')).toHaveCount(0);
  await expect(page.getByText('Synthetic available case')).toHaveCount(0);
  expect(refused).toEqual([]);
});

test('a failed retry delivery stays visible on its saved card', async ({ page }) => {
  await render(page, 'declined');
  await page.evaluate(() => { (window as any).fixture.sendFailure = true; });
  await page.getByRole('button', { name: 'Request access again', exact: true }).click();
  await page.getByLabel('Message to the reporter').fill('Please review this request.');
  await page.getByLabel('We have checked and found no conflict').check();
  await page.getByLabel('Fees').selectOption({ label: 'No fee (pro bono)' });
  await page.getByLabel('Expected reply').selectOption({ label: 'Within a week' });
  await page.getByRole('button', { name: 'Send request', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Available reports' })).toHaveCount(0);
  await expect(page.getByRole('region', { name: 'Needs attention' }).getByRole('alert').filter({ hasText: 'Request delivery was not confirmed' })).toBeVisible();
});

test('a saved report card reflects an updated public summary without duplicating the report', async ({ page }) => {
  await render(page, 'pending');
  await page.evaluate(() => {
    (window as any).fixture.listing.summary = 'Updated summary from the reporter';
    (window as any).fixture.listing.checkCode = 'TEST-CODE';
  });
  await page.getByRole('button', { name: 'Refresh' }).click();
  const waiting = page.getByRole('region', { name: 'Waiting for a reply' });
  await expect(waiting.getByText('Updated summary from the reporter')).toBeVisible();
  await expect(waiting.getByText('TEST-CODE')).toBeVisible();
  await expect(page.getByText('Synthetic saved case')).toHaveCount(0);
  await expect(page.getByRole('region', { name: 'Available reports' })).toHaveCount(0);
});

for (const hasRequest of [false, true]) {
  test(`an unapproved update stays in Needs attention until access is verified (${hasRequest ? 'request' : 'direct share'})`, async ({ page }) => {
    const refused = await render(page, 'unknown', false, hasRequest, 'unknown');
    await page.evaluate(() => { (window as any).fixture.status = {
      access: 'unknown', request: 'unknown', requestExpiresAt: null, releaseApproved: false }; });
    await page.getByRole('button', { name: 'Refresh' }).click();
    const attention = page.getByRole('region', { name: 'Needs attention' });
    const shared = page.getByRole('region', { name: 'Shared with you' });
    await expect(attention.getByText('Waiting for reporter to approve update', { exact: true })).toBeVisible();
    await expect(attention.getByText(/recovery key and choose “Approve update”/)).toBeVisible();
    await expect(shared.getByRole('listitem')).toHaveCount(0);
    await expect(page.getByRole('button', { name: /^Request access/ })).toHaveCount(0);
    await expect(attention.getByRole('button', { name: 'Check report access' })).toBeVisible();
    await page.evaluate(() => { (window as any).fixture.status = {
      access: 'granted', request: 'unknown', releaseApproved: true, expiresAt: null, contactShared: false }; });
    await page.getByRole('button', { name: 'Refresh' }).click();
    await expect(shared.getByText('Access allowed', { exact: true })).toBeVisible();
    await expect(shared.getByRole('button', { name: 'Open report' })).toBeVisible();
    await expect(attention.getByRole('listitem')).toHaveCount(0);
    expect(refused).toEqual([]);
  });
}
