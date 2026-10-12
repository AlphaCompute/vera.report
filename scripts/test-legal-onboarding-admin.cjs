// Local browser regression for the admin "Legal organizations" screens and the
// invitation page, using the real Next pages, a synthetic local admin session and
// an in-memory roster with real signed public-key candidates behind intercepted
// admin API routes. Never connects to
// Auth0, a deployed backend or an enclave; nothing here issues a real invitation.
// Requires root dependencies and `npm --prefix qa ci`.
const { spawn } = require('node:child_process');
const { createServer } = require('node:net');
const { createHash, randomBytes } = require('node:crypto');
const { pathToFileURL } = require('node:url');
const path = require('node:path');
const { mkdirSync } = require('node:fs');
const { tmpdir } = require('node:os');
const openpgp = require('openpgp');
const { chromium, expect: baseExpect } = require('../qa/node_modules/@playwright/test');
const expect = baseExpect.configure({ timeout: 30000 });

const ORG = randomBytes(32).toString('hex');
const DOMAIN = 'harbor.example';
const SECOND_ORG = randomBytes(32).toString('hex');
const SECOND_DOMAIN = 'ridge.example';
// Dev pages compile on first visit; allow for a busy machine.
const COMPILE_MS = 300000;

async function firmBinding(organizationId = ORG, domain = DOMAIN) {
  const { privateKey } = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic firm' }], format: 'object' });
  const publicKey = privateKey.toPublic();
  const recipientKeyId = createHash('sha256').update(publicKey.write()).digest('hex');
  const statement = { format: 'vera-firm-key-binding/v1', domain, organizationId, recipientKeyId, issuedAt: Date.now() };
  const signature = await openpgp.sign({ message: await openpgp.createMessage({ binary: new TextEncoder().encode(JSON.stringify(statement)) }),
    signingKeys: privateKey, detached: true, format: 'armored' });
  return { recipientKeyId, publicKey: publicKey.armor(), document: JSON.stringify({ binding: statement, publicKey: publicKey.armor(), signature }) };
}

(async () => {
  const reservation = createServer();
  await new Promise(resolve => reservation.listen(0, '127.0.0.1', resolve));
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const base = `http://127.0.0.1:${port}`;
  const secret = randomBytes(32).toString('hex');
  const providerFixture = path.join(__dirname, 'test-admin-provider.cjs').replace(/\\/g, '/');
  const server = spawn(process.execPath, [require.resolve('next/dist/bin/next'), 'dev', '--webpack', '--hostname', '127.0.0.1', '--port', String(port)], {
    cwd: path.resolve(__dirname, '..'),
    env: { ...process.env, NODE_OPTIONS: `${process.env.NODE_OPTIONS || ''} --require="${providerFixture}"`, AUTH0_SECRET: secret,
      AUTH0_DOMAIN: 'synthetic.invalid', AUTH0_CLIENT_ID: 'synthetic', AUTH0_CLIENT_SECRET: 'synthetic', AUTH0_MGMT_CLIENT_ID: 'synthetic-browser-test',
      AUTH0_MGMT_CLIENT_SECRET: 'synthetic-browser-test', ADMIN_ALLOWED_DOMAINS: 'alphacompute.ai', APP_BASE_URL: base, TENANT_ORG_ID: '',
      BACKEND_URL: 'http://127.0.0.1:1', INTERNAL_API_SECRET: 'synthetic-local-admin-ui-internal-secret',
      NEXT_PUBLIC_CONFIDENTIAL_CASES: '1', NEXT_PUBLIC_CONFIDENTIAL_RELEASE_MANIFEST: 'synthetic-release-manifest',
      NEXT_PUBLIC_ONBOARDING_AUTH0_DOMAIN: 'onboarding.synthetic.test', NEXT_PUBLIC_ONBOARDING_AUTH0_CLIENT_ID: 'synthetic-onboarding-client',
      NEXT_PUBLIC_ONBOARDING_AUTH0_AUDIENCE: 'https://api.synthetic.test/onboarding', NEXT_PUBLIC_ONBOARDING_AUTH0_ORGANIZATION: '' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '', browser;
  for (const output of [server.stdout, server.stderr]) output.on('data', data => { logs = (logs + data).slice(-12000); });
  try {
    const binding = await firmBinding();
    const secondBinding = await firmBinding(SECOND_ORG, SECOND_DOMAIN);
    const deadline = Date.now() + 240000; // First dev compile can be slow on a busy machine.
    let ready = false;
    while (Date.now() < deadline && server.exitCode === null) {
      try { if ((await fetch(base, { signal: AbortSignal.timeout(2000) })).ok) { ready = true; break; } } catch {}
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    if (!ready) throw new Error('Local Next server did not start');
    const { encrypt } = await import(pathToFileURL(path.resolve(__dirname, '../node_modules/@auth0/nextjs-auth0/dist/server/cookies.js')).href);
    const now = Math.floor(Date.now() / 1000);
    const session = await encrypt({ user: { sub: 'synthetic-admin', email: 'qa@alphacompute.ai', email_verified: true, 'https://vera.app/roles': ['admin'] },
      tokenSet: { accessToken: 'synthetic', expiresAt: now + 3600 }, internal: { sid: 'synthetic-local-only', createdAt: now } }, secret, now + 3600);
    browser = await chromium.launch({ headless: true, args: ['--disable-webgl'] });
    const context = await browser.newContext({ locale: 'en-US', timezoneId: 'America/New_York' });
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await context.addCookies([{ name: '__session', value: session, url: base, httpOnly: true, sameSite: 'Lax' }]);

    // In-memory roster standing in for the admin API (the proxy/router are unit-tested).
    const roster = { organizations: [], invitations: [], members: [], audit: [] };
    let domainMode = 'missing', createConflict = true;
    let deferredDomain = null, releaseDomain = null, deferredStarted = false;
    const mutations = [];
    let onboardingExchanges = 0;
    const event = (action, organizationId, extra = {}) => roster.audit.unshift({ eventId: randomBytes(16).toString('hex'), at: Date.now(),
      action, organizationId, actor: 'qa@alphacompute.ai', invitationId: null, subject: null, ...extra });
    const view = org => ({ ...org, pendingInvitations: roster.invitations.filter(item => item.status === 'pending').length,
      activeMembers: roster.members.filter(item => item.status === 'active').length });
    const handleRoute = async route => {
      const request = route.request(), url = new URL(request.url());
      // Complete the real PKCE callback with a synthetic provider, without network access.
      if (url.origin === 'https://onboarding.synthetic.test') {
        if (url.pathname === '/authorize') {
          expect(url.searchParams.get('redirect_uri')).toBe(`${base}/legal/administration`);
          expect(url.searchParams.get('scope')).toBe('openid legal:invite');
          expect(url.searchParams.get('code_challenge_method')).toBe('S256');
          const callback = new URL('/legal/administration', base);
          callback.searchParams.set('code', 'synthetic-onboarding-code');
          callback.searchParams.set('state', url.searchParams.get('state'));
          return route.fulfill({ status: 302, headers: { location: callback.href } });
        }
        if (url.pathname === '/oauth/token' && request.method() === 'POST') {
          const body = new URLSearchParams(request.postData());
          expect(body.get('code')).toBe('synthetic-onboarding-code');
          expect(body.get('code_verifier')).toMatch(/^[A-Za-z0-9_-]{43}$/);
          onboardingExchanges++;
          return route.fulfill({ headers: { 'access-control-allow-origin': base },
            json: { access_token: 'synthetic-onboarding-access', token_type: 'Bearer', expires_in: 300 } });
        }
        return route.abort();
      }
      if (url.origin !== base) return route.abort();
      if (!url.pathname.startsWith('/api/')) return route.continue();
      const legal = url.pathname.match(/^\/api\/admin\/confidential\/legal\/(.+)$/);
      if (!legal) return route.fulfill({ status: 200, json: { success: true, data: { reports: [], entries: [] }, alerts: [] } });
      const pathName = legal[1], method = request.method();
      if (method === 'POST') {
        expect(request.headers()['content-type']).toContain('application/json');
        mutations.push(pathName);
      }
      if (pathName === 'organizations' && method === 'GET') return route.fulfill({ json: { success: true, organizations: roster.organizations.map(view) } });
      if (pathName === 'organizations' && method === 'POST') {
        const body = request.postDataJSON();
        expect(Object.keys(body).sort()).toEqual(['displayName', 'domain', 'providerOrganizationId']);
        if (createConflict) { createConflict = false; return route.fulfill({ status: 409, json: { success: false, error: 'duplicate-domain' } }); }
        const organization = { organizationId: ORG, ...body, status: 'awaiting-registration', recipientKeyId: null, publicKey: null,
          createdAt: Date.now(), createdBy: 'qa@alphacompute.ai', registeredAt: null, revokedAt: null, revokedBy: null };
        roster.organizations.push(organization);
        event('organization_created', ORG);
        return route.fulfill({ status: 201, json: { success: true, organization: view(organization) } });
      }
      const selected = roster.organizations.find(org => pathName === `organizations/${org.organizationId}`);
      if (selected && method === 'GET') {
        if (selected.domain === deferredDomain) { deferredStarted = true; await new Promise(resolve => { releaseDomain = resolve; }); }
        const selectedBinding = selected.organizationId === SECOND_ORG ? secondBinding : binding;
        return route.fulfill({ json: { success: true, organization: { ...view(selected),
          candidateBindingDocument: domainMode === 'missing' ? null : selectedBinding.document, candidateSubject: 'auth0|lawyer' },
          invitations: roster.invitations, members: roster.members } });
      }
      if (pathName.startsWith('invitations/') && pathName.endsWith('/revoke')) {
        const invitation = roster.invitations.find(item => pathName === `invitations/${item.invitationId}/revoke`);
        Object.assign(invitation, { status: 'revoked', revokedAt: Date.now(), revokedBy: 'qa@alphacompute.ai' });
        event('invitation_revoked', ORG, { invitationId: invitation.invitationId, subject: invitation.subject });
        return route.fulfill({ json: { success: true } });
      }
      if (pathName === `organizations/${ORG}/members/remove`) {
        const { subject } = request.postDataJSON();
        roster.members.find(item => item.subject === subject).status = 'removed';
        event('member_removed', ORG, { subject });
        return route.fulfill({ json: { success: true } });
      }
      if (pathName === `organizations/${ORG}/revoke`) {
        Object.assign(roster.organizations[0], { status: 'revoked', revokedAt: Date.now(), revokedBy: 'qa@alphacompute.ai' });
        roster.invitations.filter(item => item.status === 'pending').forEach(item => { item.status = 'revoked'; });
        roster.members.filter(item => item.status === 'active').forEach(item => { item.status = 'removed'; });
        event('organization_revoked', ORG);
        return route.fulfill({ json: { success: true, invitationsRevoked: 0, membersRemoved: 1 } });
      }
      if (pathName.startsWith('audit')) {
        const scoped = url.searchParams.get('organizationId');
        return route.fulfill({ json: { success: true, events: roster.audit.filter(item => !scoped || item.organizationId === scoped), next: null } });
      }
      return route.fulfill({ status: 404, json: { success: false, error: 'not-found' } });
    };

    const page = await context.newPage();
    // Clicks that navigate wait for the next page's first dev compile.
    page.setDefaultTimeout(COMPILE_MS);
    await page.route('**/*', handleRoute);
    await page.goto(`${base}/legal/organizations`, { waitUntil: 'domcontentloaded', timeout: COMPILE_MS });
    await expect(page.getByRole('heading', { name: 'Legal organizations' })).toBeVisible({ timeout: COMPILE_MS });
    await expect(page.getByText('No legal organizations yet')).toBeVisible();

    // Create: local validation, then a server conflict attached to its field, then success.
    await page.getByRole('button', { name: 'Add legal organization' }).click();
    await expect(page.getByRole('heading', { name: 'Add a legal organization' })).toBeFocused();
    await page.getByRole('button', { name: 'Add organization' }).click();
    await expect(page.getByText('Enter the organization’s name (2 to 160 characters).')).toBeVisible();
    await expect(page.getByLabel('Organization’s own web domain')).toHaveAttribute('aria-invalid', 'true');
    expect(mutations).toEqual([]);
    await page.getByLabel('Organization name').fill('Harbor Counsel LLP');
    await page.getByLabel('Organization’s own web domain').fill('https://Harbor.Example/');
    await page.getByLabel('Identity-provider organization ID').fill('org_harbor');
    await page.getByRole('button', { name: 'Add organization' }).click();
    await expect(page.getByText('Another active legal organization already uses this domain.')).toBeVisible();
    await page.getByRole('button', { name: 'Add organization' }).click();
    await expect(page.getByRole('heading', { name: 'Harbor Counsel LLP' })).toBeFocused();
    await expect(page.getByText('Waiting for key').first()).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Send these details to the organization' })).toBeVisible();
    await page.getByRole('button', { name: 'Copy instructions' }).click();
    const note = await page.evaluate(() => navigator.clipboard.readText());
    expect(note).toContain(ORG);
    expect(note).toContain('Submit your organization profile');

    // Domain check: each failure explained, then a verified, grouped Key ID.
    await page.getByRole('button', { name: 'Check submitted key' }).click();
    await expect(page.getByText('The organization has not submitted its public key yet.')).toBeVisible();
    domainMode = 'published';
    await page.getByRole('button', { name: 'Check again' }).click();
    await expect(page.getByText('The submitted public key has a valid signature.')).toBeVisible();
    await expect(page.getByText(binding.recipientKeyId.slice(0, 4) + ' ' + binding.recipientKeyId.slice(4, 8), { exact: false })).toBeVisible();
    await expect(page.getByText('Confirm this Key ID with an authorized representative by phone or in person', { exact: false })).toBeVisible();

    const screenshots = path.join(tmpdir(), `vera-legal-onboarding-${Date.now()}`);
    mkdirSync(screenshots, { recursive: true });
    await page.screenshot({ path: path.join(screenshots, 'detail-awaiting-desktop.png'), fullPage: true });

    // The organization registers and one person joins (as the enclave would record it).
    Object.assign(roster.organizations[0], { status: 'active', recipientKeyId: binding.recipientKeyId, publicKey: binding.publicKey, registeredAt: Date.now() });
    const soon = Date.now() + 60 * 60 * 1000;
    roster.invitations.push({ invitationId: randomBytes(32).toString('hex'), subject: 'auth0|associate', createdAt: Date.now(), createdBy: 'auth0|operator',
      expiresAt: Date.now() + 3 * 86400000, status: 'pending', revokedAt: null, revokedBy: null });
    roster.invitations.push({ invitationId: randomBytes(32).toString('hex'), subject: 'auth0|lawyer', createdAt: Date.now() - 1000, createdBy: 'auth0|operator',
      expiresAt: soon, status: 'accepted', revokedAt: null, revokedBy: null });
    roster.members.push({ subject: 'auth0|lawyer', status: 'active', accessUntil: soon, updatedAt: Date.now() });
    event('organization_registered', ORG);
    event('invitation_issued', ORG, { actor: 'auth0|operator', subject: 'auth0|associate' });
    await page.getByRole('button', { name: 'Back to legal organizations' }).first().click();
    const row = page.getByRole('row', { name: /Harbor Counsel LLP/ });
    await expect(row.getByText('Active')).toBeVisible();
    await row.getByRole('button', { name: 'Open Harbor Counsel LLP' }).click();
    await expect(page.getByText('Ends soon')).toBeVisible();
    await page.getByRole('button', { name: 'Check submitted key' }).click();
    await expect(page.getByText('Onboarding progress')).toBeVisible();

    // Revoke a pending invitation.
    await page.getByRole('button', { name: 'Revoke invitation for auth0|associate' }).click();
    await expect(page.getByRole('alertdialog')).toContainText('stops working immediately');
    await page.getByRole('alertdialog').getByRole('button', { name: 'Revoke invitation' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Invitation for auth0|associate revoked' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Revoke invitation for auth0|associate' })).toHaveCount(0);

    // Mobile layout: no horizontal page scroll on the busiest screen.
    await page.setViewportSize({ width: 375, height: 812 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
    await page.screenshot({ path: path.join(screenshots, 'detail-active-mobile.png'), fullPage: true });
    await page.setViewportSize({ width: 1280, height: 900 });

    // Remove the member.
    await page.getByRole('button', { name: 'Remove auth0|lawyer' }).click();
    await expect(page.getByRole('alertdialog')).toContainText('cannot be recalled');
    await page.getByRole('alertdialog').getByRole('button', { name: 'Remove person' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'auth0|lawyer removed' })).toBeVisible();

    // Revoking the organization needs its domain typed.
    await page.getByRole('button', { name: 'Revoke organization' }).click();
    const confirm = page.getByRole('alertdialog').getByRole('button', { name: 'Revoke organization' });
    await expect(confirm).toBeDisabled();
    await page.getByLabel(`Type ${DOMAIN} to confirm`).fill('wrong.example');
    await expect(confirm).toBeDisabled();
    await page.getByLabel(`Type ${DOMAIN} to confirm`).fill(DOMAIN);
    await confirm.click();
    await expect(page.getByText('Revoked', { exact: true }).first()).toBeVisible();
    await expect(page.getByRole('button', { name: 'Issue invitation' })).toHaveCount(0);
    await expect(page.getByRole('list').getByText('Organization revoked')).toBeVisible();

    // Global audit trail.
    await page.getByRole('button', { name: 'Back to legal organizations' }).first().click();
    await page.getByRole('button', { name: /Show revoked/ }).click();
    await page.getByRole('button', { name: 'Audit trail' }).click();
    await expect(page.getByRole('heading', { name: 'Onboarding audit trail' })).toBeVisible();
    await expect(page.getByText('Invitation revoked')).toBeVisible();
    await expect(page.getByText('Harbor Counsel LLP').first()).toBeVisible();

    // Invitation page: roster from the admin API, domain checked in the browser, and
    // nothing can be issued before the onboarding sign-in and authority key.
    Object.assign(roster.organizations[0], { status: 'active', revokedAt: null, revokedBy: null });
    roster.organizations.push({ ...roster.organizations[0], organizationId: SECOND_ORG, domain: SECOND_DOMAIN,
      displayName: 'Ridge Counsel LLP', providerOrganizationId: 'org_ridge', recipientKeyId: secondBinding.recipientKeyId, publicKey: secondBinding.publicKey });
    await page.goto('about:blank');
    await page.goto(`${base}/legal/organizations`, { waitUntil: 'domcontentloaded' });
    await page.getByRole('button', { name: 'Open Harbor Counsel LLP' }).click();
    await page.getByRole('button', { name: 'Issue invitation' }).click();
    await page.waitForURL(`${base}/legal/administration`, { timeout: COMPILE_MS });
    await expect(page.getByRole('heading', { name: 'Legal onboarding' })).toBeVisible({ timeout: COMPILE_MS });
    await expect(page.getByLabel('Organization', { exact: true })).toHaveValue(ORG);
    await expect(page.getByText('This is the registered key.')).toBeVisible();
    // A slow response for the previous selection must never replace the selected firm's key.
    deferredDomain = DOMAIN; deferredStarted = false;
    await page.getByRole('button', { name: 'Check again', exact: true }).click();
    await expect.poll(() => deferredStarted).toBe(true);
    await page.getByLabel('Organization', { exact: true }).selectOption(SECOND_ORG);
    const secondKey = secondBinding.recipientKeyId.match(/.{1,4}/g).join(' ');
    await expect(page.getByText(secondKey, { exact: true })).toBeVisible();
    const staleResponse = page.waitForResponse(response => response.url() === `${base}/api/admin/confidential/legal/organizations/${ORG}`);
    deferredDomain = null; releaseDomain();
    await staleResponse;
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await expect(page.getByText(secondKey, { exact: true })).toBeVisible();
    await expect(page.getByText(binding.recipientKeyId.match(/.{1,4}/g).join(' '), { exact: true })).toHaveCount(0);
    // A stalled domain request must settle without keeping the UI busy indefinitely.
    deferredDomain = SECOND_DOMAIN; deferredStarted = false;
    await page.getByRole('button', { name: 'Check again', exact: true }).click();
    await expect.poll(() => deferredStarted).toBe(true);
    await expect(page.getByText('The organization key could not be loaded.', { exact: false }).first()).toBeVisible({ timeout: 20000 });
    await expect(page.getByRole('button', { name: 'Check again', exact: true })).toBeEnabled();
    deferredDomain = null; releaseDomain();
    await page.getByLabel('Organization', { exact: true }).selectOption(ORG);
    await expect(page.getByText('This is the registered key.')).toBeVisible();

    await expect(page.getByRole('button', { name: 'Sign in with the onboarding account' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Issue invitation' })).toBeDisabled();
    await expect(page.getByText('Independently confirm the organization’s Key ID by phone or in person.', { exact: true })).toBeVisible();
    await expect(page.getByLabel('Their user ID in the legal sign-in tenant')).toHaveValue('');
    await expect(page.getByLabel('Key ID read back by the organization')).toHaveValue('');
    await page.getByLabel('Their user ID in the legal sign-in tenant').fill('not an id');
    await page.getByLabel('Access lasts').focus();
    await expect(page.getByText('Enter a user ID such as')).toBeVisible();

    // Satisfy every other gate first, so a disabled Issue button proves readback validation.
    await page.getByRole('button', { name: 'Sign in with the onboarding account' }).click();
    await expect(page.getByText('Signed in with the onboarding account.', { exact: false })).toBeVisible();
    expect(onboardingExchanges).toBe(1);
    await expect(page.getByText('This is the registered key.')).toBeVisible();
    await expect(page.getByLabel('Their user ID in the legal sign-in tenant')).toHaveValue('');
    await page.getByLabel('Their user ID in the legal sign-in tenant').fill('auth0|lawyer');
    await page.getByRole('checkbox', { name: /I independently verified this person/ }).check();
    // This test only checks form gating; no signing or invitation request is made.
    await page.getByLabel('Encrypted onboarding authority key file').setInputFiles({
      name: 'synthetic-authority.txt', mimeType: 'text/plain', buffer: Buffer.from('synthetic-local-only') });
    await page.getByLabel('Key recovery code').fill('synthetic-local-only');
    const readback = page.getByLabel('Key ID read back by the organization');
    const keyConfirmation = page.getByRole('checkbox', { name: /I confirmed this Key ID/ });
    const issue = page.getByRole('button', { name: 'Issue invitation', exact: true });
    await readback.fill(binding.recipientKeyId);
    await keyConfirmation.check();
    await expect(issue).toBeEnabled();
    const wrongKeyId = (binding.recipientKeyId[0] === '0' ? '1' : '0') + binding.recipientKeyId.slice(1);
    await readback.fill(wrongKeyId);
    await expect(keyConfirmation).not.toBeChecked();
    await keyConfirmation.check();
    await expect(issue).toBeDisabled();
    await expect(page.getByText('Independently confirm the organization’s Key ID by phone or in person.', { exact: true })).toBeVisible();
    await readback.fill(binding.recipientKeyId);
    await expect(keyConfirmation).not.toBeChecked();
    await expect(issue).toBeDisabled();
    await keyConfirmation.check();
    await expect(issue).toBeEnabled();
    await page.setViewportSize({ width: 375, height: 812 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
    await page.screenshot({ path: path.join(screenshots, 'invitation-mobile.png'), fullPage: true });

    expect(mutations.filter(item => item === 'organizations')).toHaveLength(2);
    console.log(`Screenshots: ${screenshots}`);
    console.log('PASS: legal organization create/validate/conflict, domain check failure and verified Key ID, invitation and member revocation, typed-domain organization revocation, audit trail, invitation page gating, mismatched Key ID blocks issuance after sign-in, readback changes clear confirmation, stale organization response isolation, bounded domain timeout, mobile width');
  } catch (error) {
    console.error(logs);
    throw error;
  } finally {
    if (browser) await browser.close();
    server.kill('SIGTERM');
    await new Promise(resolve => { if (server.exitCode !== null) resolve(); else server.once('exit', resolve); });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
