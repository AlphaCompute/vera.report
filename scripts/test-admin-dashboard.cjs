// Local browser regression using the real admin page, a synthetic local session,
// and intercepted API responses. Never connects to Auth0 or a deployed backend.
// Requires root dependencies and `npm --prefix qa ci`.
const { spawn } = require('node:child_process');
const { createServer } = require('node:net');
const { pathToFileURL } = require('node:url');
const path = require('node:path');
const { mkdirSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { chromium, expect } = require('../qa/node_modules/@playwright/test');
// This suite covers legacy admin records; the confidential suites supply a release.
process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = '0';

(async () => {
  const reservation = createServer();
  await new Promise(resolve => reservation.listen(0, '127.0.0.1', resolve));
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const base = `http://127.0.0.1:${port}`;
  const secret = 'admin-ui-synthetic-secret-not-a-live-credential-2026';
  const providerFixture = path.join(__dirname, 'test-admin-provider.cjs');
  const server = spawn(process.execPath, [require.resolve('next/dist/bin/next'), 'dev', '--webpack', '--hostname', '127.0.0.1', '--port', String(port)], {
    cwd: path.resolve(__dirname, '..'),
    env: { ...process.env, NODE_OPTIONS: `${process.env.NODE_OPTIONS || ''} --require="${providerFixture}"`, AUTH0_SECRET: secret, AUTH0_DOMAIN: 'synthetic.invalid', AUTH0_CLIENT_ID: 'synthetic', AUTH0_CLIENT_SECRET: 'synthetic', AUTH0_MGMT_CLIENT_ID: 'synthetic-browser-test', AUTH0_MGMT_CLIENT_SECRET: 'synthetic-browser-test', ADMIN_ALLOWED_DOMAINS: 'alphacompute.ai', APP_BASE_URL: base, TENANT_ORG_ID: '', BACKEND_URL: 'http://127.0.0.1:1', INTERNAL_API_SECRET: 'synthetic-local-admin-ui-internal-secret' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let logs = '', browser;
  for (const output of [server.stdout, server.stderr]) output.on('data', data => { logs = (logs + data).slice(-12000); });
  try {
    const deadline = Date.now() + 90000;
    let ready = false;
    while (Date.now() < deadline && server.exitCode === null) {
      try { if ((await fetch(base, { signal: AbortSignal.timeout(2000) })).ok) { ready = true; break; } } catch {}
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    if (!ready) throw new Error('Local Next server did not start');
    const { encrypt } = await import(pathToFileURL(path.resolve(__dirname, '../node_modules/@auth0/nextjs-auth0/dist/server/cookies.js')).href);
    const now = Math.floor(Date.now() / 1000);
    const session = await encrypt({ user: { sub: 'synthetic-admin', email: 'qa@alphacompute.ai', email_verified: true, 'https://vera.app/roles': ['admin'] }, tokenSet: { accessToken: 'synthetic', expiresAt: now + 3600 }, internal: { sid: 'synthetic-local-only', createdAt: now } }, secret, now + 3600);
    // Match the existing browser CI checks: the decorative WebGL background
    // need not consume the runner's software renderer during data-flow tests.
    browser = await chromium.launch({ headless: true, args: ['--disable-webgl'] });
    // A non-UTC browser zone catches accidental server/UTC timestamp formatting.
    const context = await browser.newContext({ locale: 'en-US', timezoneId: 'America/New_York' });
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await context.addCookies([{ name: '__session', value: session, url: base, httpOnly: true, sameSite: 'Lax' }]);
    const page = await context.newPage();
    await page.clock.install();
    const report = { reportId: 'VRA-0000000000000001', trackingId: 'VRA-0000000000000001', category: 'Synthetic QA report', description: 'Synthetic data only', submittedAt: '2026-09-22T10:15:00Z', status: 'pending', priority: 'low' };
    const stats = { total: 1, pending: 1, reviewing: 0, investigating: 0, resolved: 0, dismissed: 0, critical: 0, averageAuthenticity: 0, byCategory: {}, byPriority: {}, recentTrend: [], lastUpdated: new Date().toISOString() };
    let mode = 'unavailable', requests = 0, rejectStatus = false;
    let reviewed = false, statusPolls = 0, channelApprovals = 0, routingRequests = 0, relayRequests = 0, generatedLinks = 0, emailRequests = 0, emailsSent = 0;
    const handleRoute = async route => {
      const url = new URL(route.request().url());
      if (url.origin !== base) return route.abort();
      if (!url.pathname.startsWith('/api/')) return route.continue();
      if (url.pathname.endsWith('/approve')) channelApprovals++;
      if (url.pathname.endsWith('/relay')) relayRequests++;
      if (url.pathname === `/api/admin/dashboard/reports/${report.reportId}/status`) {
        if (rejectStatus) return route.fulfill({ status: 503, json: { success: false } });
        expect(route.request().postDataJSON()).toEqual({ status: 'investigating' });
        report.activity = [{ id: 'status-1', type: 'status', description: 'Status: resolved', timestamp: '2026-09-22T10:15:20Z' }];
        return route.fulfill({ json: { success: true, data: { status: report.status, activity: report.activity } } });
      }
      if (url.pathname === `/api/admin/dashboard/reports/${report.reportId}/notes`) {
        if (route.request().method() === 'GET') return route.fulfill({ json: { success: true, notes: savedNotes } });
        if (rejectNote) { rejectNote = false; return route.fulfill({ status: 503, json: { success: false } }); }
        const note = { id: 'note-1', text: route.request().postDataJSON().text, timestamp: '2026-09-22T10:15:30Z' };
        savedNotes.push(note);
        return route.fulfill({ status: 201, json: { success: true, note } });
      }
      if (url.pathname === `/api/admin/narrative/${report.reportId}`) return route.fulfill({ json: { success: true, narrative: 'Synthetic reviewed narrative' } });
      if (url.pathname === `/api/dissemination/${report.reportId}/status`) {
        statusPolls++;
        return route.fulfill({ json: { success: true,
          consent: { agency: false, legalReview: true, psst: { granted: false }, capturedAt: new Date().toISOString(), textVersion: 'v3-legal-review-default' },
          channels: [{ entityId: 'ftc', entityName: 'Federal Trade Commission', tier: 'B', state: 'dispatched', attempts: 1, receipts: [], handoff: { url: 'https://synthetic.invalid', fields: {}, depositBody: 'Historical agency handoff' } }],
          audit: [], disposition: reviewed ? { channels: [], approvedBy: '', narrativeReviewedAt: new Date().toISOString(), narrativeReviewedBy: 'synthetic-admin' } : null } });
      }
      if (url.pathname.endsWith('/redact')) {
        expect(route.request().postDataJSON()).toEqual({ mode: 'mark-clean' });
        reviewed = true;
        return route.fulfill({ json: { success: true } });
      }
      if (url.pathname.endsWith('/plan')) { routingRequests++; return route.fulfill({ json: { success: true, plan: {
        trackingId: report.trackingId, categories: [], channels: [],
        consent: { agency: true, psst: { granted: false }, capturedAt: new Date().toISOString(), textVersion: 'v1' },
        generatedAt: new Date().toISOString(),
      } } }); }
      if (url.pathname.endsWith('/secure-packet-generate')) {
        generatedLinks++;
        return route.fulfill(reviewed
          ? { json: { success: true, url: `${base}/synthetic-generated-packet` } }
          : { status: 409, json: { success: false, error: 'narrative_review_required' } });
      }
      if (url.pathname.endsWith('/secure-packet-email')) {
        emailRequests++;
        expect(route.request().postDataJSON()).toEqual({ recipientEmail: 'recipient@example.org' });
        if (reviewed) emailsSent++;
        return route.fulfill(reviewed
          ? { json: { success: true, url: `${base}/synthetic-secure-packet`, sentTo: 'test@example.org', mode: 'dryrun' } }
          : { status: 409, json: { success: false, error: 'narrative_review_required' } });
      }
      const isAlerts = url.pathname === '/api/dissemination/alerts';
      if (!isAlerts && !/\/dashboard\/(stats|reports)$/.test(url.pathname)) return route.fulfill({ status: 200, json: { success: true, data: { entries: [], partners: [], rules: [] } } });
      requests++;
      if (mode === 'rate-limited') return route.fulfill({ status: 429, headers: { 'Retry-After': '900' }, json: { error: 'PRIVATE QUOTA DETAIL', retryAfter: 900 } });
      if (isAlerts) return route.fulfill({ status: 200, json: { success: true, alerts: [] } });
      if (mode === 'unavailable') return route.fulfill({ status: 503, json: { error: 'PRIVATE BACKEND DETAIL' } });
      if (mode === 'stats-unavailable' && url.pathname.endsWith('/stats')) return route.fulfill({ status: 503, json: { error: 'PRIVATE BACKEND DETAIL' } });
      if (mode === 'forbidden') return route.fulfill({ status: 403, json: { error: 'PRIVATE ACCESS DETAIL' } });
      if (mode === 'malformed' && url.pathname.endsWith('/reports')) return route.fulfill({ status: 200, json: { success: true, data: {} } });
      return route.fulfill({ status: 200, json: { success: true, data: url.pathname.endsWith('/stats') ? stats : { reports: mode === 'empty' ? [] : [report] } } });
    };
    const savedNotes = [];
    let rejectNote = true;
    await page.route('**/*', handleRoute);
    // The first authenticated request compiles /admin in this development server.
    // Give that startup work the same bounded budget as the initial server check.
    await page.goto(`${base}/admin`, { waitUntil: 'domcontentloaded', timeout: 90000 });
    await expect(page.getByRole('alert', { name: 'Data loading error' })).toContainText('Unable to load dashboard data');
    await expect(page.getByText('Total Reports', { exact: true })).toHaveCount(0);
    await expect(page.getByText('PRIVATE BACKEND DETAIL')).toHaveCount(0);
    await page.getByRole('button', { name: 'Reports', exact: true }).first().click();
    await expect(page.getByRole('alert', { name: 'Data loading error' })).toContainText('Unable to load reports');
    await expect(page.getByText('No reports', { exact: true })).toHaveCount(0);

    mode = 'healthy';
    const beforeRetry = requests;
    await page.getByRole('button', { name: 'Retry loading data' }).click();
    await expect(page.getByText(report.category, { exact: true })).toBeVisible();
    await expect(page.getByRole('alert', { name: 'Data loading error' })).toHaveCount(0);
    expect(requests).toBeGreaterThanOrEqual(beforeRetry + 2);

    const submittedTimestamp = 'Sep 22, 2026, 06:15:00 AM EDT';
    await expect(page.getByText(submittedTimestamp, { exact: true }).first()).toBeVisible();

    mode = 'stats-unavailable';
    await page.getByRole('button', { name: 'Dashboard', exact: true }).first().click();
    await page.getByRole('button', { name: 'Refresh reports', exact: true }).click();
    await expect(page.getByRole('alert', { name: 'Data loading error' })).toContainText('Report statistics could not be loaded');
    await page.getByRole('button', { name: 'Reports', exact: true }).first().click();
    await expect(page.getByText(report.category, { exact: true })).toBeVisible();
    await expect(page.getByText(/Summary unavailable/)).toBeVisible();

    mode = 'forbidden';
    await page.getByRole('button', { name: 'Refresh reports', exact: true }).click();
    await expect(page.getByRole('alert', { name: 'Data loading error' })).toContainText('Your account does not have access');
    await expect(page.getByText(report.category, { exact: true })).toHaveCount(0);

    mode = 'malformed';
    await page.getByRole('button', { name: 'Retry loading data' }).click();
    await expect(page.getByRole('alert', { name: 'Data loading error' })).toContainText('Reports could not be loaded. Try again.');
    await expect(page.getByText('No reports', { exact: true })).toHaveCount(0);

    mode = 'empty';
    await page.getByRole('button', { name: 'Retry loading data' }).click();
    await expect(page.getByRole('alert', { name: 'Data loading error' })).toHaveCount(0);
    await expect(page.getByText('No reports', { exact: true }).first()).toBeVisible();

    mode = 'rate-limited';
    await page.getByRole('button', { name: 'Refresh reports', exact: true }).click();
    await expect(page.getByRole('alert', { name: 'Data loading error' })).toContainText('Automatic refresh will resume after');
    await expect(page.getByText('PRIVATE QUOTA DETAIL')).toHaveCount(0);
    await page.clock.runFor(31_000); // The alerts poll also sees the 429.
    const throttledRequests = requests;
    await page.getByRole('button', { name: 'Retry loading data' }).click();
    await page.getByRole('button', { name: 'Refresh reports', exact: true }).click();
    await page.clock.runFor(60_000);
    expect(requests).toBe(throttledRequests); // No manual or automatic requests during cooldown.
    mode = 'healthy';
    await page.clock.fastForward(900_000);
    await page.clock.runFor(31_000);
    await expect(page.getByText(report.category, { exact: true })).toBeVisible();
    await expect(page.getByRole('alert', { name: 'Data loading error' })).toHaveCount(0);
    expect(requests).toBeGreaterThan(throttledRequests);
    await page.getByRole('button', { name: 'Open Report', exact: true }).click();
    await expect(page.getByText(submittedTimestamp, { exact: true }).first()).toBeVisible();
    // A same-ID report refreshed by polling must update the open detail status.
    report.status = 'resolved';
    await page.clock.runFor(31_000);
    await expect(page.getByText('Resolved', { exact: true })).toHaveCount(2);
    // A concurrent update can leave the persisted value unchanged while the
    // requested value differs; neither the control nor toast may claim it won.
    await page.getByRole('button', { name: 'Investigating', exact: true }).click();
    await expect(page.getByText('Status saved as Resolved.', { exact: true })).toBeVisible();
    await expect(page.getByText('Resolved', { exact: true })).toHaveCount(2);
    await expect(page.getByText('Status: resolved', { exact: true })).toBeVisible();
    await expect(page.getByText('Status saved as Investigating.', { exact: true })).toHaveCount(0);
    await page.clock.runFor(6_000);
    await expect(page.getByText('Status saved as Resolved.', { exact: true })).toHaveCount(0);
    rejectStatus = true;
    await page.getByRole('button', { name: 'Dismissed', exact: true }).click();
    await expect(page.getByText('Status could not be saved. Please try again.', { exact: true })).toBeVisible();
    await expect(page.getByText('Resolved', { exact: true })).toHaveCount(2);
    await page.clock.runFor(6_000);
    await expect(page.getByText('Status could not be saved. Please try again.', { exact: true })).toHaveCount(0);
    rejectStatus = false;
    const noteInput = page.getByRole('textbox', { name: 'Internal note' });
    const addNote = page.getByRole('button', { name: 'Add Note', exact: true });
    await expect(addNote).toBeDisabled();
    await noteInput.fill('   ');
    await expect(addNote).toBeDisabled();
    await expect(noteInput).toHaveAttribute('maxlength', '5000');
    await noteInput.fill('Synthetic internal note');
    await addNote.click();
    await expect(page.getByRole('alert').filter({ hasText: 'Could not save your note' })).toBeVisible();
    await expect(noteInput).toHaveValue('Synthetic internal note');
    await addNote.click();
    await expect(page.getByRole('status')).toContainText('Saved note in activity');
    await expect(noteInput).toHaveValue('');
    await expect(page.getByText('Synthetic internal note', { exact: true })).toBeVisible();
    const noteTimestamp = 'Sep 22, 2026, 06:15:30 AM EDT';
    await expect(page.getByText(noteTimestamp, { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Back', exact: true }).click();
    await page.getByRole('button', { name: 'Open Report', exact: true }).click();
    await expect(page.getByText('Synthetic internal note', { exact: true })).toBeVisible();
    await expect(page.getByText('Narrative Review', { exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Secure Report Sharing', exact: true })).toBeVisible();
    for (const label of ['Recommended Plan', 'Channels', 'Federal Trade Commission', 'Reporter Relay', 'Government agencies']) {
      await expect(page.getByText(label, { exact: true })).toHaveCount(0);
    }
    for (const name of ['Re-run Routing', 'Run Routing', 'Approve Selected Channels', 'Record Receipt', 'Release Escrow', 'Relay to Reporter']) {
      await expect(page.getByRole('button', { name, exact: true })).toHaveCount(0);
    }
    await expect(page.getByText('Trusted legal reviewers', { exact: true })).toBeVisible();
    await expect(page.getByText('Granted', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Generate and Copy Link', exact: true })).toBeVisible();
    const recipientInput = page.getByRole('textbox', { name: 'Recipient email', exact: true });
    const sendLink = page.getByRole('button', { name: 'Generate and Send Link', exact: true });
    const emailValidation = page.getByRole('alert').filter({ hasText: 'Enter a valid email address.' });
    await expect(sendLink).toBeDisabled();
    await expect(emailValidation).toHaveCount(0);
    for (const value of [
      'invalid-email', 'person@', '@example.org', 'person@example', 'person@@example.org',
      'person name@example.org', 'one@example.org two@example.org', 'a,b@c.org',
      'r\u00e9cipient@example.org', `${'a'.repeat(65)}@example.org`,
      `a@${'b'.repeat(64)}.org`, 'a..b@example.org', 'person@-example.org',
      'person@example..org', 'one@example.org,two@example.org', 'Name <person@example.org>',
    ]) {
      await recipientInput.fill(value);
      await expect(sendLink, `Reject ${JSON.stringify(value)} (input: ${JSON.stringify(await recipientInput.inputValue())})`).toBeDisabled();
      await expect(recipientInput).toHaveAttribute('aria-invalid', 'true');
      await expect(recipientInput).toHaveAccessibleDescription('Enter a valid email address.');
      await expect(emailValidation).toBeVisible();
      await recipientInput.press('Enter');
      expect(emailRequests).toBe(0);
    }
    for (const value of ['', '   ']) {
      await recipientInput.fill(value);
      await expect(sendLink).toBeDisabled();
      await expect(emailValidation).toHaveCount(0);
    }
    await expect(page.getByRole('button', { name: 'Generate and Copy Link', exact: true })).toBeEnabled();
    for (const value of ['reviewer+staging@legal.example.org', 'Reviewer+Case@xn--bcher-kva.org', "o'connor@example.org"]) {
      await recipientInput.fill(value);
      await expect(sendLink).toBeEnabled();
      await expect(recipientInput).toHaveAttribute('aria-invalid', 'false');
      await expect(emailValidation).toHaveCount(0);
    }
    // Chromium's email input converts IDN domains before React sees the value.
    await recipientInput.fill('person@b\u00fccher.org');
    await expect(recipientInput).toHaveValue('person@xn--bcher-kva.org');
    await expect(sendLink).toBeEnabled();
    await recipientInput.fill('  recipient@example.org  ');
    await expect(sendLink).toBeEnabled();
    await page.getByRole('button', { name: 'Generate and Send Link', exact: true }).click();
    const reviewMessage = 'Complete Narrative Review before generating or sending a link.';
    const inlineReviewError = page.getByRole('main').getByText(reviewMessage, { exact: false });
    const notifications = page.getByRole('region', { name: /Notifications/ });
    const reviewToast = notifications.getByText(reviewMessage, { exact: false });
    await expect(reviewToast).toBeVisible();
    await expect(reviewToast).toBeInViewport();
    await notifications.getByRole('button', { name: 'Close toast', exact: true }).click();
    await expect(reviewToast).toHaveCount(0);
    await page.getByRole('button', { name: 'Generate and Send Link', exact: true }).click();
    await expect(reviewToast).toBeVisible();
    await expect(reviewToast).toBeInViewport();
    await notifications.getByRole('button', { name: 'Close toast', exact: true }).click();
    await expect(inlineReviewError).toBeVisible();
    const beforePoll = statusPolls;
    await page.clock.runFor(16_000);
    await expect.poll(() => statusPolls).toBeGreaterThan(beforePoll);
    await expect(inlineReviewError).toBeVisible();
    await page.getByRole('button', { name: 'Mark reviewed — no redaction needed', exact: true }).click();
    await expect(page.getByText(/Narrative reviewed — no redaction needed/)).toBeVisible();
    await expect(inlineReviewError).toHaveCount(0);
    await page.getByRole('button', { name: 'Generate and Copy Link', exact: true }).click();
    await expect(page.getByText('Link generated. No email sent.', { exact: true })).toBeVisible();
    await expect(page.getByText(`${base}/synthetic-generated-packet`, { exact: true })).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(`${base}/synthetic-generated-packet`);
    expect(generatedLinks).toBe(1);
    expect(emailsSent).toBe(0);
    await page.getByRole('button', { name: 'Generate and Send Link', exact: true }).click();
    await expect(page.getByText(`${base}/synthetic-secure-packet`, { exact: true })).toBeVisible();
    await expect(page.getByText('Dryrun — sent to test inbox:', { exact: false })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Copy', exact: true })).toBeVisible();
    await expect(page.getByPlaceholder('recipient@example.org')).toHaveValue('');
    await expect(sendLink).toBeDisabled();
    await expect(recipientInput).toHaveAttribute('aria-invalid', 'false');
    await expect(emailValidation).toHaveCount(0);
    expect(channelApprovals).toBe(0);
    expect(routingRequests).toBe(0);
    expect(relayRequests).toBe(0);
    expect(emailsSent).toBe(1);
    const screenshots = path.join(tmpdir(), 'vera-secure-sharing-qa');
    mkdirSync(screenshots, { recursive: true });
    // The quota tests advance a synthetic clock; visual checks need a fresh
    // context so Motion and browser animation timelines share real time.
    for (const [name, width, height] of [['desktop', 1440, 1000], ['mobile', 390, 844]]) {
      const visualContext = await browser.newContext({ viewport: { width, height } });
      await visualContext.addCookies([{ name: '__session', value: session, url: base, httpOnly: true, sameSite: 'Lax' }]);
      const visualPage = await visualContext.newPage();
      await visualPage.route('**/*', handleRoute);
      await visualPage.goto(`${base}/admin`, { waitUntil: 'domcontentloaded' });
      await visualPage.getByRole('button', { name: 'Reports', exact: true }).first().click();
      await visualPage.getByRole('button', { name: 'Open Report', exact: true }).click();
      const panel = visualPage.getByRole('region', { name: 'Secure report sharing', exact: true });
      await panel.scrollIntoViewIfNeeded();
      await expect(panel).toHaveCSS('opacity', '1');
      await expect(panel.getByRole('textbox', { name: 'Recipient email', exact: true })).toBeVisible();
      await panel.getByRole('textbox', { name: 'Recipient email', exact: true }).fill('invalid-email');
      await expect(panel.getByRole('alert')).toHaveText('Enter a valid email address.');
      await expect(panel.getByRole('button', { name: 'Generate and Send Link', exact: true })).toBeDisabled();
      expect(await panel.evaluate(el => el.scrollWidth <= el.clientWidth + 1)).toBe(true);
      await panel.screenshot({ path: path.join(screenshots, `${name}.png`) });
      await visualContext.close();
    }
    console.log(`Screenshots: ${screenshots}`);
    console.log('PASS: malformed, non-ASCII and overlong recipients block sending; plus-addressing, Punycode, accessible errors and trimmed submission work');
    console.log('PASS: secure-sharing-only panel, current consent without routing/relay requests, standalone narrative review, persistent errors, copy-only generation without email, and explicit email delivery');
    console.log('PASS: admin outage, retry recovery, working Refresh, revoked access, malformed/empty responses, and 429 cooldown/recovery for polling and manual refresh');
  } catch (error) {
    console.error(logs);
    throw error;
  } finally {
    if (browser) await browser.close();
    server.kill('SIGTERM');
    await new Promise(resolve => { if (server.exitCode !== null) resolve(); else server.once('exit', resolve); });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
