// Run against a local production build. No real report, identity provider or external service needed.
const assert = require('node:assert/strict');
const { chromium } = require('../qa/node_modules/playwright');
async function check(base = 'http://127.0.0.1:3097') {
  if (!['127.0.0.1', 'localhost'].includes(new URL(base).hostname)) throw new Error('Use a local test server');
  const browser = await chromium.launch({ headless: true, args: ['--disable-webgl'] });
  try {
    const page = await browser.newPage();
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    await page.goto(base + '/');
    // The introduction opens only after a reporting action. Agree and continue must load
    // a new private document with its own CSP rather than a soft transition.
    await page.locator('section[aria-labelledby="hero-title"]').getByRole('link', { name: 'Start a report' }).click();
    await page.getByRole('dialog').waitFor({ state: 'visible' });
    await page.getByRole('dialog').getByRole('checkbox', { name: /I consent to VERA processing/ }).check();
    const [entryResponse] = await Promise.all([
      page.waitForResponse(response => response.request().isNavigationRequest() && new URL(response.url()).pathname === '/report'),
      page.getByRole('dialog').getByRole('button', { name: 'Agree and continue', exact: true }).click(),
    ]);
    assert.match(entryResponse.headers()['content-security-policy'], /script-src.*nonce-/);
    await page.getByPlaceholder('Describe what happened').waitFor({ state: 'visible' });
    const nonces = [];
    for (const route of ['/report', '/status', '/status']) {
      const response = await page.goto(base + route);
      assert.equal(response.status(), 200);
      const csp = response.headers()['content-security-policy'];
      const nonce = /'nonce-([^']+)'/.exec(csp)?.[1]; assert.ok(nonce);
      assert.ok(!csp.includes("'unsafe-inline'") || !csp.split('script-src')[1].split(';')[0].includes("'unsafe-inline'"));
      assert.match(response.headers()['cache-control'], /no-store/);
      assert.equal(response.headers()['referrer-policy'], 'no-referrer');
      nonces.push(nonce);
      await page.evaluate(() => { const script = document.createElement('script'); script.text = 'window.__unsafeScriptRan=true'; document.body.append(script); });
      assert.equal(await page.evaluate(() => window.__unsafeScriptRan), undefined);
      await page.waitForTimeout(200);
    }
    assert.equal(new Set(nonces).size, nonces.length);
    assert.deepEqual(errors, []);
    const code = 'VRC-' + 'A'.repeat(64);
    let observed;
    await page.route('**/api/whistleblower/status/access', async route => {
      observed = { url: route.request().url(), header: route.request().headers()['x-reporter-credential'] };
      await route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ success: false, error: 'Report not found' }) });
    });
    await page.locator('input').first().fill(code);
    const lookup = page.waitForResponse(response => response.url().endsWith('/api/whistleblower/status/access'));
    await page.locator('input').first().press('Enter');
    await lookup;
    assert.equal(observed.header, code); assert.ok(!observed.url.includes(code));
    console.log('PASS: fresh CSP nonces, inline injection blocked, no-store, hydration, and header-only reporter access');
  } finally { await browser.close(); }
}
check(process.argv[2]).catch(error => { console.error(error); process.exitCode = 1; });
