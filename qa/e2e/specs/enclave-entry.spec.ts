import { test, expect, type Request } from '@playwright/test';
import { prepare } from '../support/browser';

// The local stack signs synthetic Nitro evidence; the browser performs the real
// signature, nonce, PCR, key-binding and encrypted-reply checks.
for (const reducedMotion of ['no-preference', 'reduce'] as const) {
  test(`entry waits for the encrypted challenge before turning green (${reducedMotion})`, async ({ page }) => {
    await prepare(page.context());
    await page.emulateMedia({ reducedMotion });
    if (reducedMotion === 'reduce') await page.setViewportSize({ width: 375, height: 812 });
    // Exercise the same admission retry that can occur after the other journeys.
    if (reducedMotion === 'no-preference') await page.route('**/api/confidential/channel/open',
      route => route.fulfill({ status: 429, headers: { 'Retry-After': '1' }, body: '' }), { times: 1 });
    const requests: { path: string; body: Record<string, unknown>; request: Request }[] = [];
    page.on('request', request => {
      if (request.method() === 'POST' && new URL(request.url()).pathname.startsWith('/api/')) {
        requests.push({ path: new URL(request.url()).pathname, body: request.postDataJSON(), request });
      }
    });
    let release!: () => void;
    const held = new Promise<void>(resolve => { release = resolve; });
    let replied!: () => void;
    const answered = new Promise<void>(resolve => { replied = resolve; });
    await page.route('**/api/confidential/channel/call', async route => {
      const response = await route.fetch();
      replied();
      await held;
      await route.fulfill({ response });
    });
    try {
      await page.goto('/report');
      await answered;
      // The attestation has verified, but the authenticated reply is still held.
      await page.waitForTimeout(3300);
      await expect(page.locator('[data-workspace-state="loading"]')).toBeVisible();
      await expect(page.locator('[data-workspace-light]')).toHaveClass(/bg-red-600/);
      await expect(page.getByPlaceholder('Describe what happened')).toHaveCount(0);
      await expect(page.locator('[data-typing]')).toHaveCount(0);
      release();
      await expect(page.locator('[data-workspace-state="loaded"]')).toContainText('You’re in. Take your time.');
      await expect(page.locator('[data-workspace-light]')).toHaveClass(/bg-green-600.*motion-safe:animate-pulse/);
      const green = await page.locator('[data-workspace-light]').evaluate(async element => {
        // Reduced motion still has a brief color transition; leave the infinite pulse running.
        await Promise.all(element.getAnimations().filter(animation => animation instanceof CSSTransition).map(animation => animation.finished));
        return getComputedStyle(element).backgroundColor;
      });
      await expect(page.locator('[data-secure-channel]:visible')).toHaveAttribute('data-secure-channel', 'verified');
      const glow = page.locator('[data-secure-channel]:visible .opacity-40');
      await expect(glow).toHaveCSS('background-color', green);
      await expect(glow).toHaveCSS('animation-name', reducedMotion === 'reduce' ? 'none' : 'ping');
      await expect(page.locator('[data-typing]').first()).toContainText('Welcome to VERA.');
      await expect(page.getByPlaceholder('Describe what happened')).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      // One accepted anonymous session; throttled opens retry the same nonce without creating a session.
      const confidential = requests.filter(request => request.path.startsWith('/api/confidential/'));
      const opens = confidential.filter(request => request.path === '/api/confidential/channel/open');
      expect(opens.length).toBeGreaterThan(reducedMotion === 'no-preference' ? 1 : 0);
      expect(confidential.map(request => request.path)).toEqual([
        ...opens.map(() => '/api/confidential/channel/open'), '/api/confidential/channel/call',
      ]);
      expect(await Promise.all(opens.map(async ({ request }) => (await request.response())?.status())))
        .toEqual([...opens.slice(0, -1).map(() => 429), 200]);
      const challenge = confidential.at(-1)!;
      expect(Object.keys(challenge.body).sort()).toEqual(['ciphertext', 'last', 'nonce']);
      expect(challenge.body.last).toBe(true);
      for (const open of opens) expect(open.body).toEqual({ nonce: challenge.body.nonce });
      expect(requests.some(request => request.path.startsWith('/api/whistleblower/'))).toBe(false);
    } finally { release(); }
  });
}

for (const failure of ['unavailable', 'attestation', 'reply'] as const) {
  test(`entry stays red on ${failure} failure and retries without losing writing`, async ({ page }) => {
    await prepare(page.context());
    const path = failure === 'reply' ? '**/api/confidential/channel/call' : '**/api/confidential/channel/open';
    await page.route(path, async route => {
      if (failure === 'unavailable') return route.fulfill({ status: 503, body: '' });
      const response = await route.fetch();
      const body = await response.json();
      if (failure === 'attestation') body.document = 'AA==';
      else body.ciphertext = 'invalid encrypted reply';
      await route.fulfill({ response, json: body });
    });
    await page.goto('/report');
    await expect(page.locator('[data-workspace-state="failed"]')).toBeVisible();
    await expect(page.locator('[data-workspace-light]')).toHaveClass(/bg-red-600/);
    await expect(page.getByText('You’re in. Take your time.', { exact: true })).toHaveCount(0);
    await expect(page.locator('[data-secure-channel]:visible')).toHaveAttribute('data-secure-channel', 'failed');
    const narrative = page.getByPlaceholder('Describe what happened');
    await narrative.fill('PRIVATE-ENTRY-RETRY-SENTINEL');
    const bodies: string[] = [];
    page.on('request', request => bodies.push(request.postData() ?? ''));
    await page.unroute(path);
    await page.getByRole('button', { name: 'Check enclave again' }).click();
    await expect(page.locator('[data-secure-channel]:visible')).toHaveAttribute('data-secure-channel', 'verified');
    await expect(narrative).toHaveValue('PRIVATE-ENTRY-RETRY-SENTINEL');
    await expect(page.getByRole('button', { name: 'Check enclave again' })).toHaveCount(0);
    expect(bodies.join('\n')).not.toContain('PRIVATE-ENTRY-RETRY-SENTINEL');
  });
}

test('submission rechecks after a successful entry and turns red on a new failure', async ({ page }) => {
  await prepare(page.context());
  await page.goto('/report');
  await expect(page.locator('[data-secure-channel]:visible')).toHaveAttribute('data-secure-channel', 'verified');
  await page.getByPlaceholder('Describe what happened').fill('PRIVATE-SUBMIT-SENTINEL: invoices approved without delivered work.');
  await page.getByPlaceholder('Describe what happened').press('Enter');
  await page.getByRole('button', { name: 'Skip', exact: true }).click();
  await page.getByLabel('Email', { exact: true }).fill('private-entry@example.org');
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  await page.getByLabel('Summary for legal review').fill('Invoices appear to have been approved for work that was never delivered.');
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  const bodies: string[] = [];
  page.on('request', request => bodies.push(request.postData() ?? ''));
  let opens = 0;
  await page.route('**/api/confidential/channel/open', route => {
    opens++;
    return route.fulfill({ status: 503, body: '' });
  });
  await page.getByRole('button', { name: 'Submit Report', exact: true }).click();
  await expect(page.locator('[data-failure="unavailable"]')).toBeVisible();
  await expect(page.locator('[data-secure-channel]:visible')).toHaveAttribute('data-secure-channel', 'failed');
  expect(opens).toBe(1);
  await expect(page.getByLabel('What happened, full text')).toHaveValue(/PRIVATE-SUBMIT-SENTINEL/);
  expect(bodies.join('\n')).not.toContain('PRIVATE-SUBMIT-SENTINEL');
  expect(bodies.join('\n')).not.toContain('private-entry@example.org');
});
