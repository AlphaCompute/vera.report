import { test, expect } from '@playwright/test';

// next dev hides the body itself, so delayed-bundle fallback needs production rendering.
for (const delay of [1000, 6000]) {
  test(`homepage loader fails open without replaying with bundles delayed ${delay}ms`, async ({ page }) => {
    await page.clock.install({ time: new Date('2026-01-01T12:00:00Z') });
    await page.clock.pauseAt(new Date('2026-01-01T12:00:01Z'));
    await page.addInitScript(() => {
      new MutationObserver(() => {
        if (document.documentElement.dataset.sawHydratedLoader !== 'true' && document.querySelector('[data-site-loader][data-hydrated]')) {
          document.documentElement.dataset.sawHydratedLoader = 'true';
        }
      }).observe(document, { childList: true, subtree: true, attributes: true });
    });
    let release!: () => void;
    const bundles = new Promise<void>(resolve => { release = resolve; });
    await page.route('**/_next/**/*.js*', async route => {
      await bundles;
      await route.continue();
    });
    try {
      await page.goto('/', { waitUntil: 'commit' });
      const heading = page.locator('h1');
      await heading.waitFor({ state: 'attached' });
      const loader = page.getByRole('status', { name: 'Loading VERA' });
      await expect(loader).toBeVisible();
      await expect(loader.locator('svg')).toBeVisible();
      await expect(heading).toBeHidden();
      if (delay >= 5000) {
        // A restored position can exist behind the server-rendered loader before hydration.
        await page.evaluate(() => window.scrollTo({ top: 900, behavior: 'instant' }));
        expect(await page.evaluate(() => scrollY)).toBe(900);
      }
      await page.clock.runFor(delay);
      if (delay < 5000) {
        await expect(heading).toBeHidden();
        release();
        await expect.poll(async () => {
          await page.clock.runFor(16);
          return loader.getAttribute('data-hydrated');
        }).toBe('true');
        await expect(page.getByRole('heading', { level: 1 })).toHaveCount(0);
        await expect.poll(async () => {
          await page.clock.runFor(250);
          return loader.count();
        }).toBe(0);
      } else {
        // The public page stays usable with broken bundles; late bundles must not cover it again.
        await expect(loader).toBeHidden();
        await expect(heading).toBeVisible();
        expect(await page.evaluate(() => scrollY)).toBe(0);
        const start = page.locator('section[aria-labelledby="hero-title"]').getByRole('link', { name: 'Start a report' });
        await start.focus();
        await expect(start).toBeFocused();
        release();
        await expect.poll(async () => {
          await page.clock.runFor(16);
          // The fallback only hides the server-rendered loader; hydration removes it.
          return page.locator('[data-site-loader]').count();
        }).toBe(0);
        await expect(page.locator('html')).not.toHaveAttribute('data-saw-hydrated-loader', 'true');
      }
      await expect(page.locator('[data-site-loader]')).toHaveCount(0);
      await expect(heading).toBeVisible();
      await expect(page.locator('body')).not.toHaveCSS('overflow', 'hidden');
      await page.evaluate(() => window.scrollTo({ top: 900, behavior: 'instant' }));
      await page.clock.runFor(6000);
      expect(await page.evaluate(() => scrollY)).toBe(900);
    } finally {
      release();
      await page.unrouteAll({ behavior: 'wait' });
    }
  });
}
