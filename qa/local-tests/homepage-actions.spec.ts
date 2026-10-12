import { test, expect } from '@playwright/test';

for (const profile of [
  { name: 'desktop', viewport: { width: 1440, height: 1000 }, reducedMotion: 'no-preference' },
  { name: 'mobile', viewport: { width: 375, height: 812 }, reducedMotion: 'no-preference' },
  { name: 'reduced motion', viewport: { width: 375, height: 812 }, reducedMotion: 'reduce' },
] as const) {
  test(`scrolling report actions (${profile.name})`, async ({ page }) => {
    await page.setViewportSize(profile.viewport);
    await page.emulateMedia({ reducedMotion: profile.reducedMotion });
    await page.route('**/api/monitoring/client', route => route.fulfill({ status: 204 }));
    await page.clock.install({ time: new Date('2026-01-01T12:00:00Z') });
    await page.goto('/');
    const nav = page.locator('nav[aria-label="Primary"]');
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await page.evaluate(() => document.fonts.ready);
    await page.clock.pauseAt(new Date('2026-01-01T13:00:00Z'));
    const scroll = async (top: number) => {
      await page.evaluate(y => new Promise<void>(resolve => {
        window.addEventListener('scroll', () => resolve(), { once: true });
        window.scrollTo({ top: y, behavior: 'instant' });
      }), top);
    };
    const heroStatus = page.locator('section[aria-labelledby="hero-title"] a[href="/status"]');
    const heroStatusBottom = await heroStatus.evaluate(element => element.getBoundingClientRect().bottom + scrollY);
    const pastHero = Math.ceil(heroStatusBottom) + 1;
    const headlineTop = () => page.locator('h1').evaluate(element => element.getBoundingClientRect().top + scrollY);
    const originalTop = await headlineTop();

    // The hero shows both actions, so the dock stays out of the way until they scroll off.
    await expect(nav).toHaveAttribute('data-hidden', 'true');
    await expect(nav).toHaveAttribute('inert', '');
    await expect(page.getByRole('navigation', { name: 'Primary' })).toHaveCount(0);
    await scroll(pastHero - 2);
    await expect(nav).toHaveAttribute('data-hidden', 'true');

    await scroll(pastHero);
    await expect(nav).toHaveAttribute('data-hidden', 'false');
    await page.clock.runFor(100);
    if (profile.reducedMotion === 'reduce') await expect(nav).toHaveCSS('transform', 'none');
    else {
      await expect(nav).not.toHaveCSS('transform', 'none');
      await page.screenshot({ path: test.info().outputPath('report-actions-sliding.png') });
    }
    await page.clock.runFor(900);
    await expect(nav).toHaveCSS('transform', 'none');
    const box = (await nav.boundingBox())!;
    expect(box.y).toBeGreaterThan(profile.viewport.height - 110);
    expect(box.y + box.height).toBeLessThanOrEqual(profile.viewport.height - 15);
    expect(box.x).toBeGreaterThanOrEqual(16);
    expect(box.x + box.width).toBeLessThanOrEqual(profile.viewport.width - 16);
    expect(Math.abs(await headlineTop() - originalTop)).toBeLessThan(1);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await expect(nav.getByRole('link', { name: 'Open your report' })).toBeVisible();
    await page.screenshot({ path: test.info().outputPath('report-actions.png') });

    // The dock links keep the reporting notice and keyboard focus.
    const start = nav.getByRole('link', { name: 'Start a report' });
    await start.click();
    const notice = page.getByRole('dialog', { name: 'Before you continue' });
    await expect(notice).toBeVisible();
    await expect(notice.getByRole('button', { name: /Agree and continue/ })).toBeDisabled();
    await notice.getByRole('button', { name: 'Cancel' }).click();
    await page.clock.runFor(32);
    await expect(start).toBeFocused();
    await start.evaluate(link => link.blur());

    // Jump past the closing buttons without an intersection event.
    await scroll(await page.evaluate(() => document.documentElement.scrollHeight));
    await expect(nav).toHaveAttribute('data-hidden', 'true');
    const closing = page.locator('section[aria-labelledby="close-title"] a[href="/report"]');
    const closingStatus = page.locator('section[aria-labelledby="close-title"] a[href="/status"]');
    const closingTop = await closing.evaluate(element => element.getBoundingClientRect().top + scrollY - innerHeight / 2);
    for (const dismissal of ['Cancel', 'Escape'] as const) {
      await scroll(pastHero);
      await expect(nav).toHaveAttribute('data-hidden', 'false');
      await start.focus();
      await scroll(closingTop);
      await expect(start).toBeFocused();
      await expect(nav).toHaveAttribute('data-hidden', 'false');
      await page.keyboard.press('Enter');
      await expect(notice).toBeVisible();
      if (dismissal === 'Cancel') await notice.getByRole('button', { name: 'Cancel' }).click();
      else await page.keyboard.press('Escape');
      await page.clock.runFor(32);
      // The dock hides when the notice takes focus; return to the visible action.
      await expect(closing).toBeFocused();
      await page.keyboard.press('Tab');
      await expect(closingStatus).toBeFocused();
    }
    await expect(nav).toHaveAttribute('data-hidden', 'true');
    await expect(nav).toHaveAttribute('inert', '');
    await expect(page.getByRole('navigation', { name: 'Primary' })).toHaveCount(0);
    await expect(closing).toBeInViewport();

    await scroll(0);
    await expect(nav).toHaveAttribute('data-hidden', 'true');
    await expect(nav).toHaveAttribute('inert', '');
    await page.clock.runFor(1000);
    if (profile.reducedMotion !== 'reduce') await expect(nav).not.toHaveCSS('transform', 'none');
    await scroll(pastHero);
    await expect(nav).toHaveAttribute('data-hidden', 'false');
    await page.clock.runFor(1000);
    await expect(nav).toHaveCSS('transform', 'none');
    await nav.getByRole('link', { name: 'Open your report' }).click();
    await expect(page).toHaveURL(/\/status$/);
  });
}
