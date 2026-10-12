import { encodeRecoveryCodeV2 } from '../../enclave/src/confidential/recoveryCode';
import { recoveryLink } from '../../lib/confidential/recoveryLink';
import { test, expect, type Page, type Route } from '@playwright/test';

// Synthetic content only. Sentinels must never appear in any request.
const narrative = 'SENTINEL-NARRATIVE: invoices were approved for work that was never delivered.';
const contact = 'sentinel.contact@example.org';
const risky = 'My manager Tom Reed at Acme Capital LLC called me on 419-555-0144 on March 4, 2024.';
const safe = 'An investment firm appears to have approved invoices for work that was never delivered. I have records.';

for (const reducedMotion of ['no-preference', 'reduce'] as const) {
    test(`workspace entry holds and stays red when the service is unavailable (${reducedMotion})`, async ({ page }) => {
        await page.emulateMedia({ reducedMotion });
        const seen = await watch(page);
        await page.goto('/report', { waitUntil: 'domcontentloaded' });
        const loading = page.getByRole('heading', { name: 'Confidential workspace' });
        await expect(loading).toBeVisible();
        // This deliberate presentation delay must survive fast local preparation.
        await page.waitForTimeout(1000);
        await expect(loading).toBeVisible();
        await expect(page.getByPlaceholder('Describe what happened')).toHaveCount(0);
        await expect(page.locator('[data-typing]')).toHaveCount(0);
        await expect(page.locator('[data-workspace-state="failed"]')).toContainText('Workspace unavailable');
        await expect(page.locator('[data-workspace-state="loaded"]')).toHaveCount(0);
        await expect(page.locator('[data-workspace-light]')).toHaveClass(/bg-red-600/);
        await expect(page.getByText('You’re in. Take your time.', { exact: true })).toHaveCount(0);
        await expect(loading).toHaveCount(0);
        await expect(page.getByPlaceholder('Describe what happened')).toBeVisible();
        await expect(page.locator('[data-typing]').first()).toContainText('Welcome to VERA.');
        await expect(page.locator('[data-secure-channel]:visible')).toHaveAttribute('data-secure-channel', 'failed');
        expect(seen.urls.some(url => new URL(url).pathname === '/api/confidential/channel/open')).toBe(true);
    });
}

test('workspace entry never reports ready when local preparation fails', async ({ page }) => {
    await page.route('**/*lib_confidential_releaseIdentity_ts.js', route => route.abort());
    await page.goto('/report', { waitUntil: 'domcontentloaded' });
    await expect(page.locator('[data-workspace-state="failed"]')).toContainText('Workspace unavailable');
    await expect(page.locator('[data-workspace-state="loaded"]')).toHaveCount(0);
    await expect(page.getByText('You’re in. Take your time.', { exact: true })).toHaveCount(0);
    await expect(page.getByPlaceholder('Describe what happened')).toBeVisible();
    await expect(page.locator('[data-secure-channel]:visible')).toHaveAttribute('data-secure-channel', 'failed');
});

test.describe('homepage without JavaScript', () => {
    test.use({ javaScriptEnabled: false });

    test('keeps public information and navigation accessible', async ({ page }) => {
        await page.goto('/');
        await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
        const hero = page.getByRole('region', { name: /Say what you saw/ });
        const start = hero.getByRole('link', { name: 'Start a report' });
        await expect(start).toHaveAttribute('href', '/report');
        await expect(hero.getByRole('link', { name: 'Open your report' })).toHaveAttribute('href', '/status');
        await start.focus();
        await expect(start).toBeFocused();
        await expect(page.getByRole('status', { name: 'Loading VERA' })).toHaveCount(0);
        await expect(page.locator('body')).not.toHaveCSS('overflow', 'hidden');
    });
});

for (const profile of [
    { name: 'desktop', viewport: { width: 1440, height: 1000 }, reducedMotion: 'no-preference' },
    { name: 'mobile', viewport: { width: 375, height: 812 }, reducedMotion: 'no-preference' },
    { name: 'reduced motion', viewport: { width: 375, height: 812 }, reducedMotion: 'reduce' },
] as const) {
    test(`homepage logo-only loader (${profile.name})`, async ({ page }) => {
        await page.setViewportSize(profile.viewport);
        await page.emulateMedia({ reducedMotion: profile.reducedMotion });
        // Hold images past the intro so these checks cannot depend on the load event.
        const images: Route[] = [];
        await page.route('**/*', route => {
            if (route.request().resourceType() === 'image') images.push(route);
            else return route.fallback();
        });
        await page.route('**/api/monitoring/client', route => route.fulfill({ status: 204 }));
        await page.clock.install({ time: new Date('2026-01-01T12:00:00Z') });
        await page.clock.pauseAt(new Date('2026-01-01T12:00:01Z'));
        await page.goto('/', { waitUntil: 'domcontentloaded' });
        const loader = page.getByRole('status', { name: 'Loading VERA' });
        await expect.poll(async () => {
            await page.clock.runFor(16);
            return loader.getAttribute('data-hydrated');
        }).toBe('true');
        await expect(loader).toBeVisible();
        await expect(loader.locator('svg')).toHaveCount(1);
        await expect(page.getByRole('heading', { level: 1 })).toHaveCount(0);
        const start = page.locator('#main-content a[href="/report"]').first();
        await start.evaluate(link => link.focus());
        await expect(start).not.toBeFocused();
        await expect(page.locator('body')).toHaveCSS('overflow', 'hidden');
        await expect.poll(() => images.length).toBeGreaterThan(0);
        await page.clock.runFor(2500);
        await expect(loader).toHaveCount(0);
        await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
        await expect(page.locator('body')).not.toHaveCSS('overflow', 'hidden');
        await start.focus();
        await expect(start).toBeFocused();
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
        await Promise.all(images.map(route => route.continue()));
        await page.waitForLoadState('load');
    });
}

test('homepage server HTML covers the page with the loader before JavaScript runs', async ({ request }) => {
    const html = await (await request.get('/')).text();
    expect(html).toContain('data-site-loader');
    expect(html).toContain('<noscript><style>[data-site-loader]{display:none}</style></noscript>');
    // Without JavaScript nothing may become inert or hidden from assistive technology.
    expect(html).not.toMatch(/<main[^>]*\binert\b/);
    expect(html).not.toMatch(/<div[^>]*\binert=""/);
});

test('homepage loader reveals the top of the page even after the page scrolled behind it', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.route('**/api/monitoring/client', route => route.fulfill({ status: 204 }));
    await page.clock.install({ time: new Date('2026-01-01T12:00:00Z') });
    await page.clock.pauseAt(new Date('2026-01-01T12:00:01Z'));
    await page.goto('/', { waitUntil: 'domcontentloaded' });
    const loader = page.getByRole('status', { name: 'Loading VERA' });
    await expect.poll(async () => {
        await page.clock.runFor(16);
        return page.locator('main').evaluate(main => !!main.closest('[inert]'));
    }).toBe(true);
    expect(await page.evaluate(() => history.scrollRestoration)).toBe('manual');
    // Stands in for a restored position or a scroll before the loader appeared.
    await page.evaluate(() => window.scrollTo({ top: 900, behavior: 'instant' }));
    expect(await page.evaluate(() => scrollY)).toBe(900);
    await page.clock.runFor(2500);
    await expect(loader).toHaveCount(0);
    expect(await page.evaluate(() => scrollY)).toBe(0);
});

test('homepage loader preserves a section targeted by the URL', async ({ page }) => {
    await page.clock.install({ time: new Date('2026-01-01T12:00:00Z') });
    await page.clock.pauseAt(new Date('2026-01-01T12:00:01Z'));
    await page.goto('/#faq-title', { waitUntil: 'domcontentloaded' });
    const loader = page.getByRole('status', { name: 'Loading VERA' });
    await expect.poll(async () => {
        await page.clock.runFor(16);
        return loader.getAttribute('data-hydrated');
    }).toBe('true');
    await page.clock.runFor(2500);
    await expect(loader).toHaveCount(0);
    await expect(page.locator('#faq-title')).toBeInViewport();
});

test('policy popups preserve the homepage and reporting notice when closed', async ({ page, context }) => {
    await page.route('**/api/monitoring/client', (route) => route.fulfill({ status: 204 }));
    await page.goto('/');
    const footer = page.getByRole('navigation', { name: 'Legal', exact: true });
    for (const title of ['Terms of Service', 'Privacy Notice']) {
        const trigger = footer.getByRole('button', { name: title, exact: true });
        await trigger.scrollIntoViewIfNeeded();
        const scrollY = await page.evaluate(() => window.scrollY);
        await trigger.click();
        const policy = page.getByRole('dialog', { name: title, exact: true });
        await expect(policy).toBeVisible();
        await expect(policy.getByText('Draft for legal review', { exact: true })).toHaveCount(0);
        await expect(policy.getByRole('heading', { name: title, exact: true })).toBeFocused();
        expect(context.pages()).toHaveLength(1);
        await policy.getByRole('region').evaluate((element) => { element.scrollTop = 500; });
        await policy.getByRole('button', { name: 'Close', exact: true }).click();
        await expect(policy).not.toBeVisible();
        await expect(trigger).toBeFocused();
        expect(Math.abs((await page.evaluate(() => window.scrollY)) - scrollY)).toBeLessThan(2);
    }
    await page.getByRole('link', { name: 'Start a report', exact: false }).first().click();
    const notice = page.getByRole('dialog', { name: 'Before you continue', exact: true });
    await expect(notice).toBeVisible();
    const consent = notice.getByRole('checkbox', { name: /I consent to VERA processing/ });
    const continueButton = notice.getByRole('button', { name: 'Agree and continue', exact: false });
    await expect(consent).not.toBeChecked();
    await expect(continueButton).toBeDisabled();
    await consent.check();
    await expect(continueButton).toBeEnabled();
    const reading = notice.getByRole('region', { name: 'Before you send information', exact: true });
    await reading.evaluate((element) => { element.scrollTop = 250; });
    const scrollTop = await reading.evaluate((element) => element.scrollTop);
    for (const title of ['Terms of Service', 'Privacy Notice']) {
        const trigger = notice.getByRole('button', { name: new RegExp(title) });
        await trigger.click();
        const policy = page.getByRole('dialog', { name: title, exact: true });
        await expect(policy).toBeVisible();
        await expect(policy.getByRole('heading', { name: title, exact: true })).toBeFocused();
        await policy.getByRole('button', { name: 'Close', exact: true }).focus();
        await page.keyboard.press('Tab');
        await expect(policy.locator(':focus')).toHaveCount(1);
        await page.keyboard.press('Escape');
        await expect(policy).not.toBeVisible();
        await expect(notice).toBeVisible();
        await expect(trigger).toBeFocused();
        expect(await reading.evaluate((element) => element.scrollTop)).toBe(scrollTop);
        await expect(consent).toBeChecked();
    }
    await notice.getByRole('button', { name: 'Cancel' }).click();
    await expect(notice).not.toBeVisible();
    await page.getByRole('link', { name: 'Start a report', exact: false }).first().click();
    await expect(consent).not.toBeChecked();
    await expect(continueButton).toBeDisabled();
    await notice.getByRole('button', { name: 'Cancel' }).click();
});

test('policy deep links open readable mobile popups and close back to the homepage', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await page.route('**/api/monitoring/client', (route) => route.fulfill({ status: 204 }));
    for (const [path, title, sections] of [
        ['/terms', 'Terms of Service', 12], ['/privacy', 'Privacy Notice', 11],
    ] as const) {
        await page.goto(path);
        await expect(page.getByRole('status', { name: 'Loading VERA' })).toHaveCount(0);
        const policy = page.getByRole('dialog', { name: title, exact: true });
        await expect(policy).toBeVisible();
        await expect(policy.getByRole('heading', { level: 3 })).toHaveCount(sections);
        await expect(page.locator('meta[name="robots"]')).toHaveAttribute('content', 'noindex, nofollow');
        await expect(policy.getByText(/^Last updated(?: and effective)?: October 8, 2026$/)).toBeVisible();
        expect(await policy.evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
        const reading = policy.getByRole('region');
        await reading.hover();
        await page.mouse.wheel(0, 600);
        await expect.poll(() => reading.evaluate((element) => element.scrollTop)).toBeGreaterThan(0);
        await expect(policy.getByRole('button', { name: 'Close', exact: true })).toBeInViewport();
        await policy.getByRole('button', { name: 'Close', exact: true }).click();
        await expect(page).toHaveURL('/');
        await expect(page.getByRole('dialog')).not.toBeVisible();
    }
});

type Watch = { urls: string[]; bodies: string[] };

async function watch(page: Page): Promise<Watch> {
    const seen: Watch = { urls: [], bodies: [] };
    page.on('request', (request) => {
        seen.urls.push(request.url());
        seen.bodies.push(request.postData() ?? '');
    });
    await page.route('**/api/monitoring/client', (route) => route.fulfill({ status: 204 }));
    // The attested channel is unavailable: submit must fail closed and keep the draft.
    await page.route('**/api/confidential/**', (route) =>
        route.fulfill({ status: 503, body: 'Unavailable in this test' }),
    );
    await page.route('**/api/whistleblower/**', (route) => route.abort());
    return seen;
}

async function describe(page: Page) {
    await page.goto('/report');
    const description = page.getByPlaceholder('Describe what happened');
    await expect(description).toBeVisible();
    await expect(page.getByText(/compensation|reward/i)).toHaveCount(0);
    await description.fill(narrative);
    await description.press('Enter');
    // The evidence limit is stated before the person picks anything.
    await expect(page.getByText('Up to 10 files, 256 MB in total.', { exact: false }).first()).toBeVisible();
    await expect(page.getByRole('button', { name: 'Attach files', exact: true })).toBeVisible();
}

test('confidential intake asks only what happened, files, contact and summary, then fails closed', async ({ page }) => {
    const seen = await watch(page);
    await describe(page);
    await expect(page.getByText('metadata is removed on our servers', { exact: false })).toHaveCount(0);
    await page
        .locator('input[type="file"]')
        .setInputFiles({ name: 'ledger.csv', mimeType: 'text/csv', buffer: Buffer.from('a,b\n1,2\n') });
    await expect(page.getByText('ledger.csv', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Continue', exact: true }).click();

    await page.getByRole('button', { name: 'Continue', exact: true }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'Add at least one contact method.' })).toBeVisible();
    await page.screenshot({ path: '/tmp/vera-contact-desktop.png', fullPage: true });
    await expect(page.locator('strong').filter({ hasText: 'Add at least one contact method.' })).toBeVisible();
    await expect(
        page
            .getByText('only you can see them unless you later share them with a specific legal organization', {
                exact: false,
            })
            .first(),
    ).toBeVisible();
    await page.getByLabel('Email', { exact: true }).fill(contact);
    await page.getByLabel('Signal', { exact: true }).fill('+1 555 555 0100');
    await page.screenshot({ path: '/tmp/vera-contact-current.png', fullPage: true });
    await page.getByLabel('iMessage', { exact: true }).fill('imessage@example.com');
    await page.getByRole('button', { name: 'Continue', exact: true }).click();

    // Summary step: examples, on-device checks, live preview.
    await expect(page.getByRole('heading', { name: 'Write the summary legal organizations will see' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Write the summary legal organizations will see' })).toBeFocused();
    await page.getByText('See three examples', { exact: true }).click();
    await expect(page.getByText('Instead of:', { exact: false })).toHaveCount(3);
    const summary = page.getByLabel('Summary for legal review');
    await summary.fill(risky);
    await expect(page.getByText('4 possible identifying details found.', { exact: false })).toBeVisible();
    for (const text of ['Tom Reed', 'Acme Capital LLC', '419-555-0144', 'March 4, 2024']) {
        await expect(page.locator('q', { hasText: text })).toBeVisible();
    }
    await expect(page.getByRole('region', { name: 'What legal organizations will see' })).toHaveCount(0);

    await summary.fill(safe);
    await expect(page.getByText('No obvious identifying details detected.', { exact: false })).toBeVisible();
    await expect(page.getByRole('checkbox', { name: /Publish a/ })).toHaveCount(0);
    await page.getByRole('button', { name: 'Continue', exact: true }).click();

    // Review: what stays encrypted vs what is published. No legacy questions.
    const review = page.getByRole('region', { name: /Review your report/ });
    await expect(review.getByLabel('What happened, full text')).toHaveValue(narrative);
    await expect(review.getByText('ledger.csv', { exact: true })).toBeVisible();
    await expect(review.getByLabel('Email', { exact: true })).toHaveValue(contact);
    await expect(review.getByLabel('Signal', { exact: true })).toHaveValue('+1 555 555 0100');
    await expect(review.getByLabel('iMessage', { exact: true })).toHaveValue('imessage@example.com');
    await expect(review.getByLabel('Summary for legal review')).toHaveValue(safe);
    await expect(page.getByText('Keep my name and contact details out of the report', { exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /United States/ })).toHaveCount(0);

    await page.getByRole('button', { name: 'Submit Report', exact: true }).click();
    // A 503 from the relay is maintenance, not a possible attack; the draft stays.
    const failure = page.locator('[data-failure="unavailable"]');
    await expect(failure).toContainText('Your report is still here.');
    await expect(failure).not.toContainText('Possible security problem');
    // Draft kept, nothing plaintext sent anywhere, legacy intake never touched.
    await expect(page.getByRole('button', { name: 'Submit Report', exact: true })).toBeVisible();
    expect(seen.urls.some((url) => url.includes('/api/whistleblower/'))).toBe(false);
    const traffic = [...seen.urls, ...seen.bodies].join('\n');
    for (const secret of ['SENTINEL-NARRATIVE', contact, 'Tom Reed', 'investment firm'])
        expect(traffic).not.toContain(secret);

    // Going back returns to the summary with everything kept, including edits
    // made on the review.
    await review.getByLabel('What happened, full text').fill(`${narrative} Corrected on review.`);
    await review.getByLabel('Email', { exact: true }).fill('corrected@example.com');
    await page.getByRole('button', { name: 'Back', exact: true }).click();
    await expect(page.getByLabel('Summary for legal review')).toHaveValue(safe);
    await page.getByRole('button', { name: 'Continue', exact: true }).click();
    await expect(review.getByLabel('What happened, full text')).toHaveValue(`${narrative} Corrected on review.`);
    await expect(review.getByLabel('Email', { exact: true })).toHaveValue('corrected@example.com');
});

test('confidential intake fits a phone screen and refuses an over-limit selection before encrypting', async ({
    page,
}) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await watch(page);
    await describe(page);
    // Playwright cannot attach a buffer over 50 MB, so the size limit is unit-tested;
    // here the count limit and an unsupported type are refused before any encryption.
    await page
        .locator('input[type="file"]')
        .setInputFiles(
            Array.from({ length: 11 }, (_, n) => ({
                name: `page-${n}.pdf`,
                mimeType: 'application/pdf',
                buffer: Buffer.from('%PDF-1.4'),
            })),
        );
    await expect(page.getByText('You can attach up to 10 files at a time.', { exact: false })).toBeVisible();
    await page
        .locator('input[type="file"]')
        .setInputFiles({ name: 'tool.exe', mimeType: 'application/x-msdownload', buffer: Buffer.from('MZ') });
    await expect(page.getByText('tool.exe: ', { exact: false })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Skip', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Skip', exact: true }).click();
    // On a phone width the refusal toasts sit over the next choice. Sonner pauses
    // them while the pointer rests on them (a touch user never hovers), so move
    // the pointer away and let them close as they would on a phone.
    await page.mouse.move(0, 0);
    await expect(page.locator('[data-sonner-toast]')).toHaveCount(0, { timeout: 15_000 });
    await page.screenshot({ path: '/tmp/vera-contact-current.png', fullPage: true });
    await page.getByLabel('iMessage', { exact: true }).fill('imessage@example.com');
    await page.getByRole('button', { name: 'Continue', exact: true }).click();
    await expect(page.getByLabel('Summary for legal review')).toBeVisible();
    await page.getByLabel('Summary for legal review').fill(risky);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow).toBeLessThanOrEqual(0);
});

test('landing introduction opens on File a report and cancel stays on the landing page', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await page.locator('#main-content a[href="/report"]').first().click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await expect(page.getByRole('dialog')).toContainText('We see your short summary');
    await expect(page.getByRole('dialog')).not.toContainText('VERA staff');
    const authorities = page.getByRole('region', { name: 'OFFICIAL U.S. STARTING POINTS' });
    await expect(authorities.getByRole('link')).toHaveCount(8);
    const more = authorities.locator('summary');
    await more.focus();
    await more.press('Enter');
    await expect(authorities.getByRole('link')).toHaveCount(16);
    await expect(authorities.getByRole('link', { name: /NHTSA/ })).toContainText('$ REWARD PROGRAM');
    await expect(authorities.getByRole('link', { name: /FinCEN/ })).not.toContainText('$ REWARD PROGRAM');
    await more.press('Enter');
    await expect(authorities.getByRole('link')).toHaveCount(8);
    await page.screenshot({ path: '/tmp/vera-entry-dialog.png', fullPage: true });
    await page.getByRole('button', { name: 'Cancel', exact: false }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page).toHaveURL(/\/$/);
    await page.locator('#main-content a[href="/report"]').first().click();
    await page.getByRole('checkbox', { name: /I consent to VERA processing/ }).check();
    await page.getByRole('button', { name: 'Agree and continue', exact: false }).click();
    await expect(page).toHaveURL(/\/report$/);
});

test('homepage paper-feed punches engage with scrolling, stay registered, and retract at rest', async ({ page }) => {
    // Keep the desktop geometry consistent before and after the mobile check.
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await page.clock.install({ time: new Date('2026-01-01T12:00:00Z') });
    await page.goto('/');
    await page.evaluate(() => document.fonts.ready);
    const layer = page.locator('[data-rising-marks]');
    await expect(layer.locator('[data-side="left"]').first()).toBeAttached();
    await expect(page.getByRole('status', { name: 'Loading VERA' })).toHaveCount(0);
    await page.clock.pauseAt(new Date('2026-01-01T13:00:00Z'));
    await page.clock.runFor(2000);
    const row = layer.locator('[data-side="left"]').nth(8);
    const position = () => row.evaluate((el) => el.getBoundingClientRect().top + scrollY);
    const originalY = await position();
    // The first row follows the headline's layout, not its entrance transform.
    const headlineTop = await page.locator('main h1').evaluate((el) => el.getBoundingClientRect().top + scrollY);
    const firstRowTop = await layer.locator('[data-side="left"]').first()
        .evaluate((el) => el.getBoundingClientRect().top + scrollY);
    // offsetTop is rounded to CSS pixels; allow only that subpixel difference.
    expect(Math.abs(firstRowTop - headlineTop)).toBeLessThanOrEqual(1);
    const sizes = await row.evaluate((el) => {
        const css = getComputedStyle(el);
        return { width: parseFloat(css.width), height: parseFloat(css.height) };
    });
    expect(sizes.width).toBeGreaterThanOrEqual(33);
    const pitch = Math.max(16, Math.round(sizes.height * 4));
    const decoration = await layer.evaluate((el) => {
        const bars = Array.from(el.querySelectorAll('[data-side="left"]'), (bar) => bar.getBoundingClientRect());
        const patterns = Array.from(document.querySelectorAll('[data-edge-pattern]'), (pattern) => pattern.getBoundingClientRect());
        return {
            firstGap: bars[1].top - bars[0].top,
            overlapsPattern: bars.some((bar) => patterns.some((pattern) => bar.bottom > pattern.top && bar.top < pattern.bottom)),
            perforations: [getComputedStyle(el, '::before').content, getComputedStyle(el, '::after').content],
        };
    });
    expect(decoration.firstGap).toBe(pitch * 2);
    expect(decoration.overlapsPattern).toBe(false);
    expect(decoration.perforations).toEqual(['none', 'none']);
    const scales = () =>
        layer
            .locator('[data-side="left"]')
            .evaluateAll((bars) => bars.map((bar) => new DOMMatrixReadOnly(getComputedStyle(bar).transform).a));
    const wheel = (deltaY: number, extra: Record<string, number | boolean> = {}) =>
        page.evaluate(
            ({ deltaY, extra }) => {
                const event = new WheelEvent('wheel', { deltaY, bubbles: true, cancelable: true, ...extra });
                document.body.dispatchEvent(event);
                return event.defaultPrevented;
            },
            { deltaY, extra },
        );
    await expect(layer).toHaveAttribute('data-feed-state', 'idle');
    expect((await scales()).every((scale) => scale === 0)).toBe(true);

    // Punches sweep in before the held paper starts to feed; no opacity fading.
    expect(await wheel(600)).toBe(true);
    await page.clock.runFor(32);
    expect(await page.evaluate(() => scrollY)).toBe(0);
    expect((await scales()).some((scale) => scale === 0.42)).toBe(true);
    await page.clock.runFor(250);
    const during = await page.evaluate(() => scrollY);
    expect(during).toBeGreaterThan(0);
    expect(during).toBeLessThan(600);
    expect(await position()).toBe(originalY);
    expect(
        await layer.locator('span').evaluateAll((bars) =>
            bars.every((bar, i) => {
                const css = getComputedStyle(bar);
                return (
                    css.opacity === '1' &&
                    css.transitionDuration === '0s' &&
                    (i % 2 === 0 || css.transform === getComputedStyle(bars[i - 1]).transform)
                );
            }),
        ),
    ).toBe(true);
    await page.clock.runFor(3500);
    const resting = Math.round(600 / pitch) * pitch;
    expect(await page.evaluate(() => scrollY)).toBe(resting);
    await expect(layer).toHaveAttribute('data-feed-state', 'idle');
    expect((await scales()).every((scale) => scale === 0)).toBe(true);
    await page.clock.runFor(1000);
    expect(await page.evaluate(() => scrollY)).toBe(resting);

    // Reverse travel and a tiny new trackpad gesture both register on a full row.
    await wheel(-200);
    await page.clock.runFor(3500);
    const reverse = Math.round((resting - 200) / pitch) * pitch;
    expect(await page.evaluate(() => scrollY)).toBe(reverse);
    expect(await position()).toBe(originalY);
    await wheel(1);
    await page.clock.runFor(3500);
    expect(await page.evaluate(() => scrollY)).toBe(reverse + pitch);
    await page.keyboard.press('ArrowDown');
    await page.clock.runFor(3500);
    expect(await page.evaluate(() => scrollY)).toBe(reverse + 3 * pitch);

    // Pinch zoom, horizontal input, editable controls, and contained scrollers stay native.
    expect(await wheel(100, { ctrlKey: true })).toBe(false);
    expect(await wheel(100, { deltaX: 200 })).toBe(false);
    expect(
        await page.evaluate(() => {
            const scroller = document.createElement('div');
            scroller.style.cssText = 'position:fixed;height:50px;overflow:auto;overscroll-behavior:contain';
            scroller.innerHTML = '<div style="height:200px"><input aria-label="Scroll test"></div>';
            document.body.append(scroller);
            scroller.scrollTop = 150;
            const event = new WheelEvent('wheel', { deltaY: 100, bubbles: true, cancelable: true });
            scroller.dispatchEvent(event);
            const input = scroller.querySelector('input')!;
            input.focus({ preventScroll: true });
            const key = new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true, cancelable: true });
            input.dispatchEvent(key);
            scroller.remove();
            return event.defaultPrevented || key.defaultPrevented;
        }),
    ).toBe(false);

    // External scroll interrupts a running drive instead of pulling the user back.
    await wheel(800);
    await page.clock.runFor(150);
    // Native scroll events are not driven by Playwright's mocked animation clock.
    await page.evaluate(() => new Promise<void>((resolve) => {
        window.addEventListener('scroll', () => resolve(), { once: true });
        window.scrollTo({ top: 123, behavior: 'instant' });
    }));
    await page.clock.runFor(3500);
    expect(await page.evaluate(() => scrollY)).toBe(123);
    expect(await position()).toBe(originalY);

    await page.keyboard.press('End');
    await page.clock.runFor(5000);
    expect(await page.evaluate(() => scrollY)).toBe(
        await page.evaluate(() => document.documentElement.scrollHeight - innerHeight),
    );
    expect(
        await layer.locator('span').evaluateAll((bars) => {
            const top = document.querySelector('main h1')!.getBoundingClientRect().top;
            const footer = document.querySelector('footer')!.getBoundingClientRect().top;
            const last = bars.at(-1)!.getBoundingClientRect().bottom;
            return (
                bars.every(
                    (bar) => bar.getBoundingClientRect().top >= top - 1 && bar.getBoundingClientRect().bottom <= footer,
                ) && footer - last < 80
            );
        }),
    ).toBe(true);

    // Native preferences bypass the engine, including a change during motion.
    await wheel(-600);
    await page.clock.runFor(150);
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await expect(layer).toBeHidden();
    const stopped = await page.evaluate(() => scrollY);
    await page.clock.runFor(3500);
    expect(await page.evaluate(() => scrollY)).toBe(stopped);
    expect(await wheel(100)).toBe(false);
    await expect(page.locator('[class*="staticMarks"]').first()).toHaveCSS('visibility', 'visible');
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(layer).toBeHidden();
    expect(await wheel(100)).toBe(false);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.clock.resume();
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'instant' }));
    await page.locator('#main-content a[href="/report"]').first().click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await expect(layer).toHaveCSS('visibility', 'hidden');
    await wheel(100); // The dialog's own scroll lock may prevent background input.
    await expect(layer).toHaveAttribute('data-feed-state', 'idle');
    const reading = page.getByRole('region', { name: /Before you (file|send) information/ });
    await reading.hover();
    await page.mouse.wheel(0, 300);
    await expect.poll(() => reading.evaluate((el) => el.scrollTop)).toBeGreaterThan(0);
    await page.getByRole('button', { name: 'Cancel', exact: false }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await page.mouse.move(800, 500);
    await page.mouse.wheel(0, 600);
    await expect.poll(() => page.evaluate(() => scrollY)).toBe(resting);
    await expect(layer).toHaveAttribute('data-feed-state', 'idle');
});

test('QR login consumes the recovery link locally and enters the restore flow', async ({ page, baseURL }) => {
    const seen = await watch(page);
    const code = await encodeRecoveryCodeV2(new Uint8Array(32).fill(7));
    await page.goto(recoveryLink(baseURL!, code));
    await expect(page).toHaveURL(/\/status$/);
    await expect(page.locator('[data-failure="unavailable"]')).toBeVisible();
    // The service is deliberately unavailable. This still verifies that scanning
    // enters recovery without manual input and never transmits the code.
    expect(seen.urls.some((url) => url.includes('/api/confidential/'))).toBe(true);
    for (const text of [...seen.urls, ...seen.bodies]) expect(text).not.toContain(code);
    expect(seen.urls.some((url) => url.includes('/api/whistleblower/'))).toBe(false);
});
