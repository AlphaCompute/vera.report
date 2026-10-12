import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { evidenceResponseHeaders } from '../../src/utils/evidenceResponse';

// Browser enforcement of real response headers, using synthetic transport only.
// Authorization is exercised separately against the actual Next API below.
test('legacy PNG stays viewable while hostile HTML is downloaded without executing', async ({ page, baseURL }) => {
  const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=', 'base64');
  const hostile = '<html><script>window.evidenceExecuted=true</script>synthetic evidence</html>';
  const origin = new URL(baseURL!).origin;
  await page.route(`${origin}/evidence-fixture`, route => route.fulfill({ contentType: 'text/html', body:
    '<img alt="Synthetic PNG" src="/fixture-evidence/pixel.png"><a href="/fixture-evidence/unsafe.html">Open untrusted evidence</a>' }));
  await page.route(`${origin}/fixture-evidence/**`, route => {
    const image = route.request().url().endsWith('/pixel.png');
    return route.fulfill({ headers: evidenceResponseHeaders(image ? 'pixel.png' : 'unsafe.html', image ? 'image/png' : 'text/html'), body: image ? png : hostile });
  });
  await page.goto('/evidence-fixture');
  await expect.poll(() => page.getByRole('img', { name: 'Synthetic PNG' }).evaluate((image: HTMLImageElement) => image.naturalWidth)).toBe(1);
  const downloading = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Open untrusted evidence' }).click();
  const download = await downloading;
  expect(download.suggestedFilename()).toBe('unsafe.html');
  expect(readFileSync((await download.path())!, 'utf8')).toBe(hostile);
  await expect(page).toHaveURL(`${origin}/evidence-fixture`);
  expect(await page.evaluate(() => (window as any).evidenceExecuted)).toBeUndefined();
});

test('the real legacy evidence proxy refuses a signed-out browser', async ({ request }) => {
  const response = await request.get('/api/whistleblower/evidence/VRA-0000000000000001/synthetic.png', { maxRedirects: 0 });
  expect([401, 403]).toContain(response.status());
  expect(response.headers()['content-type']).not.toContain('image/');
  expect(response.headers()['content-disposition']).toBeUndefined();
});
