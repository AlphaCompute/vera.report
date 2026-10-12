import { expect, test } from '@playwright/test';

for (const path of ['/status', '/legal', '/legal/report']) {
  test(`${path} blocks outbound organization website connections`, async ({ page }) => {
    let requests = 0;
    await page.route('https://onboarding.example/**', route => { requests++; return route.abort(); });
    const response = await page.goto(path);
    const policy = response!.headers()['content-security-policy'];
    expect(policy).not.toContain('onboarding.example');
    expect(policy).not.toMatch(/connect-src[^;]*(?:\shttps:|\s\*)(?:\s|;)/);
    expect(await page.evaluate(async () => {
      try { await fetch('https://onboarding.example/'); return false; }
      catch { return true; }
    })).toBe(true);
    expect(requests).toBe(0);
  });
}
