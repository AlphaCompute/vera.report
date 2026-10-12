import { defineConfig, devices } from '@playwright/test';
import fixture from '../tests/fixtures/confidential-release-manifest-vector.json';
const port = 3192;
// Confidential intake on a confidential build. The attested channel is
// intercepted (unavailable), so these checks cover the reporter-side flow up to
// and including a fail-closed submit. Legal key administration also needs a
// confidential build: with the mode off every /legal page is disabled.
export default defineConfig({
  testDir: './local-tests', testMatch: ['confidential-intake.spec.ts', 'confidential-administration.spec.ts', 'homepage-actions.spec.ts'], workers: 1, timeout: 180_000,
  expect: { timeout: 30_000 }, reporter: 'list',
  use: { ...devices['Desktop Chrome'], baseURL: `http://127.0.0.1:${port}`, headless: true,
    launchOptions: { args: ['--disable-webgl'] }, actionTimeout: 30_000, navigationTimeout: 60_000,
    screenshot: 'only-on-failure', trace: 'retain-on-failure' },
  webServer: {
    command: `npm --prefix .. run dev -- --webpack --hostname 127.0.0.1 --port ${port}`,
    url: `http://127.0.0.1:${port}/report`, reuseExistingServer: false, timeout: 180_000,
    env: { NEXT_PUBLIC_CONFIDENTIAL_CASES: '1', NEXT_PUBLIC_CONFIDENTIAL_RELEASE_MANIFEST: fixture.expected.canonical },
  },
});
