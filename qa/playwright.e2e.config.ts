import { defineConfig, devices } from '@playwright/test';

// Click-through tests of the confidential-case feature against the local stack
// (qa/e2e/stack): MongoDB, the confidential API process, the enclave
// composition and the Next production server. Nitro attestation and identity-provider responses are synthetic.
// Run from the repository root, with no other Next build or server in this checkout:
//   node qa/node_modules/@playwright/test/cli.js test --config qa/playwright.e2e.config.ts
const port = Number(process.env.VERA_E2E_PORT || 3196);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid VERA_E2E_PORT');
process.env.VERA_E2E_PORT = String(port);

export default defineConfig({
  testDir: './e2e/specs',
  globalSetup: './e2e/global-setup.ts',
  workers: 1,
  fullyParallel: false,
  // Journeys run several attested sessions and OpenPGP key generations.
  // Global setup builds once; production serving avoids HMR session churn.
  timeout: 600_000,
  expect: { timeout: 60_000 },
  reporter: [['list']],
  outputDir: './e2e/test-results',
  use: {
    ...devices['Desktop Chrome'],
    // `localhost` (not 127.0.0.1): WebAuthn and the strict legal CSP need a host name.
    baseURL: `http://localhost:${port}`,
    headless: true,
    launchOptions: { args: ['--disable-webgl'] },
    actionTimeout: 60_000,
    navigationTimeout: 180_000,
    acceptDownloads: true,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'journeys', testIgnore: /access-expiry\.spec\.ts$/ },
    // Moves the stack's time forward for good (trusted time never goes back), so
    // it runs once every other spec has finished.
    { name: 'time-shifted', testMatch: /access-expiry\.spec\.ts$/, dependencies: ['journeys'] },
  ],
});
