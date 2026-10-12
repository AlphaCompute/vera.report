import { defineConfig, devices } from '@playwright/test';
import fixture from '../tests/fixtures/confidential-release-manifest-vector.json';
// Legal organization onboarding and device unlock against the actual Next pages.
// `localhost` (not 127.0.0.1) because WebAuthn needs a domain as its relying party.
const port = Number(process.env.VERA_ONBOARDING_QA_PORT || 3194);
export default defineConfig({
  testDir: './local-tests', testMatch: ['firm-onboarding.spec.ts', 'firm-domain-csp.spec.ts'], workers: 1, timeout: 300_000,
  expect: { timeout: 30_000 }, reporter: 'list',
  use: { ...devices['Desktop Chrome'], baseURL: `http://localhost:${port}`, headless: true,
    launchOptions: { args: ['--disable-webgl'] }, actionTimeout: 30_000, navigationTimeout: 60_000,
    screenshot: 'only-on-failure', trace: 'retain-on-failure' },
  webServer: {
    command: `npm --prefix .. run dev -- --webpack --hostname localhost --port ${port}`,
    url: `http://localhost:${port}/legal`, reuseExistingServer: false,
    timeout: Number(process.env.VERA_ONBOARDING_QA_SERVER_TIMEOUT_MS || 180_000),
    env: { NEXT_PUBLIC_CONFIDENTIAL_CASES: '1', NEXT_PUBLIC_CONFIDENTIAL_RELEASE_MANIFEST: fixture.expected.canonical,
      NEXT_PUBLIC_LEGAL_AUTH0_DOMAIN: 'identity.example', NEXT_PUBLIC_LEGAL_AUTH0_CLIENT_ID: 'legal-test-client',
      NEXT_PUBLIC_LEGAL_AUTH0_AUDIENCE: 'https://legal.example' },
  },
});
