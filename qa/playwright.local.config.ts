import { defineConfig, devices } from '@playwright/test';
import fixture from '../tests/fixtures/confidential-release-manifest-vector.json';

const port = Number(process.env.VERA_QA_PORT || 3100);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid VERA_QA_PORT');
const baseURL = `http://127.0.0.1:${port}`;
const production = process.env.VERA_QA_PRODUCTION === '1';

const visual = process.env.VERA_VISUAL_TEST === '1';

// Local-only UI regressions: the report API is intercepted by each test.
export default defineConfig({
  testDir: './local-tests',
  // Confidential workspace checks have isolated origin/build settings.
  // Run them with playwright.vault.config.ts, playwright.participant.config.ts,
  // playwright.intake.config.ts and playwright.onboarding.config.ts.
  testIgnore: [
    '**/device-vault.spec.ts',
    '**/participant-workspaces.spec.ts',
    '**/legal-request-status.spec.ts',
    '**/legal-invite-feedback.spec.ts',
    '**/confidential-intake.spec.ts',
    '**/confidential-administration.spec.ts',
    '**/firm-domain-csp.spec.ts',
    '**/legal-browser-privacy.spec.ts',
    '**/legal-report-view.spec.ts',
    '**/firm-onboarding.spec.ts',
    '**/receipt-lock.spec.ts',
    '**/owner-status-failures.spec.ts',
  ],
  timeout: 120_000,
  expect: { timeout: 20_000 },
  workers: 1,
  use: {
    baseURL,
    ...devices['Desktop Chrome'],
    headless: !visual,
    launchOptions: { slowMo: visual ? 500 : 0, args: ['--disable-webgl'] },
    video: visual ? 'on' : 'off',
    trace: visual ? 'on' : 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  webServer: {
    // Synthetic local-only session configuration. Signed-out authorization
    // needs a configured SDK, but these tests never start a provider login.
    env: {
      // Local UI checks run the confidential build, as deployed; the suites supply a synthetic release.
      NEXT_PUBLIC_CONFIDENTIAL_CASES: '1',
      NEXT_PUBLIC_CONFIDENTIAL_RELEASE_MANIFEST: fixture.expected.canonical,
      AUTH0_DOMAIN: 'identity.invalid',
      AUTH0_CLIENT_ID: 'local-ui-fixture',
      AUTH0_CLIENT_SECRET: 'synthetic-local-ui-client-not-a-credential',
      AUTH0_SECRET: 'synthetic-local-ui-session-key-not-a-credential-00000000000000000000',
      APP_BASE_URL: baseURL,
    },
    command: production
      ? `npm --prefix .. run start:next -- --hostname 127.0.0.1 --port ${port}`
      : `npm --prefix .. run dev -- --webpack --hostname 127.0.0.1 --port ${port}`,
    url: `${baseURL}/report`,
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
