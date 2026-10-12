import { defineConfig, devices } from '@playwright/test';
import fixture from '../tests/fixtures/confidential-release-manifest-vector.json';
const port = Number(process.env.VERA_PARTICIPANT_TEST_PORT || process.env.VERA_PARTICIPANT_QA_PORT || 3188);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid VERA_PARTICIPANT_TEST_PORT / VERA_PARTICIPANT_QA_PORT');
// Each scenario covers several full recovery/unlock flows against a compiling
// dev server. Bound individual actions separately from the complete journey.
export default defineConfig({
  testDir: './local-tests', testMatch: ['participant-workspaces.spec.ts', 'fixture-bundle.spec.ts', 'legal-request-status.spec.ts', 'legal-invite-feedback.spec.ts', 'legal-browser-privacy.spec.ts', 'legal-report-view.spec.ts', 'owner-report-view.spec.ts', 'receipt-lock.spec.ts', 'owner-status-failures.spec.ts'], workers: 1, timeout: 300_000,
  expect: { timeout: 30_000 }, reporter: 'list',
  use: { ...devices['Desktop Chrome'], baseURL: `http://127.0.0.1:${port}`, headless: true,
    // Match the existing report-flow runner: software WebGL rendering can
    // starve input processing on CI. These checks cover recovery, not graphics.
    launchOptions: { args: ['--disable-webgl'] },
    actionTimeout: 30_000, navigationTimeout: 60_000,
    screenshot: 'only-on-failure', trace: 'retain-on-failure' },
  webServer: {
    command: `npm --prefix .. run dev -- --webpack --hostname 127.0.0.1 --port ${port}`,
    url: `http://127.0.0.1:${port}/status`, reuseExistingServer: false, timeout: 300_000,
    env: { NEXT_PUBLIC_CONFIDENTIAL_CASES: '1', NEXT_PUBLIC_CONFIDENTIAL_RELEASE_MANIFEST: fixture.expected.canonical,
      NEXT_PUBLIC_LEGAL_AUTH0_DOMAIN: 'identity.example', NEXT_PUBLIC_LEGAL_AUTH0_CLIENT_ID: 'legal-test-client',
      NEXT_PUBLIC_LEGAL_AUTH0_AUDIENCE: 'https://legal.example' },
  },
});
