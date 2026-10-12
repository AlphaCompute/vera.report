import { defineConfig, devices } from '@playwright/test';

// Synthetic login pages test fixture mechanics, not Auth0 or deployment acceptance.
export default defineConfig({
  testDir: './fixture-tests',
  timeout: 45_000,
  workers: 1,
  use: { ...devices['Desktop Chrome'], baseURL: 'http://127.0.0.1:3199' },
});
