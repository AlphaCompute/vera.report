import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './local-tests', testMatch: 'device-vault.spec.ts', fullyParallel: false,
  workers: 1, timeout: 30_000, reporter: 'list', use: { browserName: 'chromium', headless: true },
});
