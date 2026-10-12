import { defineConfig, devices } from '@playwright/test';
export default defineConfig({ testDir: './local-tests', testMatch: 'product-sharing.spec.ts', workers: 1,
  timeout: 60_000, outputDir: '/tmp/vera-product-fixtures', use: { ...devices['Desktop Chrome'], headless: true } });
