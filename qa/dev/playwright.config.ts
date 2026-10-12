import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: '.', testMatch: 'review.spec.ts', workers: 1, timeout: 180_000,
  expect: { timeout: 60_000 }, outputDir: '/tmp/vera-dev-review-tests',
  use: { baseURL: process.env.VERA_DEV_REVIEW_URL || 'http://127.0.0.1:3000', headless: true, reducedMotion: 'reduce', launchOptions: { args: ['--disable-webgl'] }, screenshot: 'only-on-failure' },
});
