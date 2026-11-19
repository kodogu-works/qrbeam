import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './src/tests/browser',
  testMatch: '**/*.spec.ts',
  timeout: 180_000,
  expect: { timeout: 60_000 },
  fullyParallel: false,
  workers: 1,
  reporter: 'list',
  use: {
    browserName: 'chromium', headless: true,
    viewport: { width: 1366, height: 1000 },
    screenshot: 'only-on-failure', trace: 'retain-on-failure',
  },
});
