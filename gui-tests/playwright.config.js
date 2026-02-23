// @ts-check
const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests',
  timeout: 30000,
  retries: 0,
  workers: 1, // Sequential — shared HTTP server

  use: {
    baseURL: 'http://localhost:8787',
    headless: true,
    screenshot: 'only-on-failure',
    trace: 'off',
    // Generous timeouts for WASM loading inside containers
    navigationTimeout: 15000,
    actionTimeout: 10000,
    // Use system Chromium instead of Playwright-bundled browser
    launchOptions: {
      executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || undefined,
      args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage'],
    },
  },

  reporter: [
    ['list'],
    ['json', { outputFile: 'test-results/results.json' }],
  ],

  outputDir: 'test-results',
});
