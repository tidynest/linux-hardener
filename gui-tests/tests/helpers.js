// =============================================================================
// SHARED TEST HELPERS — Linux System Hardener GUI Tests
// =============================================================================

const { expect } = require('@playwright/test');

/**
 * Wait for WASM to finish loading and the app to render.
 * Checks for the nav header which only appears after Leptos hydrates.
 */
async function waitForApp(page) {
  await page.waitForSelector('.nav-header', { timeout: 15000 });
}

/**
 * Navigate to the app and wait for load. Optionally append query params.
 */
async function loadApp(page, path = '/', query = '') {
  const url = path + (query ? `?${query}` : '');
  await page.goto(url);
  await waitForApp(page);
}

/**
 * Click the "Run Scan" / "Run Security Scan" button and wait for results.
 * The button text changes to "Scanning..." while in progress.
 */
async function runScan(page) {
  const btn = page.getByRole('button', { name: /Run.*Scan/i });
  await btn.click();
  // Wait for scanning to complete (button text reverts from "Scanning...")
  await expect(btn).not.toHaveText(/Scanning/i, { timeout: 10000 });
}

/**
 * Switch to a named theme via the theme dropdown.
 */
async function selectTheme(page, themeValue) {
  await page.selectOption('#theme-select', themeValue);
  // Small delay for CSS transition
  await page.waitForTimeout(300);
}

/**
 * Take a named screenshot and save to the screenshots directory.
 */
async function takeScreenshot(page, name) {
  await page.screenshot({ path: `test-results/screenshots/${name}.png`, fullPage: true });
}

module.exports = { waitForApp, loadApp, runScan, selectTheme, takeScreenshot };
