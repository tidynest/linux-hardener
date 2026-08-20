// =============================================================================
// SHARED TEST HELPERS - Linux Hardener GUI Tests
// =============================================================================

const { expect } = require('@playwright/test');
const { outputDir } = require('../output-dir');

/**
 * Wait for WASM to finish loading and the app to render.
 *
 * Waits on the main landmark, which exists once Leptos has hydrated and
 * routed. This used to wait on `.nav-header`, a class the interface redesign
 * removed, and the cost was not one failing test but the whole suite: every
 * spec's beforeEach calls this, so all 113 tests spent the full 30 s here
 * before reaching an assertion of their own, and the run passed the outer
 * 600 s ceiling and was killed. A landmark is the right thing to wait on
 * anyway. It says the application rendered, where a class says only that
 * someone kept the name.
 */
async function waitForApp(page) {
  await page.getByRole('main').waitFor({ state: 'visible', timeout: 30000 });
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
  // The name matches both states on purpose. The button's accessible name is
  // the very thing being waited on: it reads "Scanning..." mid-scan, so a
  // locator written only for the resting name resolves to nothing at exactly
  // the moment the wait matters, and Playwright reports a missing element
  // rather than a pending one. The failure is a race, so it looks like a
  // different bug on every machine: on a host where the mock settles before
  // the first poll the test passes, and on a slower one it fails instantly
  // with "element(s) not found" against a button plainly present in the
  // accessibility tree.
  const btn = page.getByRole('button', { name: /Run.*Scan|Scanning/i });
  await btn.click();
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
  await page.screenshot({ path: `${outputDir}/screenshots/${name}.png`, fullPage: true });
}

/**
 * Every theme the selector offers, in the order it lists them.
 *
 * One definition, read by themes.spec.js and contrast.spec.js. A second copy
 * is how a theme gets added to the picker and checked by only one of them.
 */
const THEMES = [
  { value: 'default', name: 'Midnight Teal', dataTheme: null },
  { value: 'fortress', name: 'Fortress', dataTheme: 'fortress' },
  { value: 'sentinel', name: 'Sentinel', dataTheme: 'sentinel' },
  { value: 'command', name: 'Command', dataTheme: 'command' },
  { value: 'guardian', name: 'Guardian', dataTheme: 'guardian' },
  { value: 'daywatch', name: 'Daywatch', dataTheme: 'daywatch' },
  { value: 'high-contrast', name: 'High Contrast', dataTheme: 'high-contrast' },
];

/**
 * Drive a full apply on `/hardening`, through the Configure tab, the preview
 * and the acknowledgement, leaving the results panel rendered.
 *
 * Lived in `hardening.spec.js` until `contrast.spec.js` needed the same five
 * steps to reach `.partial-row-badge-failed`, which renders only after an
 * apply. Moved rather than copied: the sequence encodes the confirmation flow,
 * so a second copy would be a second thing to update when that flow changes.
 */
async function runApply(page) {
  await page.getByRole('tab', { name: 'Configure' }).click();
  await page.getByRole('button', { name: /Preview Changes/i }).click();
  const apply = page.getByRole('button', { name: /Apply \d+ Changes/ });
  await expect(apply).toBeVisible({ timeout: 10000 });
  await page.getByText(/I understand this can affect/).click();
  await apply.click();
}

module.exports = {
  waitForApp,
  loadApp,
  runScan,
  runApply,
  selectTheme,
  takeScreenshot,
  THEMES,
};
