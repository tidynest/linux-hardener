// =============================================================================
// THEME TESTS (T-THEME-01..07) + 30 Screenshot Captures
// =============================================================================

const { test, expect } = require('@playwright/test');
const { loadApp, runScan, selectTheme, takeScreenshot } = require('./helpers');

const THEMES = [
  { value: 'default', name: 'Midnight Teal', dataTheme: null },
  { value: 'fortress', name: 'Fortress', dataTheme: 'fortress' },
  { value: 'sentinel', name: 'Sentinel', dataTheme: 'sentinel' },
  { value: 'command', name: 'Command', dataTheme: 'command' },
  { value: 'guardian', name: 'Guardian', dataTheme: 'guardian' },
  { value: 'daywatch', name: 'Daywatch', dataTheme: 'daywatch' },
];

test.describe('Themes', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/');
  });

  // T-THEME-01: Theme selector dropdown visible
  test('T-THEME-01: theme selector dropdown visible in nav', async ({ page }) => {
    await expect(page.locator('#theme-select')).toBeVisible();
  });

  // T-THEME-02: Midnight Teal is default
  test('T-THEME-02: Midnight Teal is the default theme', async ({ page }) => {
    const html = page.locator('html');
    const dataTheme = await html.getAttribute('data-theme');
    // Default theme either has no data-theme or "midnight-teal"
    expect(dataTheme === null || dataTheme === '' || dataTheme === 'default').toBeTruthy();
  });

  // T-THEME-03: Fortress theme
  test('T-THEME-03: Fortress theme applies data-theme', async ({ page }) => {
    await selectTheme(page, 'fortress');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'fortress');
  });

  // T-THEME-04: Sentinel theme
  test('T-THEME-04: Sentinel theme applies data-theme', async ({ page }) => {
    await selectTheme(page, 'sentinel');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'sentinel');
  });

  // T-THEME-05: Command theme
  test('T-THEME-05: Command theme applies data-theme', async ({ page }) => {
    await selectTheme(page, 'command');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'command');
  });

  // T-THEME-06: Guardian theme
  test('T-THEME-06: Guardian theme applies data-theme', async ({ page }) => {
    await selectTheme(page, 'guardian');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'guardian');
  });

  // T-THEME-07: Daywatch theme
  test('T-THEME-07: Daywatch theme applies data-theme', async ({ page }) => {
    await selectTheme(page, 'daywatch');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'daywatch');
  });
});

// ---------------------------------------------------------------------------
// SCREENSHOT CAPTURES — 5 states x 6 themes = 30 screenshots
// ---------------------------------------------------------------------------

const STATES = [
  {
    name: 'dashboard-empty',
    setup: async (page) => {
      await loadApp(page, '/');
    },
  },
  {
    name: 'dashboard-scanned',
    setup: async (page) => {
      await loadApp(page, '/');
      await runScan(page);
    },
  },
  {
    name: 'analysis-findings',
    setup: async (page) => {
      await loadApp(page, '/');
      await runScan(page);
      await page.getByRole('link', { name: /View Analysis/i }).or(
        page.locator('.btn', { hasText: /View Analysis/i })
      ).click();
      await page.waitForURL(/\/analysis/);
    },
  },
  {
    name: 'hardening-configure',
    setup: async (page) => {
      await loadApp(page, '/hardening');
    },
  },
  {
    name: 'hardening-history',
    setup: async (page) => {
      await loadApp(page, '/hardening');
      await page.getByRole('tab', { name: 'History' }).click();
      await page.waitForSelector('.history-section', { timeout: 10000 });
    },
  },
];

test.describe('Theme Screenshots', () => {
  // Longer timeout for screenshot captures — Chromium slows under memory
  // pressure after 70+ prior tests in containerised environments
  test.describe.configure({ timeout: 60000 });

  for (const theme of THEMES) {
    for (const state of STATES) {
      test(`screenshot: ${state.name} [${theme.name}]`, async ({ page }) => {
        await state.setup(page);
        await selectTheme(page, theme.value);
        await takeScreenshot(page, `${state.name}_${theme.value}`);
      });
    }
  }
});
