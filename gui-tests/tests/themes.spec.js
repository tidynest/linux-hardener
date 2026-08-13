// =============================================================================
// THEME TESTS (T-THEME-01..09) + 35 Screenshot Captures
// =============================================================================

const { test, expect } = require('@playwright/test');
const { loadApp, runScan, selectTheme, takeScreenshot, THEMES } = require('./helpers');

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

  // T-THEME-08: High Contrast theme. This one asserts the rendered colours as
  // well as the attribute, unlike its six siblings above. The attribute being
  // present says the selector fired; it does not say the rule won. A
  // `[data-theme="high-contrast"]` block whose custom properties are beaten
  // later in the cascade renders identically to no theme at all and passes a
  // `toHaveAttribute` check, and this is the theme where that failure is an
  // accessibility one rather than a cosmetic one. `body` resolves
  // `background-color` and `color` straight from `--bg-primary` and
  // `--text-primary`, so reading them back is reading what the user sees.
  test('T-THEME-08: High Contrast applies data-theme and renders its WCAG AAA colours', async ({
    page,
  }) => {
    await selectTheme(page, 'high-contrast');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'high-contrast');

    const rendered = await page.evaluate(() => {
      const style = getComputedStyle(document.body);
      return { background: style.backgroundColor, text: style.color };
    });
    expect(rendered.background).toBe('rgb(0, 0, 0)');
    expect(rendered.text).toBe('rgb(255, 255, 255)');
  });

  // T-THEME-09: every theme the application offers is covered by this file.
  // The seven cases above and the screenshot matrix below both enumerate
  // themes by hand, and the application enumerates them again in
  // `crates/hardener-ui/src/utils/theme.rs`. Three hand-maintained copies of
  // one fact drift, and this suite already proved it: High Contrast shipped
  // with a selector entry, a stylesheet block and no test, and six of seven
  // themes read as full coverage because nothing compared the lists. A
  // per-theme check cannot catch that, because it has to be written for the
  // theme nobody remembered. This one asks the page instead, so the eighth
  // theme fails here on the day it is added.
  test('T-THEME-09: the theme selector offers exactly the themes this file covers', async ({
    page,
  }) => {
    const offered = await page.$$eval('#theme-select option', (options) =>
      options.map((option) => option.value).sort()
    );
    expect(offered).toEqual(THEMES.map((theme) => theme.value).sort());
  });
});

// ---------------------------------------------------------------------------
// SCREENSHOT CAPTURES - 5 states x 7 themes = 35 screenshots
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
    // Reached directly rather than through the dashboard. This used to click a
    // "View Analysis" quick-action, which the redesign removed, and the click
    // failed for all six themes: one dead control, six failing screenshots.
    // The state being captured is Analysis carrying findings, and scanning from
    // that page produces it without depending on how one arrives.
    setup: async (page) => {
      await loadApp(page, '/analysis');
      await runScan(page);
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
  // Longer timeout for screenshot captures - Chromium slows under memory
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
