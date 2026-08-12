// =============================================================================
// SETTINGS PAGE TESTS (T-SET-01..08)
// =============================================================================
//
// The /settings route had no coverage at all while this suite shipped 35 theme
// screenshots as evidence, so the page that selects a theme was the one page
// nothing tested. It earns tests cheaply: `SettingsPage` calls no IPC, so
// nothing here needs a fixture in `tauri-mock.js` and nothing here can drift
// away from a Rust type.
//
// The subject is `ThemePicker`, which is not presentational. It is a
// `role="radiogroup"` with a hand-written `on:keydown` implementing Arrow, Home
// and End over a roving tabindex, and `focus_swatch` moves focus by element id
// to dodge a race with the aria-checked re-render. That is real logic, and
// these are the suite's first `toBeFocused` assertions.
//
// One quirk shapes every assertion below: `apply_theme` REMOVES `data-theme`
// for the default theme rather than setting it, because "default" is the base
// `:root` block. So selection is asserted through `aria-checked`, which is
// uniform across all seven, and `data-theme` is only read for the six that set
// it.

const { test, expect } = require('@playwright/test');
const { loadApp } = require('./helpers');

// Mirrors `THEMES` in crates/hardener-ui/src/utils/theme.rs. T-SET-02 is what
// stops this copy drifting: it compares the rendered radios against the header
// selector's own options rather than against this list.
const FIRST = { id: 'default', name: 'Midnight Teal' };
const SECOND = { id: 'fortress', name: 'Fortress' };
const LAST = { id: 'high-contrast', name: 'High Contrast' };

const swatch = (page, id) => page.locator(`#theme-swatch-${id}`);

/** Focuses the currently selected swatch, which is the only one with tabindex 0. */
async function focusSelected(page) {
  const active = page.locator('.theme-grid [role="radio"][aria-checked="true"]');
  await active.focus();
  await expect(active).toBeFocused();
}

test.describe('Settings', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/settings');
  });

  // T-SET-01: the route renders, with both blocks.
  test('T-SET-01: settings page renders Appearance and About', async ({ page }) => {
    await expect(page.locator('.settings-page')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Appearance' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'About' })).toBeVisible();
    await expect(page.locator('.settings-block')).toHaveCount(2);
  });

  // T-SET-02: the grid offers exactly the themes the application offers.
  //
  // Asks the page for both lists rather than comparing against the constant at
  // the top of this file. Same reasoning as T-THEME-09: the theme list is
  // written out by hand in the Rust source, in the header selector and in this
  // suite, and a per-theme test cannot catch the theme nobody remembered to
  // add. An eighth theme fails here on the day it lands.
  test('T-SET-02: the swatch grid offers exactly the themes the selector offers', async ({
    page,
  }) => {
    const group = page.locator('.theme-grid[role="radiogroup"]');
    await expect(group).toHaveAttribute('aria-label', 'Colour theme');

    const swatchNames = await group.locator('[role="radio"]').evaluateAll((els) =>
      els.map((el) => el.getAttribute('aria-label')).sort()
    );
    const selectNames = await page
      .locator('#theme-select option')
      .evaluateAll((els) => els.map((el) => el.textContent.trim()).sort());

    expect(swatchNames).toEqual(selectNames);
    expect(swatchNames.length).toBe(7);
  });

  // T-SET-03: clicking a swatch applies the theme, and the header follows.
  //
  // The second half is the point. The swatch grid and the header selector are
  // two controls over one `AppState.theme` signal, so they can desynchronise
  // without either one looking broken on its own.
  test('T-SET-03: clicking a swatch applies the theme and the header selector follows', async ({
    page,
  }) => {
    await swatch(page, SECOND.id).click();

    await expect(page.locator('html')).toHaveAttribute('data-theme', SECOND.id);
    await expect(swatch(page, SECOND.id)).toHaveAttribute('aria-checked', 'true');
    await expect(swatch(page, FIRST.id)).toHaveAttribute('aria-checked', 'false');
    await expect(page.locator('#theme-select')).toHaveValue(SECOND.id);
  });

  // T-SET-04: ArrowRight moves selection and focus together.
  test('T-SET-04: ArrowRight advances the selection and takes focus with it', async ({ page }) => {
    await focusSelected(page);
    await page.keyboard.press('ArrowRight');

    await expect(swatch(page, SECOND.id)).toHaveAttribute('aria-checked', 'true');
    await expect(swatch(page, SECOND.id)).toBeFocused();
    await expect(page.locator('html')).toHaveAttribute('data-theme', SECOND.id);
  });

  // T-SET-05: ArrowLeft from the first wraps to the last.
  //
  // `current.checked_sub(1).unwrap_or(count - 1)` is the wrap, and an
  // off-by-one there is invisible anywhere except at this boundary.
  test('T-SET-05: ArrowLeft from the first swatch wraps to the last', async ({ page }) => {
    await focusSelected(page);
    await page.keyboard.press('ArrowLeft');

    await expect(swatch(page, LAST.id)).toHaveAttribute('aria-checked', 'true');
    await expect(swatch(page, LAST.id)).toBeFocused();
    await expect(page.locator('html')).toHaveAttribute('data-theme', LAST.id);
  });

  // T-SET-06: Home and End jump to the ends.
  //
  // Home lands on the default theme, whose `data-theme` is removed rather than
  // set, so this asserts the attribute is gone. That is the branch in
  // `apply_theme` that a test written only against the other six never reaches.
  test('T-SET-06: End jumps to the last swatch and Home returns to the first', async ({ page }) => {
    await focusSelected(page);

    await page.keyboard.press('End');
    await expect(swatch(page, LAST.id)).toHaveAttribute('aria-checked', 'true');
    await expect(swatch(page, LAST.id)).toBeFocused();

    await page.keyboard.press('Home');
    await expect(swatch(page, FIRST.id)).toHaveAttribute('aria-checked', 'true');
    await expect(swatch(page, FIRST.id)).toBeFocused();
    await expect(page.locator('html')).not.toHaveAttribute('data-theme', /.+/);
  });

  // T-SET-07: the roving tabindex leaves exactly one tab stop.
  //
  // A radiogroup where every radio is tabbable makes a keyboard user press Tab
  // seven times to leave the grid. The markup sets tabindex 0 on the selected
  // swatch and -1 on the rest, and that has to hold after a selection changes,
  // not only on first render.
  test('T-SET-07: exactly one swatch is tabbable, and it is the selected one', async ({ page }) => {
    const radios = page.locator('.theme-grid [role="radio"]');
    await expect(radios).toHaveCount(7);

    const tabbableBefore = await radios.evaluateAll((els) =>
      els.filter((el) => el.getAttribute('tabindex') === '0').map((el) => el.id)
    );
    expect(tabbableBefore).toEqual([`theme-swatch-${FIRST.id}`]);

    await swatch(page, SECOND.id).click();

    const tabbableAfter = await radios.evaluateAll((els) =>
      els.filter((el) => el.getAttribute('tabindex') === '0').map((el) => el.id)
    );
    expect(tabbableAfter).toEqual([`theme-swatch-${SECOND.id}`]);
    await expect(swatch(page, FIRST.id)).toHaveAttribute('tabindex', '-1');
  });

  // T-SET-08: the About block reports a real version and build identity.
  //
  // Both come from `env!` at compile time, so no browser-side test can check
  // they are correct, only that they are present and non-empty. An empty string
  // here means the build did not set `HARDENER_BUILD_IDENTITY`, which is
  // exactly the state a release must not ship in.
  test('T-SET-08: About reports a non-empty version and build identity', async ({ page }) => {
    const about = page.locator('.settings-about');
    await expect(about).toBeVisible();

    const rows = await about.locator('.settings-about-row').evaluateAll((els) =>
      Object.fromEntries(
        els.map((el) => [
          el.querySelector('dt')?.textContent.trim(),
          el.querySelector('dd')?.textContent.trim(),
        ])
      )
    );

    expect(rows.Application).toBe('Linux Hardener');
    expect(rows.Version).toMatch(/^\d+\.\d+\.\d+/);
    expect(rows.Build).toBeTruthy();
    expect(rows.Build.length).toBeGreaterThan(0);
  });
});
