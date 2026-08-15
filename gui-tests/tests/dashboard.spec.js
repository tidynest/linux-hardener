// =============================================================================
// DASHBOARD TESTS (T-DASH-01..10) - Linux Hardener GUI Tests
// =============================================================================
//
// The redesign renamed the heading, replaced the numeric score panel with a
// score bar exposed as a status region reading "<score>/100" beside a band
// label, and dropped the two quick-action buttons: the only in-page link is the
// activity entry's "View", and Hardening is reached from the sidebar.

const { test, expect } = require('@playwright/test');
const { loadApp, runScan } = require('./helpers');

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/');
  });

  // T-DASH-01: Page loads
  test('T-DASH-01: page loads with heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Dashboard', level: 1 })).toBeVisible();
  });

  // T-DASH-02: Before a scan there is no score to show
  //
  // Was `.score-value` reading '--' beside a `.score-max` of '/100'. The score
  // is now a bar that is simply absent until there is something to plot, so the
  // placeholder it used to assert no longer exists to be checked.
  // Asserts the score hero by class rather than by text through `.first()`.
  // Two unrelated elements read "Not scanned yet", the hero and the header
  // subtitle, so `.first()` silently decided which one this test was about and
  // would have passed on either. The subtitle is T-DASH-10's subject and says
  // something different; this one is only about the hero.
  test('T-DASH-02: initial state reports nothing scanned', async ({ page }) => {
    await expect(page.locator('.score-empty-title')).toHaveText('Not scanned yet');
    await expect(page.getByRole('status')).toHaveCount(0);
  });

  // T-DASH-10: The header subtitle names the last completed scan
  //
  // Its populated branch had never rendered. `last_scanned_label` reads
  // `completed_at`, which the mock omitted while claiming `status: 'completed'`,
  // so the subtitle showed the empty-state string over a scanned page in all
  // seven themes and no test looked at it. The subtitle is history-backed and
  // the hero is session-backed, so this holds on a freshly loaded page.
  test('T-DASH-10: header subtitle names the last completed scan', async ({ page }) => {
    await expect(page.locator('.dashboard-subtitle')).toHaveText(/^Last scanned \S/);
  });

  // T-DASH-03: Run Scan button visible and enabled
  test('T-DASH-03: Run Security Scan button is visible and enabled', async ({ page }) => {
    const btn = page.getByRole('button', { name: /Run Security Scan/i });
    await expect(btn).toBeVisible();
    await expect(btn).toBeEnabled();
  });

  // T-DASH-04: Click Run Scan populates results
  test('T-DASH-04: clicking Run Security Scan populates the score', async ({ page }) => {
    await runScan(page);
    await expect(page.getByRole('status')).toHaveText(/^\d+\/100$/);
  });

  // T-DASH-05: The activity entry links through to Analysis
  //
  // Was a "View Analysis" quick-action button. The redesign moved that journey
  // into the activity entry the scan produces, which is the only place on this
  // page that now links to /analysis.
  test('T-DASH-05: activity entry links to Analysis', async ({ page }) => {
    await runScan(page);
    await page.getByRole('link', { name: 'View' }).first().click();
    await expect(page).toHaveURL(/\/analysis/);
  });

  // T-DASH-06: Hardening is reachable from the sidebar
  //
  // Was a "Configure Hardening" quick-action button, which the redesign
  // dropped: the grouped sidebar is how the sections are reached. The journey
  // being covered is the same one, by the route an operator now takes.
  test('T-DASH-06: sidebar navigates to Hardening', async ({ page }) => {
    await page
      .getByRole('navigation', { name: 'Main navigation' })
      .getByRole('link', { name: 'Hardening' })
      .click();
    await expect(page).toHaveURL(/\/hardening/);
  });

  // T-DASH-07: Initial activity shows empty state
  test('T-DASH-07: initial activity shows "No activity yet"', async ({ page }) => {
    await expect(page.locator('.empty-state-title')).toContainText('No activity yet');
  });

  // T-DASH-08: Post-scan activity shows scan entry
  test('T-DASH-08: after scan, activity shows Security Scan with finding count', async ({ page }) => {
    await runScan(page);
    const activity = page.locator('.activity-item').first();
    await expect(activity).toContainText('Security Scan');
    await expect(activity).toContainText('findings');
  });

  // T-DASH-09: Post-scan score is numeric and banded
  //
  // The colour class this used to read (`score-pending` on `.score-display`) is
  // gone with the numeric panel. The band label beside the score carries the
  // same meaning in text, which is the more honest thing to assert: a colour
  // an operator cannot read is not what tells them where they stand.
  test('T-DASH-09: after scan, score is numeric and banded', async ({ page }) => {
    await runScan(page);
    const score = page.getByRole('status');
    await expect(score).toHaveText(/^\d+\/100$/);
    const value = Number((await score.textContent()).split('/')[0]);
    expect(value).toBeGreaterThan(0);
    expect(value).toBeLessThanOrEqual(100);
    // The mock scores 60, which is the middle band.
    await expect(page.getByText('Needs attention')).toBeVisible();
  });
});
