// =============================================================================
// DASHBOARD TESTS (T-DASH-01..11) - Linux Hardener GUI Tests
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
  // Two unrelated elements used to read "Not scanned yet", the hero and the
  // header subtitle, so `.first()` silently decided which one this test was
  // about and would have passed on either. The subtitle is T-DASH-10's subject
  // and is history-backed; the hero is session-backed and now says so with
  // its own words, because "Not scanned yet" under "Last scanned 2026-02-23"
  // was two true statements that read as a contradiction.
  test('T-DASH-02: initial state reports nothing scanned', async ({ page }) => {
    await expect(page.locator('.score-empty-title')).toHaveText('No score yet');
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

    // The exact number, not just a band, because the band alone is a weak
    // assertion: two of the three bands span thirty points, so a scorer that
    // drifted by twenty could stay green. 73 is `calculate_all_scores`'s mean
    // over the ten frameworks the Dashboard requests (`ComplianceFramework::
    // ALL`), taken from `summary_score_percentage` and rounded:
    //
    //   (82.5 + 71 + 88 + 55 + 65 + 78.26 + 74 + 69 + 81 + 63) / 10
    //     = 72.676 -> 73, and `score_band` puts anything >= 70 in Good.
    //
    // GDPR's 78.26 is `(18 / 23) * 100` rather than a literal, because that
    // framework is the one carrying exclusions and its score has to be the
    // one its own counts imply.
    //
    // **This read 60 and "Needs attention" until 2026-08-19, and was wrong
    // from `b263ae10` onward.** That commit replaced the graded scorer (Pass
    // 100, ManualReview 80, a failure 25 to 90) with the report's own binary
    // one, which moved the mock's hero from 60 to 73; the expectation was
    // written for the graded scorer and nothing re-ran this suite until the
    // release-readiness batch of 2026-08-18, so it failed on all six
    // distributions at once. If a fixture percentage above changes, this
    // number changes with it and the failure will say so by name.
    //
    // The label is read off `.score-pill`, the one element that renders
    // `score_band_label`, rather than by text: "Good" is a substring of too
    // much to search the page for, and a band read from the element that
    // paints it cannot pass against a stray match elsewhere.
    expect(value).toBe(73);
    await expect(page.locator('.score-pill')).toHaveText('Good');
  });

  // T-DASH-11: The compliance row annotates excluded controls, and only where
  // there are some
  //
  // The row renders "<n> excluded by policy" behind `fs.excluded != 0`, and
  // until now nothing could reach it: the mock returned
  // `summary_not_applicable: 0` for all ten frameworks, so the branch was dead
  // to Playwright and to the contrast measurement alike. GDPR is the one
  // framework the fixture gives exclusions to.
  //
  // Both directions are asserted deliberately. A test that only looked for the
  // pill would pass just as happily against markup that rendered it
  // unconditionally, which is the defect this annotation exists to prevent: an
  // operator has to be able to tell a score raised by an exclusion from one
  // raised by the host improving. CIS is the control, carrying the same row
  // shape and an "unassessed" count but no exclusions, and its row is asserted
  // to exist before its pill is asserted absent, so the negative half cannot
  // pass by the row having disappeared.
  test('T-DASH-11: only a framework with exclusions carries the excluded annotation', async ({ page }) => {
    await runScan(page);
    // The list lives in a collapsed disclosure, so nothing inside it is visible
    // until the summary is clicked. Asserting on closed content would read the
    // text straight out of the DOM and call a hidden pill rendered.
    await page.locator('.compliance-disclosure > summary').click();

    // `has:` takes a page-rooted locator. Built from the scoped row instead it
    // matches nothing, and every assertion downstream passes vacuously.
    const frameworkRow = (name) =>
      page.locator('.compliance-item').filter({
        has: page.locator('.compliance-name', { hasText: new RegExp(`^${name}$`) }),
      });

    const gdpr = frameworkRow('GDPR');
    await expect(gdpr).toHaveCount(1);
    await expect(gdpr.locator('.compliance-excluded')).toBeVisible();
    await expect(gdpr.locator('.compliance-excluded')).toHaveText('6 excluded by policy');

    const cis = frameworkRow('CIS');
    await expect(cis).toHaveCount(1);
    await expect(cis.locator('.compliance-manual')).toBeVisible();
    await expect(cis.locator('.compliance-excluded')).toHaveCount(0);
  });
});
