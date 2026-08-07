// =============================================================================
// ANALYSIS TESTS - Findings (T-FIND-01..10) + Compliance (T-COMP-01..08)
// =============================================================================

const { test, expect } = require('@playwright/test');
const { loadApp, runScan } = require('./helpers');

// ---------------------------------------------------------------------------
// FINDINGS TAB
// ---------------------------------------------------------------------------

test.describe('Findings', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/analysis');
  });

  // T-FIND-01: Page loads with heading and Findings tab selected
  //
  // The heading is 'Analysis'; the redesign dropped the 'Security' prefix. The
  // selected tab is read from aria-selected rather than a `tab-active` class:
  // the attribute is what a screen reader and the browser act on, so it is the
  // thing that is actually wrong if it stops being set.
  test('T-FIND-01: page loads with the Analysis heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Analysis', level: 1 })).toBeVisible();
    await expect(page.getByRole('tab', { name: 'Findings' }))
      .toHaveAttribute('aria-selected', 'true');
  });

  // T-FIND-02: Empty state before scan
  test('T-FIND-02: shows "No findings yet" before scan', async ({ page }) => {
    await expect(page.locator('#panel-findings .empty-state-title')).toContainText('No findings yet');
  });

  // T-FIND-03: Scan button visible in header
  test('T-FIND-03: Run Security Scan button visible', async ({ page }) => {
    const btn = page.getByRole('button', { name: /Run Security Scan/i });
    await expect(btn).toBeVisible();
  });

  // T-FIND-04: Clicking scan populates findings table
  test('T-FIND-04: clicking scan populates findings table', async ({ page }) => {
    await runScan(page);
    const rows = page.locator('.finding-row');
    await expect(rows.first()).toBeVisible();
    const count = await rows.count();
    expect(count).toBeGreaterThan(0);
  });

  // T-FIND-05: Findings are grouped by severity
  //
  // This asserted a table with Severity, Category and Title columns. The
  // redesign has no findings table: findings are grouped under severity
  // headings, which the empty state announces in as many words ("Findings are
  // grouped by severity"). Repairing the column selectors would have pinned a
  // layout the interface deliberately stopped having, so the test now covers
  // the grouping that replaced it.
  test('T-FIND-05: findings are grouped by severity', async ({ page }) => {
    await runScan(page);
    const panel = page.getByRole('tabpanel', { name: 'Findings' });
    for (const severity of ['Critical', 'High', 'Medium']) {
      await expect(panel.getByText(severity, { exact: true })).toBeVisible();
    }
  });

  // T-FIND-06: Clicking a finding row shows detail panel
  test('T-FIND-06: clicking a finding row opens detail panel', async ({ page }) => {
    await runScan(page);
    await page.locator('.finding-row').first().click();
    await expect(page.locator('.finding-detail')).toBeVisible();
  });

  // T-FIND-07: An expanded finding shows its detail
  //
  // The detail is an inline expander below the finding, not a separate panel
  // with its own header: the title stays in the button that expands it, so
  // `.detail-header h2` describes markup that no longer exists.
  //
  // The remediation step count is asserted as a number. It previously read
  // `toHaveCount(await ...count())`, which compares the count against itself
  // and therefore passes for every value including zero, so the one assertion
  // covering remediation steps could not fail.
  test('T-FIND-07: an expanded finding shows its description and remediation', async ({ page }) => {
    await runScan(page);
    await page.getByRole('button', { name: /ASLR not fully enabled/ }).click();
    const detail = page.locator('.finding-detail');
    await expect(detail).toBeVisible();
    await expect(detail).toContainText('Address Space Layout Randomisation');
    await expect(detail).toContainText('Remediation');
    await expect(detail.getByRole('listitem')).toHaveCount(2);
    await expect(detail.getByRole('link', { name: /Configure Fix/i })).toBeVisible();
  });

  // T-FIND-08: The expander closes the way it opened
  //
  // There is no close button. The finding's own button toggles, so collapsing
  // is a second click on the thing that expanded it. Asserted through the
  // detail's visibility rather than aria-expanded, because whether the
  // attribute is rendered at all in the collapsed state is a detail of the
  // component and not the behaviour under test.
  test('T-FIND-08: clicking an expanded finding collapses it', async ({ page }) => {
    await runScan(page);
    const finding = page.getByRole('button', { name: /ASLR not fully enabled/ });
    await finding.click();
    await expect(page.locator('.finding-detail')).toBeVisible();
    await finding.click();
    await expect(page.locator('.finding-detail')).not.toBeVisible();
  });

  // T-FIND-09: Finding count matches table rows
  test('T-FIND-09: finding count matches rows in table', async ({ page }) => {
    await runScan(page);
    const rows = page.locator('.finding-row');
    const count = await rows.count();
    // Mock has 8 total findings across 6 plugins
    expect(count).toBe(8);
  });

  // T-FIND-10: MiniSecurityScore appears after scan
  test('T-FIND-10: mini security score component is visible', async ({ page }) => {
    const miniScore = page.locator('.mini-security-score');
    await expect(miniScore).toBeVisible();
    // Score value starts as "--" (pending) until compliance reports are generated
    const value = page.locator('.mini-score-value');
    await expect(value).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// COMPLIANCE TAB
// ---------------------------------------------------------------------------

// The frameworks are aria-pressed toggle buttons inside a named group, not
// checkboxes in a `.framework-grid`, so selecting them means reading `pressed`
// rather than `checked`.
const compliancePanel = (page) => page.getByRole('tabpanel', { name: 'Compliance' });

const frameworkToggles = (page) =>
  page.getByRole('group', { name: 'Compliance frameworks' }).getByRole('button');

const setAllFrameworks = async (page, pressed) => {
  const toggles = frameworkToggles(page);
  for (let i = 0; i < (await toggles.count()); i++) {
    const toggle = toggles.nth(i);
    if ((await toggle.getAttribute('aria-pressed')) !== String(pressed)) {
      await toggle.click();
    }
  }
};
const selectAllFrameworks = (page) => setAllFrameworks(page, true);
const deselectAllFrameworks = (page) => setAllFrameworks(page, false);

test.describe('Compliance', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/analysis');
    await page.getByRole('tab', { name: 'Compliance' }).click();
  });

  // T-COMP-01: Tab switch shows compliance content
  test('T-COMP-01: compliance tab shows framework selection', async ({ page }) => {
    await expect(page.getByRole('group', { name: 'Compliance frameworks' })).toBeVisible();
  });

  // T-COMP-02: Every supported framework is offered
  //
  // This asserted six. There are ten, and there were ten before the redesign
  // touched this screen: `ComplianceFramework::ALL` gained ISO 27001, SOC 2,
  // NIST SP 800-171 and FedRAMP, and the test was never updated, so it was
  // wrong about the product rather than about the markup. The count is pinned
  // to catch a framework silently disappearing from the picker; it has to be
  // raised deliberately when `ComplianceFramework::ALL` grows.
  test('T-COMP-02: all ten frameworks are offered', async ({ page }) => {
    const toggles = frameworkToggles(page);
    await expect(toggles).toHaveCount(10);
    const names = (await toggles.allTextContents()).join(' ');
    for (const framework of [
      'CIS', 'DISA STIG', 'NIST 800-53', 'PCI-DSS', 'HIPAA', 'GDPR',
      'ISO/IEC 27001', 'SOC 2', 'NIST SP 800-171', 'FedRAMP',
    ]) {
      expect(names).toContain(framework);
    }
  });

  // T-COMP-03: CIS selected by default
  test('T-COMP-03: CIS is selected by default', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'CIS Benchmark' }))
      .toHaveAttribute('aria-pressed', 'true');
  });

  // T-COMP-04: Generate button visible and enabled
  test('T-COMP-04: Generate Reports button visible when frameworks selected', async ({ page }) => {
    const btn = page.getByRole('button', { name: /Generate Report/i });
    await expect(btn).toBeVisible();
    await expect(btn).toBeEnabled();
  });

  // T-COMP-05: Generating a report shows a report card
  //
  // `.report-card` is gone. A report renders as a level-3 heading naming its
  // framework, a control count, a score and the four control tallies, so the
  // heading is what identifies one.
  test('T-COMP-05: generating a report shows a report card', async ({ page }) => {
    const btn = page.getByRole('button', { name: /Generate Report/i });
    await btn.click();
    await expect(btn).not.toHaveText(/Generating/i, { timeout: 10000 });
    // CIS is selected by default, so it is the report that appears.
    await expect(page.getByRole('heading', { name: 'CIS Benchmark', level: 3 })).toBeVisible();
    await expect(compliancePanel(page).getByText(/\d+ controls assessed/)).toBeVisible();
  });

  // T-COMP-06: A report carries its score and control tallies
  //
  // This asserted a `score-(high|medium|low)` class on `.compliance-score`.
  // Both are gone: the score renders as "<n>/100" beside the counts it is
  // derived from. Asserting the numbers rather than the colour is the better
  // test regardless, since a colour alone tells an operator nothing they can
  // read, and the tallies are what the score has to agree with.
  test('T-COMP-06: a report carries its score and control tallies', async ({ page }) => {
    await page.getByRole('button', { name: /Generate Report/i }).click();
    const panel = compliancePanel(page);
    await expect(panel.getByText(/^\d+\/100$/)).toBeVisible();
    for (const tally of [/\d+ Pass/, /\d+ Fail/, /\d+ Manual review/]) {
      await expect(panel.getByText(tally)).toBeVisible();
    }
  });

  // T-COMP-07: Deselect all disables generate button
  test('T-COMP-07: deselecting all frameworks disables generate button', async ({ page }) => {
    await deselectAllFrameworks(page);
    const btn = page.getByRole('button', { name: /Generate Report/i });
    await expect(btn).toBeDisabled();
  });

  // T-COMP-08: Every selected framework produces a report
  //
  // The old assertion was `toBeGreaterThanOrEqual(1)` under a name promising
  // multiple cards, so one card satisfied it: the very thing "multiple" exists
  // to exclude. An exact count is what makes this test able to fail, and it is
  // now derivable, the mock carrying a report for all ten frameworks.
  test('T-COMP-08: selecting every framework generates a report each', async ({ page }) => {
    await selectAllFrameworks(page);
    const btn = page.getByRole('button', { name: /Generate Report/i });
    await expect(btn).toBeEnabled();
    await btn.click();
    await expect(btn).not.toHaveText(/Generating/i, { timeout: 10000 });
    await expect(compliancePanel(page).getByRole('heading', { level: 3 })).toHaveCount(10);
  });
});
