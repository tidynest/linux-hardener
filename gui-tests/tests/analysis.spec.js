// =============================================================================
// ANALYSIS TESTS - Findings (T-FIND-01..12) + Compliance (T-COMP-01..08)
// + Exceptions (T-EXC-01..05)
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

  // T-FIND-10: The Scan History tab
  //
  // This asserted a `.mini-security-score` on Analysis. The component is gone
  // from the interface entirely, not renamed: neither MiniSecurityScore nor
  // either of its classes appears anywhere in `crates/hardener-ui/src`, and
  // the page carries no score markup at all. The score lives on the Dashboard,
  // where T-DASH-04 and T-DASH-09 cover it.
  //
  // The test also never scanned, though its own comment said the component
  // appeared after a scan, so it was asserting a pending placeholder rather
  // than the thing it named.
  //
  // Repointed at the third tab, which nothing covered: Analysis has Findings,
  // Compliance and Scan History, and the first two have eighteen tests between
  // them while the third had none.
  test('T-FIND-10: the Scan History tab opens', async ({ page }) => {
    await page.getByRole('tab', { name: 'Scan History' }).click();
    await expect(page.getByRole('tab', { name: 'Scan History' }))
      .toHaveAttribute('aria-selected', 'true');
    await expect(page.getByRole('tabpanel', { name: 'Scan History' })).toBeVisible();
  });

  // T-FIND-12: The header subtitle names the last completed scan
  //
  // The Dashboard's twin is T-DASH-10, and both had the same hole: the fixture
  // claimed `status: 'completed'` while omitting `completed_at`, which is an
  // Option and so deserialised to None, and `last_scanned_label` correctly
  // reported never-scanned. This page fetches once on construction and again in
  // its scan handler, so the populated subtitle is there on load.
  test('T-FIND-12: header subtitle names the last completed scan', async ({ page }) => {
    await expect(page.locator('.header-subtitle')).toHaveText(/^Last scanned \S/);
  });

  // T-FIND-11: A declined exception is named on the finding it failed to cover
  //
  // Issue #133. The CLI has rendered this line since the three-state
  // ExceptionOutcome landed and the GUI rendered nothing, which left the
  // operator with no surface at all: someone editing the config file is at
  // least near the text they wrote, someone in the GUI is not.
  //
  // Asserted on the wording rather than the class, because the sentence is the
  // deliverable and it comes from `exception_declined_line` in hardener-types,
  // the same formatter the CLI calls. Asserting the class would pass while the
  // two surfaces said different things.
  //
  // The last two assertions are the ones that would catch the wrong fix. A
  // declined exception is live, so the finding keeps its real severity and
  // stays in its severity group; only an applied exception moves a finding
  // into Policy Exceptions and replaces its severity with the label.
  //
  // The fixture now also carries services-001 as a keyed, Applied finding
  // (added for T-EXC-04), so a 'Policy Exceptions' group is always present on
  // this fixture: asserting its absence from the whole panel no longer says
  // anything about ssh-001 in particular, since that group would exist
  // regardless of what happens to the declined finding under test. The
  // property this test proves is scoped to the group instead: the declined
  // finding is absent from the Policy Exceptions group specifically, and
  // present in its own severity group (Critical) instead.
  test('T-FIND-11: a declined exception says so in the finding detail', async ({ page }) => {
    await runScan(page);
    await page.getByRole('button', { name: /Root login via SSH enabled/ }).click();
    const detail = page.locator('.finding-detail');
    await expect(detail).toContainText(
      "exception not applied: documents 'prohibit-password', host has 'yes'",
    );
    await expect(detail).toContainText('Break-glass access from the bastion');
    // The `has:` locators below are built from `page`, not from `panel`. A
    // panel-rooted inner locator carries the tabpanel role at the head of its
    // selector chain, and that chain is matched relative to each
    // `.finding-group` candidate, which contains no tabpanel: the filter then
    // matches no group at all. That is not a theoretical hazard. Written the
    // panel-rooted way, the Critical assertion failed against a build the
    // accessibility tree showed to be correct, and the Policy Exceptions
    // assertion beside it passed vacuously, because `toHaveCount(0)` is
    // satisfied by a filter that resolves to nothing.
    const panel = page.getByRole('tabpanel', { name: 'Findings' });
    const policyExceptionsGroup = panel.locator('.finding-group', {
      has: page.getByText('Policy Exceptions', { exact: true }),
    });
    // The absence assertion below can only mean something if the group it
    // searches exists. Without this line it passes whether the group is empty,
    // missing, or never matched.
    await expect(policyExceptionsGroup).toHaveCount(1);
    await expect(
      policyExceptionsGroup.getByRole('button', { name: 'Root login via SSH enabled' }),
    ).toHaveCount(0);
    const criticalGroup = panel.locator('.finding-group', {
      has: page.getByText('Critical', { exact: true }),
    });
    await expect(
      criticalGroup.getByRole('button', { name: 'Root login via SSH enabled' }),
    ).toBeVisible();
  });

  // The row-head locators below (here and in T-FIND-11 above) match on the
  // finding title alone, deliberately without `exact: true`. The row head's
  // accessible name is not the title on its own: it concatenates the title
  // with its category tag in the same element (`.finding-row-head` in
  // findings_tab.rs renders both spans as siblings inside the button), so an
  // exact match against the bare title would fail on a correct build. A
  // reviewer has already flagged the missing `exact: true` once as an
  // oversight; it is not one.
  //
  // T-EXC-01: A keyed finding with no exception offers the accept control
  //
  // 'Bluetooth service enabled' is the mock's own finding_title (services-002)
  // carrying finding_exception_key: 'bluetooth-service' with finding_exception
  // still NotConfigured, read from gui-tests/tauri-mock.js rather than assumed.
  test('T-EXC-01: a keyed finding offers Accept This Finding', async ({ page }) => {
    await runScan(page);
    await page.getByRole('button', { name: 'Bluetooth service enabled' }).click();
    await expect(page.getByRole('button', { name: 'Accept This Finding', exact: true })).toBeVisible();
  });

  // T-EXC-02: The submit button stays disabled until a reason is typed.
  //
  // Reason is the evidence that makes this a documented deviation rather than
  // an unexplained gap, so an empty one cannot be submitted.
  test('T-EXC-02: Accept Finding is disabled without a reason', async ({ page }) => {
    await runScan(page);
    await page.getByRole('button', { name: 'Bluetooth service enabled' }).click();
    await page.getByRole('button', { name: 'Accept This Finding', exact: true }).click();
    const submit = page.getByRole('button', { name: 'Accept Finding', exact: true });
    await expect(submit).toBeDisabled();
    await page.getByLabel('Reason').fill('laptop needs it');
    await expect(submit).toBeEnabled();
  });

  // T-EXC-03: Submitting patches the row in place, with no second scan.
  //
  // Scoped to the expanded row's own `.finding-detail`, and matched exactly.
  // Unscoped and substring-matched, 'POLICY EXCEPTION' also matches the
  // 'Policy Exceptions' group heading that renders once the fixture carries
  // any Applied exception (services-001, added for T-EXC-04): Playwright's
  // default text match is a case-insensitive substring, so the locator would
  // resolve to two elements and `toBeVisible()` would throw a strict-mode
  // violation instead of proving the accepted row now carries the label and
  // the typed reason.
  test('T-EXC-03: accepting a finding shows it as a policy exception', async ({ page }) => {
    await runScan(page);
    await page.getByRole('button', { name: 'Bluetooth service enabled' }).click();
    await page.getByRole('button', { name: 'Accept This Finding', exact: true }).click();
    await page.getByLabel('Reason').fill('laptop needs it');
    await page.getByRole('button', { name: 'Accept Finding', exact: true }).click();
    const detail = page.locator('.finding-detail');
    await expect(detail.getByText('POLICY EXCEPTION', { exact: true })).toBeVisible();
    await expect(detail).toContainText('laptop needs it');
  });

  // T-EXC-04: An already-excepted finding offers removal instead.
  //
  // 'Unnecessary services running' is the mock's finding_title (services-001)
  // carrying finding_exception_key: 'unnecessary-services' with
  // finding_exception Applied, so the row starts already accepted.
  //
  // `exact: true` matters: without it a 'Remove Exception' locator also matches
  // a longer accessible name that happens to contain it.
  test('T-EXC-04: an excepted finding offers Remove Exception', async ({ page }) => {
    await runScan(page);
    await page.getByRole('button', { name: 'Unnecessary services running' }).click();
    await expect(page.getByRole('button', { name: 'Remove Exception', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Accept This Finding', exact: true })).toHaveCount(0);
  });

  // T-EXC-05: A finding with no exception key offers no control at all.
  //
  // 'Password complexity not enforced' (pam-001) carries no
  // finding_exception_key at all in the mock, which deserialises to None.
  //
  // Asserted on the count rather than on visibility: a control that is present
  // and hidden is a different defect from one that was never rendered, and only
  // the second is correct here.
  test('T-EXC-05: a keyless finding offers no exception control', async ({ page }) => {
    await runScan(page);
    await page.getByRole('button', { name: 'Password complexity not enforced' }).click();
    await expect(page.getByRole('button', { name: 'Accept This Finding', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Remove Exception', exact: true })).toHaveCount(0);
  });

  // T-FIND-13/14: a plugin that produced no result is named, not left silent.
  //
  // The fixture's inventory is 8 plugins and its scan covers 6, so audit and
  // MAC are absent. That is exactly the state the notice exists for: a domain
  // nobody scanned shows no findings, which looks the same as a clean one.
  //
  // Asserted rather than screenshotted. The theme sweep captures this view and
  // captured it happily on every run before the notice existed, so a green
  // sweep says nothing about whether it renders.
  test('T-FIND-13: names the plugins that produced no result', async ({ page }) => {
    await runScan(page);
    const notice = page.locator('.findings-not-run');
    await expect(notice).toBeVisible();
    await expect(notice).toContainText('Audit Hardening');
    await expect(notice).toContainText('MAC Hardening');
    await expect(notice).toContainText('2 of the 8');
  });

  // The green half. Before a scan every plugin is trivially absent, and saying
  // so under "No findings yet" would announce a gap where there is simply no
  // scan yet. Without this, a notice that fired unconditionally would pass the
  // test above.
  test('T-FIND-14: says nothing about missing plugins before a scan', async ({ page }) => {
    await expect(page.getByText('No findings yet')).toBeVisible();
    await expect(page.locator('.findings-not-run')).toHaveCount(0);
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

  // T-FIND-13: A config-skipped plugin is named with its remedy, apart from
  // absences the payload does not explain
  //
  // The `?skip_marker=1` fixture swaps PAM's scanned entry for the marker a
  // config-disabled plugin arrives as. The skipped notice must name PAM with
  // the config-edit remedy, and the unexplained notice - which this fixture
  // still raises for Audit and MAC, absent from every variant - must not
  // claim PAM, whose absence the marker explains. Before the skip channel,
  // both groups collapsed into one notice that named config as the
  // commonest cause of everything.
  test('T-FIND-13: a skip marker is reported as skipped by config, not unexplained', async ({ page }) => {
    await loadApp(page, '/analysis', 'skip_marker=1');
    await runScan(page);

    const skipped = page.locator('.findings-not-run', { hasText: 'skipped by configuration' });
    await expect(skipped).toContainText('PAM Hardening');
    await expect(skipped).toContainText('enabled_plugins');

    const unexplained = page.locator('.findings-not-run', { hasText: 'produced no result' });
    await expect(unexplained).toContainText('Audit Hardening');
    await expect(unexplained).not.toContainText('PAM');
  });
