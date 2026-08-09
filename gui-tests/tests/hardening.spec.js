// =============================================================================
// HARDENING TESTS - Configure (T-CONF-01..10) + History (T-HIST-01..06)
// =============================================================================

const { test, expect } = require('@playwright/test');
const { loadApp, runScan } = require('./helpers');

// ---------------------------------------------------------------------------
// CONFIGURE SECTION
// ---------------------------------------------------------------------------

// The protection levels are a named radiogroup and the plugins a named group of
// checkboxes, so both are reached by role rather than by `input[value=...]` and
// `.plugin-grid`, neither of which survived the redesign.
const level = (page, name) =>
  page.getByRole('radiogroup', { name: 'Protection level' })
    .getByRole('radio', { name, exact: true });

const plugins = (page) => page.getByRole('group', { name: 'Plugin areas' });
const pluginBoxes = (page) => plugins(page).getByRole('checkbox');

const checkedPluginCount = async (page) => {
  const boxes = pluginBoxes(page);
  const states = await Promise.all(
    Array.from({ length: await boxes.count() }, (_, i) => boxes.nth(i).isChecked()),
  );
  return states.filter(Boolean).length;
};

test.describe('Configure', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/hardening');
  });

  // T-CONF-01: Page loads with heading
  test('T-CONF-01: page loads with System Hardening heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'System Hardening' })).toBeVisible();
  });

  // T-CONF-02: The protection levels on offer
  //
  // There are four, not three: the redesign added Custom, which is what a
  // manual plugin change now selects. Reached through the radiogroup rather
  // than `input[value=...]`, so the test reads what an operator is offered.
  test('T-CONF-02: four protection levels are offered', async ({ page }) => {
    const levels = page.getByRole('radiogroup', { name: 'Protection level' });
    await expect(levels.getByRole('radio')).toHaveCount(4);
    for (const level of ['Baseline', 'Secure', 'High', 'Custom']) {
      await expect(levels.getByRole('radio', { name: level, exact: true })).toBeVisible();
    }
  });

  // T-CONF-03: Eight plugin areas present
  test('T-CONF-03: eight plugin areas with correct names', async ({ page }) => {
    await expect(pluginBoxes(page)).toHaveCount(8);
    for (const name of [
      'Kernel Hardening', 'SSH Hardening', 'Firewall', 'PAM Authentication',
      'Service Minimisation', 'Audit Rules', 'File Permissions', 'MAC System',
    ]) {
      await expect(plugins(page).getByRole('checkbox', { name, exact: true })).toBeVisible();
    }
  });

  // T-CONF-04: Secure profile (default) - 5 plugins on, 3 off
  test('T-CONF-04: Secure profile enables kernel, ssh, firewall, pam, services', async ({ page }) => {
    await expect(level(page, 'Secure')).toBeChecked();
    expect(await checkedPluginCount(page)).toBe(5);
  });

  // T-CONF-05: Baseline profile - only ssh and firewall
  test('T-CONF-05: Baseline profile enables only ssh and firewall', async ({ page }) => {
    await level(page, 'Baseline').check();
    expect(await checkedPluginCount(page)).toBe(2);
  });

  // T-CONF-06: High profile - all 8 on
  test('T-CONF-06: High profile enables all 8 plugins', async ({ page }) => {
    await level(page, 'High').check();
    expect(await checkedPluginCount(page)).toBe(8);
  });

  // T-CONF-07: A manual change moves the profile to Custom
  //
  // The old name said "deselects profile radios", and its comment admitted it
  // did not know whether the radio cleared, so it asserted only that the count
  // went from 5 to 6. That holds equally if the profile silently stayed on
  // Secure while no longer describing the selection, which is the thing worth
  // catching. Custom exists to represent this state, so it is what is checked.
  test('T-CONF-07: manually toggling a plugin selects Custom', async ({ page }) => {
    await expect(level(page, 'Secure')).toBeChecked();
    await plugins(page).getByRole('checkbox', { name: 'Audit Rules', exact: true }).check();
    expect(await checkedPluginCount(page)).toBe(6);
    await expect(level(page, 'Custom')).toBeChecked();
  });

  // T-CONF-08: Preview button visible and enabled
  test('T-CONF-08: Preview Changes button is visible', async ({ page }) => {
    const btn = page.getByRole('button', { name: /Preview Changes/i });
    await expect(btn).toBeVisible();
    await expect(btn).toBeEnabled();
  });

  // T-CONF-09: Click Preview shows the estimated changes
  //
  // The preview replaces the configure panel rather than opening a
  // `.preview-panel` beside it: a per-plugin breakdown of change counts, a
  // confirmation to tick, and an Apply naming the total. Apply being disabled
  // until the box is ticked is the safety property worth pinning here, since a
  // preview that could apply without acknowledgement is the failure that
  // matters.
  test('T-CONF-09: clicking Preview shows the estimated changes', async ({ page }) => {
    await page.getByRole('button', { name: /Preview Changes/i }).click();
    const apply = page.getByRole('button', { name: /Apply \d+ Changes/ });
    await expect(apply).toBeVisible({ timeout: 10000 });
    await expect(apply).toBeDisabled();
    await expect(page.getByText(/\d+ changes/).first()).toBeVisible();
  });

  // T-CONF-10: Cancel returns to the configure panel
  test('T-CONF-10: Cancel returns to the configure panel', async ({ page }) => {
    await page.getByRole('button', { name: /Preview Changes/i }).click();
    await expect(page.getByRole('button', { name: /Apply \d+ Changes/ }))
      .toBeVisible({ timeout: 10000 });
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    await expect(page.getByRole('radiogroup', { name: 'Protection level' })).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// HISTORY SECTION
// ---------------------------------------------------------------------------

const rollbackButtons = (page) => page.getByRole('button', { name: 'Roll back' });

test.describe('History', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/hardening');
    // Switch to History tab (TabBar uses role="tab")
    await page.getByRole('tab', { name: 'History' }).click();
  });

  // T-HIST-01: History section visible
  test('T-HIST-01: History section is visible after tab switch', async ({ page }) => {
    await expect(page.locator('.history-section')).toBeVisible();
  });

  // T-HIST-02: The checkpoints, grouped by the day they were taken
  //
  // There is no checkpoints table. The redesign groups checkpoints under a
  // date, each carrying its name, time, the user who took it, and its three
  // actions, so the ID/Name/Created/Actions columns this asserted are gone
  // along with the table that held them.
  test('T-HIST-02: the three checkpoints are listed with their detail', async ({ page }) => {
    await expect(rollbackButtons(page)).toHaveCount(3);
    await expect(page.getByText('Pre-hardening checkpoint')).toBeVisible();
    await expect(page.getByText('Latest')).toBeVisible();
  });

  // T-HIST-03: Rollback button present per checkpoint
  test('T-HIST-03: rollback button present per checkpoint', async ({ page }) => {
    await expect(rollbackButtons(page)).toHaveCount(3);
  });

  // T-HIST-04: Refresh button triggers checkpoint reload
  test('T-HIST-04: refresh button triggers checkpoint reload', async ({ page }) => {
    const btn = page.getByRole('button', { name: /Refresh/i });
    await expect(btn).toBeVisible();
    await btn.click();
    await expect(rollbackButtons(page)).toHaveCount(3);
  });

  // T-HIST-05: Creating a checkpoint needs a name
  //
  // This asserted an "No apply operations yet" empty state in an apply-results
  // summary. That section is not in History any more: the panel shows
  // checkpoints and nothing else. Rather than drop the slot, it covers the one
  // ungated control the panel does have, whose disabled state is the only
  // thing stopping a nameless checkpoint being created.
  test('T-HIST-05: Create Checkpoint is disabled until the name is given', async ({ page }) => {
    const create = page.getByRole('button', { name: 'Create Checkpoint' });
    await expect(create).toBeDisabled();
    await page.getByRole('textbox', { name: 'Checkpoint name...' }).fill('Before the change');
    await expect(create).toBeEnabled();
  });

  // T-HIST-06: An apply cannot proceed without acknowledgement
  //
  // The flow changed shape. There is no "Confirm & Apply": a preview is
  // acknowledged by ticking "I understand this can affect how I log in...",
  // and only then does "Apply N Changes" become usable. The old test waited on
  // a `.preview-panel` that no longer exists and so never reached an apply at
  // all, which is why no artefact in this repository shows what a completed
  // apply looks like.
  //
  // What is asserted is the gate, which is the part worth protecting and which
  // can be checked from here. The result the apply produces is deliberately
  // not asserted: nothing has ever observed it, and a guess would be the kind
  // of assertion that passes without covering anything.
  test('T-HIST-06: apply is gated on acknowledging the warning', async ({ page }) => {
    await page.getByRole('tab', { name: 'Configure' }).click();
    await page.getByRole('button', { name: /Preview Changes/i }).click();

    const apply = page.getByRole('button', { name: /Apply \d+ Changes/ });
    await expect(apply).toBeVisible({ timeout: 10000 });
    await expect(apply).toBeDisabled();

    await page.getByText(/I understand this can affect/).click();
    await expect(apply).toBeEnabled();
  });
});

// ---------------------------------------------------------------------------
// APPLY RESULTS (T-APPLY-01..04)
// ---------------------------------------------------------------------------

// Issue #136. Until these, nothing in this repository had ever observed what a
// completed apply produces: T-HIST-06 asserts the gate and stops at it.
//
// The reason that was safe to leave, and the reason it stopped being safe, is
// the fixture. The default APPLY_RESULTS is three changes, all successful, so
// `applied_change_count()` and `apply_changes.len()` are both 3 and any
// assertion on the count passes under either implementation. `?apply_mode=mixed`
// selects a fixture where they differ: seven entries, three genuinely applied.
// That divergence is what makes the assertions below capable of failing.
//
// Why this matters more than the usual test: the renderers have a standing rule
// to use `applied_change_count()` and `is_skipped()` rather than
// `apply_changes.len()`. Breaking it does not crash, does not empty a view and
// does not fail any other test. It reports more success than occurred, which is
// the worst available failure for a hardening tool.

// Runs an apply to completion and returns once a result panel is on screen.
// The preview, the acknowledgement and the apply are one sequence because no
// test wants any prefix of it.
async function runApply(page) {
  await page.getByRole('tab', { name: 'Configure' }).click();
  await page.getByRole('button', { name: /Preview Changes/i }).click();
  const apply = page.getByRole('button', { name: /Apply \d+ Changes/ });
  await expect(apply).toBeVisible({ timeout: 10000 });
  await page.getByText(/I understand this can affect/).click();
  await apply.click();
}

test.describe('Apply results', () => {
  // T-APPLY-01: The success path renders the done panel and its own totals
  //
  // The default fixture applies 2 kernel settings and 1 SSH setting, so the
  // count is the sum across areas and the area count excludes any area that
  // changed nothing.
  test('T-APPLY-01: a fully successful apply reports its settings and areas', async ({ page }) => {
    await loadApp(page, '/hardening');
    await runApply(page);

    const done = page.locator('.done-panel');
    await expect(done).toBeVisible({ timeout: 15000 });
    await expect(done.locator('.done-summary-line'))
      .toHaveText('3 settings applied across 2 areas');
    await expect(page.locator('.partial-panel')).toHaveCount(0);
  });

  // T-APPLY-02: The count is of settings applied, not of entries returned
  //
  // This is the assertion the issue was filed for. The mixed fixture returns
  // seven entries: three genuinely applied, two failed, one skipped no-op and
  // one checkpoint. A renderer counting `apply_changes.len()` reports 7; one
  // following the rule reports 3. The denominator is 5, being what was meant
  // to change, which deliberately excludes the skip and the checkpoint rather
  // than inflating the total with work nobody asked for.
  test('T-APPLY-02: the mixed apply counts settings applied, not entries returned', async ({ page }) => {
    await loadApp(page, '/hardening', 'apply_mode=mixed');
    await runApply(page);

    const partial = page.locator('.partial-panel');
    await expect(partial).toBeVisible({ timeout: 15000 });
    await expect(partial.locator('.partial-heading-text'))
      .toHaveText('3 of 5 settings applied. Firewall failed, PAM needs a manual step.');
    await expect(partial.locator('.partial-heading-text')).not.toContainText('7');
  });

  // T-APPLY-03: Each area reports its own outcome, and the four differ
  //
  // The classifier's precedence is the part worth pinning. Firewall applied one
  // rule and failed another, and must read as failed rather than applied: an
  // area that did some real work and still failed is a failure. PAM's error is
  // the sole entry in MANUAL_ACTION_MARKERS, so it is a manual step rather than
  // a failure, and a genuine failure would have dominated it had both been
  // present. MAC did nothing applicable, which is not a failure and must not
  // read as one.
  test('T-APPLY-03: each area reports its own outcome', async ({ page }) => {
    await loadApp(page, '/hardening', 'apply_mode=mixed');
    await runApply(page);

    const rows = page.locator('.partial-panel .partial-row');
    await expect(rows).toHaveCount(4);

    await expect(rows.filter({ hasText: 'Kernel Hardening' })).toContainText('2 applied');

    // Applied one rule, failed another. The badge must be the failure, and the
    // row must not claim the success it did have.
    const firewall = rows.filter({ hasText: 'Firewall' });
    await expect(firewall.locator('.partial-row-badge')).toHaveText('Failed');
    await expect(firewall).not.toContainText('applied');
    await expect(firewall.getByRole('button', { name: 'Retry' })).toBeVisible();

    await expect(rows.filter({ hasText: 'PAM Authentication' }).locator('.partial-row-badge'))
      .toHaveText('Manual step');

    await expect(rows.filter({ hasText: 'MAC System' }))
      .toContainText('Skipped: No MAC system present');
  });

  // T-APPLY-04: A skipped area is never counted as hardened
  //
  // The narrow case behind the wide one. MAC returned a single Skipped entry
  // and the kernel's checkpoint entry is bookkeeping; neither is a setting
  // applied. If either were ever counted, the header's first number would rise
  // and this assertion is what notices.
  test('T-APPLY-04: skipped and checkpoint entries are not counted as applied', async ({ page }) => {
    await loadApp(page, '/hardening', 'apply_mode=mixed');
    await runApply(page);

    const heading = page.locator('.partial-panel .partial-heading-text');
    await expect(heading).toBeVisible({ timeout: 15000 });
    await expect(heading).toContainText('3 of 5');
    // 4 would mean the skip was counted, 5 the checkpoint as well.
    await expect(heading).not.toContainText('4 of');
    await expect(heading).not.toContainText('5 of 5');
  });
});

// ---------------------------------------------------------------------------
// ROLLBACK MODAL: THE DIVERGENCE SECTION (#143)
// ---------------------------------------------------------------------------
//
// This section shipped on reading alone. No test rendered it and the mock
// carried no divergence rows, so it had never been drawn with data at any
// width. The fixture is the part that decides whether any of this is testable,
// and it now carries the real shapes: a sysctl key and an absolute path, both
// unbreakable, beside sentences of the length the kernel probe actually emits.

test.describe('Rollback modal divergences', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/hardening');
    await page.getByRole('tab', { name: 'History' }).click();
    await page.getByRole('button', { name: 'Roll back', exact: true }).first().click();
    // The modal's own confirm button, reached by its class rather than its
    // name: the name carries a file count, and "Roll back" as a substring also
    // matches every button in the history list behind the modal.
    await page.locator('.modal-actions button.btn-danger').click();
    await expect(page.getByText('Still diverged:')).toBeVisible({ timeout: 15000 });
  });

  test('T-DIVG-01: both divergence states render, labelled apart', async ({ page }) => {
    const rows = page.locator('.rollback-divergence');
    await expect(rows).toHaveCount(2);
    // The two states ask an operator to do different things, so a render that
    // showed them identically would be a defect even with both rows present.
    await expect(rows.nth(0)).toContainText('diverged');
    await expect(rows.nth(1)).toContainText('could not check');
    await expect(rows.nth(0)).toContainText('net.ipv4.conf.all.accept_source_route');
    await expect(rows.nth(1)).toContainText('/usr/lib/sysctl.d/50-default.conf');
  });

  test('T-DIVG-02: the sentence is shown in full, not clipped away', async ({ page }) => {
    // A row that hid its detail would pass an overflow check trivially, so the
    // text is asserted present before the geometry below is asked about.
    await expect(page.locator('.rollback-divergence').first()).toContainText(
      'the rollback restored files and reloaded them without changing /proc/sys',
    );
  });

  // The defect the issue predicted, asked as geometry rather than as
  // appearance. A flex item's `min-width: auto` floors it at min-content, and
  // an unbreakable 38-character key has a min-content width no container can
  // be narrower than: the row overflows instead of wrapping.
  for (const [label, width] of [['wide', 1280], ['narrow', 420]]) {
    test(`T-DIVG-03-${label}: no row overflows the list at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      // Awaited so the assertion below reads a settled layout rather than one
      // mid-resize.
      await expect(page.locator('.rollback-divergence').first()).toBeVisible();

      const overflow = await page.evaluate(() => {
        const rows = Array.from(document.querySelectorAll('.rollback-divergence'));
        const list = rows[0].closest('.rollback-file-list');
        return rows.map((r) => r.scrollWidth - list.clientWidth);
      });

      // Measured against the list that clips them rather than against the row
      // itself: a row is as wide as its content, and comparing a thing to
      // itself is the check that cannot fail.
      for (const o of overflow) {
        expect(o).toBeLessThanOrEqual(1);
      }
    });
  }
});
