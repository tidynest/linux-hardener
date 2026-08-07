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

  // T-HIST-02: Checkpoints table with rows
  test('T-HIST-02: checkpoints table shows 3 rows with correct columns', async ({ page }) => {
    // Wait for checkpoint data to load
    await page.waitForSelector('.checkpoints-section table', { timeout: 10000 });
    const headers = page.locator('.checkpoints-section table th');
    const texts = await headers.allTextContents();
    expect(texts).toContain('ID');
    expect(texts).toContain('Name');
    expect(texts).toContain('Created');
    expect(texts).toContain('Actions');
    // 3 mock checkpoints
    const rows = page.locator('.checkpoints-section table tbody tr');
    await expect(rows).toHaveCount(3);
  });

  // T-HIST-03: Rollback button present per checkpoint
  test('T-HIST-03: rollback button present per checkpoint', async ({ page }) => {
    await page.waitForSelector('.rollback-button', { timeout: 10000 });
    const buttons = page.locator('.rollback-button');
    await expect(buttons).toHaveCount(3);
  });

  // T-HIST-04: Refresh button triggers checkpoint reload
  test('T-HIST-04: refresh button triggers checkpoint reload', async ({ page }) => {
    const btn = page.getByRole('button', { name: /Refresh/i });
    await expect(btn).toBeVisible();
    await btn.click();
    // Button should show refreshing state briefly
    // Then return to normal - verify table still has data
    await page.waitForSelector('.checkpoints-section table tbody tr', { timeout: 10000 });
    const rows = page.locator('.checkpoints-section table tbody tr');
    const count = await rows.count();
    expect(count).toBe(3);
  });

  // T-HIST-05: Initial apply shows empty state
  test('T-HIST-05: apply results shows "No apply operations yet"', async ({ page }) => {
    const emptyTitle = page.locator('.apply-results-summary .empty-state-title');
    await expect(emptyTitle).toContainText('No apply operations yet');
  });

  // T-HIST-06: After apply, shows success status
  test('T-HIST-06: after apply, shows success with change count', async ({ page }) => {
    // Switch back to Configure, trigger apply
    await page.getByRole('tab', { name: 'Configure' }).click();
    await page.getByRole('button', { name: /Preview Changes/i }).click();
    await expect(page.locator('.preview-panel')).toBeVisible({ timeout: 10000 });
    await page.getByRole('button', { name: /Confirm & Apply/i }).click();
    // Wait for apply to complete, switch to History
    await page.waitForTimeout(2000);
    await page.getByRole('tab', { name: 'History' }).click();
    // Verify apply result displayed
    const summary = page.locator('.result-summary-card');
    await expect(summary).toBeVisible({ timeout: 10000 });
    await expect(summary).toContainText(/Success|changes/i);
  });
});
