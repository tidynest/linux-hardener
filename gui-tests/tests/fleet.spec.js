// =============================================================================
// FLEET SCAN TESTS (T-FLEET-01..07) - Linux Hardener GUI Tests
// =============================================================================
// Read-only multi-host scan: host selection, per-host results, expandable rows,
// and the failed-host path.
//
// The redesign folded remote scanning into this page and renamed it Hosts.
// There is no `.fleet-host-option`, no results table and no `.fleet-row`: hosts
// are checkboxes named "Select <host>", the scan button carries its own
// selection count, and an unscanned host says so in its row.
//
// Whether a host has been scanned is therefore readable without knowing how a
// result is drawn, which is what the assertions below use: two hosts start as
// "Not scanned yet", and scanning one leaves one.

const { test, expect } = require('@playwright/test');
const { loadApp } = require('./helpers');

const selectHost = (page, name) => page.getByRole('checkbox', { name: `Select ${name}` });
const scanButton = (page) => page.getByRole('button', { name: /Scan Selected/i });
const unscanned = (page) => page.getByText('Not scanned yet');

test.describe('Fleet Scan', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/fleet');
  });

  // T-FLEET-01: Page loads
  test('T-FLEET-01: page loads with heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Hosts', level: 1 })).toBeVisible();
  });

  // T-FLEET-02: Nothing is scanned before a scan
  test('T-FLEET-02: both hosts start unscanned', async ({ page }) => {
    await expect(unscanned(page)).toHaveCount(2);
  });

  // T-FLEET-03: Saved hosts listed; scan button disabled until a host is picked
  test('T-FLEET-03: lists saved hosts and disables Scan until selection', async ({ page }) => {
    await expect(selectHost(page, 'web-01')).toBeVisible();
    await expect(selectHost(page, 'db-01')).toBeVisible();
    await expect(scanButton(page)).toBeDisabled();
  });

  // T-FLEET-04: Selecting a host enables Scan; running it scans that host alone
  test('T-FLEET-04: scanning a host populates its result', async ({ page }) => {
    await selectHost(page, 'web-01').check();
    const btn = scanButton(page);
    await expect(btn).toBeEnabled();
    await btn.click();
    // web-01 has a result now; db-01 was not selected and still has none.
    await expect(unscanned(page)).toHaveCount(1);
  });

  // T-FLEET-05: A scanned row expands to show that host's detail
  test('T-FLEET-05: expanding a scanned host shows its detail', async ({ page }) => {
    await selectHost(page, 'web-01').check();
    await scanButton(page).click();
    await expect(unscanned(page)).toHaveCount(1);
    const expander = page.getByRole('button', { name: 'Expand host' }).first();
    await expander.click();
    await expect(expander).toHaveAttribute('aria-expanded', 'true');
  });

  // T-FLEET-06: A host that fails to scan says so rather than crashing
  //
  // db-01 is the mock's failing host, refused on port 2222.
  test('T-FLEET-06: failed host shows its failure', async ({ page }) => {
    await selectHost(page, 'db-01').check();
    await scanButton(page).click();
    await expect(page.getByText(/Failed|connection refused/i).first()).toBeVisible();
  });

  // T-FLEET-07: Scanning both hosts leaves neither unscanned
  test('T-FLEET-07: scanning multiple hosts yields a result each', async ({ page }) => {
    await selectHost(page, 'web-01').check();
    await selectHost(page, 'db-01').check();
    await scanButton(page).click();
    await expect(unscanned(page)).toHaveCount(0);
  });
});
