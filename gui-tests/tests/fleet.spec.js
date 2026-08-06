// =============================================================================
// FLEET SCAN TESTS (T-FLEET-01..07) - Linux Hardener GUI Tests
// =============================================================================
// Read-only multi-host scan: host selection, results table with compliance-score
// column, expandable per-host rows, and the failed-host path.

const { test, expect } = require('@playwright/test');
const { loadApp } = require('./helpers');

// Select a saved-host checkbox by its visible "name (hostname)" label.
function hostOption(page, name) {
  return page.locator('.fleet-host-option').filter({ hasText: name });
}

test.describe('Fleet Scan', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/fleet');
  });

  // T-FLEET-01: Page loads
  test('T-FLEET-01: page loads with heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Fleet Scan' })).toBeVisible();
  });

  // T-FLEET-02: Empty results state before any scan
  test('T-FLEET-02: shows empty fleet-table state before scanning', async ({ page }) => {
    await expect(page.getByText('No fleet scan yet')).toBeVisible();
  });

  // T-FLEET-03: Saved hosts listed; scan button disabled until a host is picked
  test('T-FLEET-03: lists saved hosts and disables Scan until selection', async ({ page }) => {
    await expect(hostOption(page, 'web-01')).toBeVisible();
    await expect(hostOption(page, 'db-01')).toBeVisible();
    await expect(page.getByRole('button', { name: /Scan selected/i })).toBeDisabled();
  });

  // T-FLEET-04: Selecting a host enables Scan; running populates the table + CIS % column
  test('T-FLEET-04: scanning a host populates the results table', async ({ page }) => {
    await hostOption(page, 'web-01').locator('input[type=checkbox]').check();
    const btn = page.getByRole('button', { name: /Scan selected/i });
    await expect(btn).toBeEnabled();
    await btn.click();
    await expect(page.getByRole('columnheader', { name: 'CIS %' })).toBeVisible();
    const row = page.locator('.fleet-row').first();
    await expect(row).toBeVisible();
    await expect(row).toContainText('web-01');
    await expect(row).toContainText('OK');
  });

  // T-FLEET-05: A successful row expands to show that host's findings
  test('T-FLEET-05: clicking a host row expands its detail', async ({ page }) => {
    await hostOption(page, 'web-01').locator('input[type=checkbox]').check();
    await page.getByRole('button', { name: /Scan selected/i }).click();
    const row = page.locator('.fleet-row').first();
    await expect(row).toBeVisible();
    await row.click();
    await expect(page.locator('.fleet-detail-row')).toBeVisible();
  });

  // T-FLEET-06: A host that fails to scan shows a Failed status, not a crash
  test('T-FLEET-06: failed host shows Failed status', async ({ page }) => {
    await hostOption(page, 'db-01').locator('input[type=checkbox]').check();
    await page.getByRole('button', { name: /Scan selected/i }).click();
    const row = page.locator('.fleet-row').first();
    await expect(row).toBeVisible();
    await expect(row).toContainText(/Failed/i);
  });

  // T-FLEET-07: Scanning two hosts yields two rows (one OK, one Failed)
  test('T-FLEET-07: scanning multiple hosts yields a row each', async ({ page }) => {
    await hostOption(page, 'web-01').locator('input[type=checkbox]').check();
    await hostOption(page, 'db-01').locator('input[type=checkbox]').check();
    await page.getByRole('button', { name: /Scan selected/i }).click();
    await expect(page.locator('.fleet-row')).toHaveCount(2);
  });
});
