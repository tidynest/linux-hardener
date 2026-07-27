// =============================================================================
// REMOTE SCANNING TESTS (T-REMOTE-01..07) - Linux System Hardener GUI Tests
// =============================================================================
// Host inventory list, connect/disconnect lifecycle, remote scan, add-host form,
// and two-step delete.

const { test, expect } = require('@playwright/test');
const { loadApp } = require('./helpers');

const entry = (page, name) => page.locator('.host-entry').filter({ hasText: name });

test.describe('Remote Scanning', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/remote');
  });

  // T-REMOTE-01: Page loads with the saved-host inventory
  test('T-REMOTE-01: page loads listing saved hosts', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Remote Scanning' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Saved Hosts' })).toBeVisible();
    await expect(entry(page, 'web-01')).toBeVisible();
    await expect(entry(page, 'db-01')).toBeVisible();
  });

  // T-REMOTE-02: With no connection, the status panel shows the guide
  test('T-REMOTE-02: shows the not-connected guide', async ({ page }) => {
    await expect(page.locator('.remote-empty')).toBeVisible();
    await expect(page.getByText(/Add a remote host using the sidebar/i)).toBeVisible();
  });

  // T-REMOTE-03: Connecting marks the host active and reveals connected actions
  test('T-REMOTE-03: connecting a host shows connected state', async ({ page }) => {
    await entry(page, 'web-01').getByRole('button', { name: 'Connect' }).click();
    await expect(page.getByRole('button', { name: 'Disconnect' })).toBeVisible();
    await expect(entry(page, 'web-01')).toContainText('Connected');
  });

  // T-REMOTE-04: A connected host can run a scan, populating results
  test('T-REMOTE-04: running a remote scan populates results', async ({ page }) => {
    await entry(page, 'web-01').getByRole('button', { name: 'Connect' }).click();
    await page.getByRole('button', { name: /Run Scan/i }).click();
    await expect(page.locator('.remote-results')).toBeVisible();
  });

  // T-REMOTE-05: Disconnecting returns to the guide
  test('T-REMOTE-05: disconnecting returns to the guide', async ({ page }) => {
    await entry(page, 'web-01').getByRole('button', { name: 'Connect' }).click();
    await page.getByRole('button', { name: 'Disconnect' }).click();
    await expect(page.locator('.remote-empty')).toBeVisible();
  });

  // T-REMOTE-06: "Add Host" swaps the sidebar to the host form
  test('T-REMOTE-06: Add Host opens the host form', async ({ page }) => {
    await page.getByRole('button', { name: 'Add Host' }).click();
    await expect(page.getByRole('textbox').first()).toBeVisible();
  });

  // T-REMOTE-07: Two-step delete removes a host from the inventory
  test('T-REMOTE-07: deleting a host removes it', async ({ page }) => {
    await entry(page, 'db-01').getByRole('button', { name: 'Delete' }).click();
    await entry(page, 'db-01').getByRole('button', { name: 'Confirm' }).click();
    await expect(entry(page, 'db-01')).toHaveCount(0);
  });
});
