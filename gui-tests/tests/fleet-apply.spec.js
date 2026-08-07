// =============================================================================
// FLEET APPLY TESTS (T-FAPPLY-01..09) - Linux Hardener GUI Tests
// =============================================================================
// Mutating fleet page. Execute is gated behind a mandatory dry-run for the EXACT
// current selection plus a confirm modal; any selection change re-arms the gate.

const { test, expect } = require('@playwright/test');
const { loadApp } = require('./helpers');

// Hosts are checkboxes named "<host> (<address>)" inside a group of their own,
// which is what separates them from the plugin selector; `.fleet-host-select`
// and `.fleet-host-option` are both gone. The preview control is labelled
// "Preview Changes" rather than "Dry-run".
const host = (page, name) =>
  page.getByRole('group', { name: 'Hosts', exact: true })
    .getByRole('checkbox', { name: new RegExp(`^${name} `) });

const dryRunBtn = (page) => page.getByRole('button', { name: /Preview Changes/i });
const executeBtn = (page) => page.getByRole('button', { name: /^Execute/ });

// A completed preview is what puts Execute on the page, so its appearance is
// the signal to wait on. `.fleet-preview` no longer exists.
async function dryRun(page) {
  await dryRunBtn(page).click();
  await expect(executeBtn(page)).toBeVisible();
}

test.describe('Fleet Apply', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/fleet-apply');
  });

  // T-FAPPLY-01: Page loads with mode radios
  test('T-FAPPLY-01: page loads with Apply/Roll back modes', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Fleet Apply' })).toBeVisible();
    const action = page.getByRole('radiogroup', { name: 'Action' });
    await expect(action.getByRole('radio', { name: 'Apply', exact: true })).toBeChecked();
    await expect(action.getByRole('radio', { name: 'Roll back' })).toBeVisible();
  });

  // T-FAPPLY-02: Nothing can run before a host is chosen
  //
  // Execute is not rendered at all until a preview exists, so it is asserted
  // absent rather than disabled: `toBeDisabled` on an element that is not
  // there fails for the wrong reason.
  test('T-FAPPLY-02: nothing can run with no selection', async ({ page }) => {
    await expect(dryRunBtn(page)).toBeDisabled();
    await expect(page.getByText('Select at least one host to preview.')).toBeVisible();
    await expect(executeBtn(page)).toHaveCount(0);
  });

  // T-FAPPLY-03: Dry-run enables once a host is picked and shows a preview
  test('T-FAPPLY-03: selecting a host enables Dry-run and shows preview', async ({ page }) => {
    await host(page, 'web-01').check();
    await expect(dryRunBtn(page)).toBeEnabled();
    await dryRun(page);
    await expect(page.getByText(/would change/)).toBeVisible();
  });

  // T-FAPPLY-04: Execute unlocks only AFTER a matching dry-run
  test('T-FAPPLY-04: Execute stays disabled until a dry-run runs', async ({ page }) => {
    // Execute is not rendered until a preview exists, so the gate before one
    // is its absence rather than a disabled state.
    await host(page, 'web-01').check();
    await expect(executeBtn(page)).toHaveCount(0);
    await dryRun(page);
    await expect(executeBtn(page)).toBeEnabled();
  });

  // T-FAPPLY-05: THE GATE - changing the selection after a dry-run re-disables Execute
  test('T-FAPPLY-05: changing selection re-arms the dry-run gate', async ({ page }) => {
    await host(page, 'web-01').check();
    await dryRun(page);
    await expect(executeBtn(page)).toBeEnabled();
    // Add a second host -> selection no longer matches the previewed one, and
    // Execute goes away until it is previewed again.
    await host(page, 'db-01').check();
    await expect(executeBtn(page)).toHaveCount(0);
  });

  // T-FAPPLY-06: Execute opens a confirm modal naming the host count
  test('T-FAPPLY-06: Execute opens the confirm modal', async ({ page }) => {
    await host(page, 'web-01').check();
    await dryRun(page);
    await executeBtn(page).click();
    await expect(page.locator('.modal')).toBeVisible();
    await expect(page.locator('#fleet-apply-modal-title')).toContainText('Execute apply on 1 host(s)?');
  });

  // T-FAPPLY-07: Cancelling the modal performs no mutation
  test('T-FAPPLY-07: modal Cancel closes without applying', async ({ page }) => {
    await host(page, 'web-01').check();
    await dryRun(page);
    await executeBtn(page).click();
    await page.locator('.modal').getByRole('button', { name: 'Cancel' }).click();
    await expect(page.locator('.modal')).toHaveCount(0);
    await expect(page.locator('.fleet-results')).toHaveCount(0);
  });

  // T-FAPPLY-08: Confirming executes and renders results
  test('T-FAPPLY-08: confirming the modal applies and shows results', async ({ page }) => {
    await host(page, 'web-01').check();
    await dryRun(page);
    await executeBtn(page).click();
    await page.getByRole('button', { name: /Yes, execute/i }).click();
    await expect(page.locator('.fleet-results')).toBeVisible();
    await expect(page.locator('.fleet-results')).toContainText('web-01');
  });

  // T-FAPPLY-09: Roll back mode also previews via dry-run
  test('T-FAPPLY-09: roll back mode previews via dry-run', async ({ page }) => {
    await page.getByRole('radio', { name: 'Roll back' }).check();
    await host(page, 'web-01').check();
    await dryRun(page);
    await expect(page.getByText(/would change/)).toBeVisible();
  });
});
