// =============================================================================
// FLEET APPLY TESTS (T-FAPPLY-01..09) - Linux System Hardener GUI Tests
// =============================================================================
// Mutating fleet page. Execute is gated behind a mandatory dry-run for the EXACT
// current selection plus a confirm modal; any selection change re-arms the gate.

const { test, expect } = require('@playwright/test');
const { loadApp } = require('./helpers');

// Host checkboxes live in .fleet-host-select; the plugin selector reuses the
// same .fleet-host-option class, so scope host lookups to the host fieldset.
function host(page, name) {
  return page.locator('.fleet-host-select .fleet-host-option').filter({ hasText: name });
}
const dryRunBtn = (page) => page.getByRole('button', { name: /Dry-run/i });
const executeBtn = (page) => page.getByRole('button', { name: /^Execute/ });

async function dryRun(page) {
  await dryRunBtn(page).click();
  await expect(page.locator('.fleet-preview').first()).toBeVisible();
}

test.describe('Fleet Apply', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/fleet-apply');
  });

  // T-FAPPLY-01: Page loads with mode radios
  test('T-FAPPLY-01: page loads with Apply/Roll back modes', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Fleet Apply' })).toBeVisible();
    await expect(page.getByRole('radio', { name: 'Apply' })).toBeVisible();
    await expect(page.getByRole('radio', { name: 'Roll back' })).toBeVisible();
  });

  // T-FAPPLY-02: Both actions gated before a selection / dry-run
  test('T-FAPPLY-02: Dry-run and Execute disabled with no selection', async ({ page }) => {
    await expect(dryRunBtn(page)).toBeDisabled();
    await expect(executeBtn(page)).toBeDisabled();
  });

  // T-FAPPLY-03: Dry-run enables once a host is picked and shows a preview
  test('T-FAPPLY-03: selecting a host enables Dry-run and shows preview', async ({ page }) => {
    await host(page, 'web-01').locator('input[type=checkbox]').check();
    await expect(dryRunBtn(page)).toBeEnabled();
    await dryRun(page);
    await expect(page.locator('.fleet-preview').first()).toContainText(/web-01/);
  });

  // T-FAPPLY-04: Execute unlocks only AFTER a matching dry-run
  test('T-FAPPLY-04: Execute stays disabled until a dry-run runs', async ({ page }) => {
    await host(page, 'web-01').locator('input[type=checkbox]').check();
    await expect(executeBtn(page)).toBeDisabled();
    await dryRun(page);
    await expect(executeBtn(page)).toBeEnabled();
  });

  // T-FAPPLY-05: THE GATE - changing the selection after a dry-run re-disables Execute
  test('T-FAPPLY-05: changing selection re-arms the dry-run gate', async ({ page }) => {
    await host(page, 'web-01').locator('input[type=checkbox]').check();
    await dryRun(page);
    await expect(executeBtn(page)).toBeEnabled();
    // Add a second host -> selection no longer matches the previewed one.
    await host(page, 'db-01').locator('input[type=checkbox]').check();
    await expect(executeBtn(page)).toBeDisabled();
  });

  // T-FAPPLY-06: Execute opens a confirm modal naming the host count
  test('T-FAPPLY-06: Execute opens the confirm modal', async ({ page }) => {
    await host(page, 'web-01').locator('input[type=checkbox]').check();
    await dryRun(page);
    await executeBtn(page).click();
    await expect(page.locator('.modal')).toBeVisible();
    await expect(page.locator('#fleet-apply-modal-title')).toContainText('Execute apply on 1 host(s)?');
  });

  // T-FAPPLY-07: Cancelling the modal performs no mutation
  test('T-FAPPLY-07: modal Cancel closes without applying', async ({ page }) => {
    await host(page, 'web-01').locator('input[type=checkbox]').check();
    await dryRun(page);
    await executeBtn(page).click();
    await page.locator('.modal').getByRole('button', { name: 'Cancel' }).click();
    await expect(page.locator('.modal')).toHaveCount(0);
    await expect(page.locator('.fleet-results')).toHaveCount(0);
  });

  // T-FAPPLY-08: Confirming executes and renders results
  test('T-FAPPLY-08: confirming the modal applies and shows results', async ({ page }) => {
    await host(page, 'web-01').locator('input[type=checkbox]').check();
    await dryRun(page);
    await executeBtn(page).click();
    await page.getByRole('button', { name: /Yes, execute/i }).click();
    await expect(page.locator('.fleet-results')).toBeVisible();
    await expect(page.locator('.fleet-results')).toContainText('web-01');
  });

  // T-FAPPLY-09: Roll back mode also previews via dry-run
  test('T-FAPPLY-09: roll back mode previews via dry-run', async ({ page }) => {
    await page.getByRole('radio', { name: 'Roll back' }).check();
    await host(page, 'web-01').locator('input[type=checkbox]').check();
    await dryRun(page);
    await expect(page.locator('.fleet-preview').first()).toBeVisible();
  });
});
