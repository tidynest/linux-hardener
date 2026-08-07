// =============================================================================
// ERROR HANDLING TESTS (T-ERR-01..04)
// =============================================================================

const { test, expect } = require('@playwright/test');
const { loadApp } = require('./helpers');

test.describe('Error Handling', () => {
  // T-ERR-01: Scan error shows error banner
  //
  // The button is "Run Security Scan". /Run Scan/i has no literal "Run Scan"
  // to match in that, so this waited out its timeout on a control that was
  // sitting there in plain sight.
  test('T-ERR-01: scan error shows error banner', async ({ page }) => {
    await loadApp(page, '/', 'error_mode=scan');
    const btn = page.getByRole('button', { name: /Run Security Scan/i });
    await btn.click();
    await expect(btn).not.toHaveText(/Scanning/i, { timeout: 10000 });
    const banner = page.locator('.error-banner');
    await expect(banner).toBeVisible();
    await expect(banner).toContainText(/permission denied|failed/i);
  });

  // T-ERR-02: Apply error shows error banner
  test('T-ERR-02: apply error shows error banner', async ({ page }) => {
    await loadApp(page, '/hardening', 'error_mode=apply');
    // Trigger preview (which calls dry_run - also errored in apply mode)
    await page.getByRole('button', { name: /Preview Changes/i }).click();
    // Should get error
    const banner = page.locator('.error-banner');
    await expect(banner).toBeVisible({ timeout: 10000 });
    await expect(banner).toContainText(/Authentication|failed/i);
  });

  // T-ERR-03: Checkpoint load error shows error banner
  test('T-ERR-03: checkpoint error shows error banner', async ({ page }) => {
    await loadApp(page, '/hardening', 'error_mode=checkpoint');
    await page.getByRole('tab', { name: 'History' }).click();
    // Checkpoint loading should fail
    const banner = page.locator('.error-banner');
    await expect(banner).toBeVisible({ timeout: 10000 });
    await expect(banner).toContainText(/database|locked|failed/i);
  });

  // T-ERR-04: Dismiss error banner
  //
  // Same button-name repair as T-ERR-01. The dismiss control is reached by its
  // accessible name rather than `.error-banner-dismiss`: it is the one thing
  // in the banner an operator has to be able to find, so the name is the part
  // worth pinning.
  test('T-ERR-04: clicking dismiss hides error banner', async ({ page }) => {
    await loadApp(page, '/', 'error_mode=scan');
    await page.getByRole('button', { name: /Run Security Scan/i }).click();
    const banner = page.locator('.error-banner');
    await expect(banner).toBeVisible({ timeout: 10000 });
    await page.getByRole('button', { name: 'Dismiss error' }).click();
    await expect(banner).not.toBeVisible();
  });
});
