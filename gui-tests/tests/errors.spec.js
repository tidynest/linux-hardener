// =============================================================================
// ERROR HANDLING TESTS (T-ERR-01..04)
// =============================================================================

const { test, expect } = require('@playwright/test');
const { loadApp } = require('./helpers');

test.describe('Error Handling', () => {
  // T-ERR-01: Scan error shows error banner
  test('T-ERR-01: scan error shows error banner', async ({ page }) => {
    await loadApp(page, '/', 'error_mode=scan');
    const btn = page.getByRole('button', { name: /Run Scan/i });
    await btn.click();
    await expect(btn).not.toHaveText(/Scanning/i, { timeout: 10000 });
    const banner = page.locator('.error-banner');
    await expect(banner).toBeVisible();
    await expect(banner).toContainText(/permission denied|failed/i);
  });

  // T-ERR-02: Apply error shows error banner
  test('T-ERR-02: apply error shows error banner', async ({ page }) => {
    await loadApp(page, '/hardening', 'error_mode=apply');
    // Trigger preview (which calls dry_run — also errored in apply mode)
    await page.getByRole('button', { name: /Preview Changes/i }).click();
    // Should get error
    const banner = page.locator('.error-banner');
    await expect(banner).toBeVisible({ timeout: 10000 });
    await expect(banner).toContainText(/Authentication|failed/i);
  });

  // T-ERR-03: Checkpoint load error shows error banner
  test('T-ERR-03: checkpoint error shows error banner', async ({ page }) => {
    await loadApp(page, '/hardening', 'error_mode=checkpoint');
    await page.locator('.section-btn', { hasText: 'History' }).click();
    // Checkpoint loading should fail
    const banner = page.locator('.error-banner');
    await expect(banner).toBeVisible({ timeout: 10000 });
    await expect(banner).toContainText(/database|locked|failed/i);
  });

  // T-ERR-04: Dismiss error banner
  test('T-ERR-04: clicking dismiss hides error banner', async ({ page }) => {
    await loadApp(page, '/', 'error_mode=scan');
    await page.getByRole('button', { name: /Run Scan/i }).click();
    const banner = page.locator('.error-banner');
    await expect(banner).toBeVisible({ timeout: 10000 });
    await page.locator('.error-banner-dismiss').click();
    await expect(banner).not.toBeVisible();
  });
});
