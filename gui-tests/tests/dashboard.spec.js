// =============================================================================
// DASHBOARD TESTS (T-DASH-01..09) - Linux System Hardener GUI Tests
// =============================================================================

const { test, expect } = require('@playwright/test');
const { loadApp, runScan } = require('./helpers');

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/');
  });

  // T-DASH-01: Page loads
  test('T-DASH-01: page loads with heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'System Security Dashboard' })).toBeVisible();
  });

  // T-DASH-02: Initial score shows --/100
  test('T-DASH-02: initial score shows placeholder', async ({ page }) => {
    const scoreValue = page.locator('.score-value');
    await expect(scoreValue).toHaveText('--');
    const scoreMax = page.locator('.score-max');
    await expect(scoreMax).toHaveText('/100');
    await expect(page.locator('.score-status')).toContainText('Run a scan');
  });

  // T-DASH-03: Run Scan button visible and enabled
  test('T-DASH-03: Run Scan button is visible and enabled', async ({ page }) => {
    const btn = page.getByRole('button', { name: /Run Scan/i });
    await expect(btn).toBeVisible();
    await expect(btn).toBeEnabled();
  });

  // T-DASH-04: Click Run Scan populates results
  test('T-DASH-04: clicking Run Scan populates results', async ({ page }) => {
    await runScan(page);
    // After scan completes, score should no longer be pending
    const scoreValue = page.locator('.score-value');
    await expect(scoreValue).not.toHaveText('--', { timeout: 10000 });
  });

  // T-DASH-05: View Analysis navigates to /analysis
  test('T-DASH-05: View Analysis navigates to /analysis', async ({ page }) => {
    const link = page.getByRole('link', { name: /View Analysis/i }).or(
      page.locator('.btn', { hasText: /View Analysis/i })
    );
    await link.click();
    await expect(page).toHaveURL(/\/analysis/);
  });

  // T-DASH-06: Configure Hardening navigates to /hardening
  test('T-DASH-06: Configure Hardening navigates to /hardening', async ({ page }) => {
    const link = page.getByRole('link', { name: /Configure Hardening/i }).or(
      page.locator('.btn', { hasText: /Configure Hardening/i })
    );
    await link.click();
    await expect(page).toHaveURL(/\/hardening/);
  });

  // T-DASH-07: Initial activity shows empty state
  test('T-DASH-07: initial activity shows "No activity yet"', async ({ page }) => {
    await expect(page.locator('.empty-state-title')).toContainText('No activity yet');
  });

  // T-DASH-08: Post-scan activity shows scan entry
  test('T-DASH-08: after scan, activity shows Security Scan with finding count', async ({ page }) => {
    await runScan(page);
    const activity = page.locator('.activity-item').first();
    await expect(activity).toContainText('Security Scan');
    await expect(activity).toContainText('findings');
  });

  // T-DASH-09: Post-scan score is numeric and colour-coded
  test('T-DASH-09: after scan, score is numeric and colour-coded', async ({ page }) => {
    await runScan(page);
    const scoreValue = page.locator('.score-value');
    // Should be a number, not "--"
    await expect(scoreValue).not.toHaveText('--');
    const text = await scoreValue.textContent();
    expect(Number(text)).toBeGreaterThan(0);
    // Score display should have a colour class (not score-pending)
    const scoreDisplay = page.locator('.score-display');
    const classes = await scoreDisplay.getAttribute('class');
    expect(classes).not.toContain('score-pending');
  });
});
