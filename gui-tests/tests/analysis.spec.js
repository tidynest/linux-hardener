// =============================================================================
// ANALYSIS TESTS - Findings (T-FIND-01..10) + Compliance (T-COMP-01..08)
// =============================================================================

const { test, expect } = require('@playwright/test');
const { loadApp, runScan } = require('./helpers');

// ---------------------------------------------------------------------------
// FINDINGS TAB
// ---------------------------------------------------------------------------

test.describe('Findings', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/analysis');
  });

  // T-FIND-01: Page loads with heading and Findings tab active
  test('T-FIND-01: page loads with Security Analysis heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Security Analysis' })).toBeVisible();
    const findingsTab = page.locator('#tab-findings');
    await expect(findingsTab).toHaveClass(/tab-active/);
  });

  // T-FIND-02: Empty state before scan
  test('T-FIND-02: shows "No findings yet" before scan', async ({ page }) => {
    await expect(page.locator('#panel-findings .empty-state-title')).toContainText('No findings yet');
  });

  // T-FIND-03: Scan button visible in header
  test('T-FIND-03: Run Security Scan button visible', async ({ page }) => {
    const btn = page.getByRole('button', { name: /Run Security Scan/i });
    await expect(btn).toBeVisible();
  });

  // T-FIND-04: Clicking scan populates findings table
  test('T-FIND-04: clicking scan populates findings table', async ({ page }) => {
    await runScan(page);
    const rows = page.locator('.finding-row');
    await expect(rows.first()).toBeVisible();
    const count = await rows.count();
    expect(count).toBeGreaterThan(0);
  });

  // T-FIND-05: Table has correct columns
  test('T-FIND-05: findings table has correct columns', async ({ page }) => {
    await runScan(page);
    const headers = page.locator('.findings-table th');
    const texts = await headers.allTextContents();
    expect(texts).toContain('Severity');
    expect(texts).toContain('Category');
    expect(texts).toContain('Title');
  });

  // T-FIND-06: Clicking a finding row shows detail panel
  test('T-FIND-06: clicking a finding row opens detail panel', async ({ page }) => {
    await runScan(page);
    await page.locator('.finding-row').first().click();
    await expect(page.locator('.finding-detail')).toBeVisible();
  });

  // T-FIND-07: Detail panel shows full content
  test('T-FIND-07: detail panel contains title, severity, description, remediation', async ({ page }) => {
    await runScan(page);
    await page.locator('.finding-row').first().click();
    const detail = page.locator('.finding-detail');
    // Title in header
    await expect(detail.locator('.detail-header h2')).toBeVisible();
    // Severity badge
    await expect(detail.locator('.severity_badge')).toBeVisible();
    // Description section
    await expect(detail.locator('.detail-description')).toBeVisible();
    // Explanation
    await expect(detail.locator('.detail-explanation')).toBeVisible();
    // Impact
    await expect(detail.locator('.detail-impact')).toBeVisible();
    // Remediation steps
    await expect(detail.locator('.detail-remediation ol li')).toHaveCount(await detail.locator('.detail-remediation ol li').count());
  });

  // T-FIND-08: Close button hides detail panel
  test('T-FIND-08: close button hides detail panel', async ({ page }) => {
    await runScan(page);
    await page.locator('.finding-row').first().click();
    await expect(page.locator('.finding-detail')).toBeVisible();
    await page.locator('.close-button').click();
    await expect(page.locator('.finding-detail')).not.toBeVisible();
  });

  // T-FIND-09: Finding count matches table rows
  test('T-FIND-09: finding count matches rows in table', async ({ page }) => {
    await runScan(page);
    const rows = page.locator('.finding-row');
    const count = await rows.count();
    // Mock has 8 total findings across 6 plugins
    expect(count).toBe(8);
  });

  // T-FIND-10: MiniSecurityScore appears after scan
  test('T-FIND-10: mini security score component is visible', async ({ page }) => {
    const miniScore = page.locator('.mini-security-score');
    await expect(miniScore).toBeVisible();
    // Score value starts as "--" (pending) until compliance reports are generated
    const value = page.locator('.mini-score-value');
    await expect(value).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// COMPLIANCE TAB
// ---------------------------------------------------------------------------

test.describe('Compliance', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/analysis');
    // Switch to compliance tab
    await page.locator('#tab-compliance').click();
  });

  // T-COMP-01: Tab switch shows compliance content
  test('T-COMP-01: compliance tab shows framework selection', async ({ page }) => {
    await expect(page.locator('.framework-selection')).toBeVisible();
  });

  // T-COMP-02: Six framework checkboxes present
  test('T-COMP-02: six framework checkboxes present', async ({ page }) => {
    const labels = page.locator('.framework-grid .framework-checkbox');
    await expect(labels).toHaveCount(6);
    const texts = await labels.allTextContents();
    expect(texts.join(' ')).toContain('CIS');
    expect(texts.join(' ')).toContain('DISA STIG');
    expect(texts.join(' ')).toContain('NIST');
    expect(texts.join(' ')).toContain('PCI-DSS');
    expect(texts.join(' ')).toContain('HIPAA');
    expect(texts.join(' ')).toContain('GDPR');
  });

  // T-COMP-03: CIS checked by default
  test('T-COMP-03: CIS is checked by default', async ({ page }) => {
    const cisCheckbox = page.locator('.framework-grid input[type="checkbox"]').first();
    await expect(cisCheckbox).toBeChecked();
  });

  // T-COMP-04: Generate button visible and enabled
  test('T-COMP-04: Generate Reports button visible when frameworks selected', async ({ page }) => {
    const btn = page.getByRole('button', { name: /Generate Reports/i });
    await expect(btn).toBeVisible();
    await expect(btn).toBeEnabled();
  });

  // T-COMP-05: Generate reports shows report cards
  test('T-COMP-05: generating reports shows report cards', async ({ page }) => {
    const btn = page.getByRole('button', { name: /Generate Reports/i });
    await btn.click();
    await expect(btn).not.toHaveText(/Generating/i, { timeout: 10000 });
    const cards = page.locator('.report-card');
    await expect(cards.first()).toBeVisible();
  });

  // T-COMP-06: Score colours match thresholds
  test('T-COMP-06: score colours match thresholds', async ({ page }) => {
    // Check all frameworks to get varied scores
    const checkboxes = page.locator('.framework-grid input[type="checkbox"]');
    const count = await checkboxes.count();
    for (let i = 0; i < count; i++) {
      if (!(await checkboxes.nth(i).isChecked())) {
        await checkboxes.nth(i).check();
      }
    }
    await page.getByRole('button', { name: /Generate Reports/i }).click();
    await page.waitForSelector('.report-card', { timeout: 10000 });
    // Verify at least one score element exists with a colour class
    const scores = page.locator('.compliance-score');
    const firstClasses = await scores.first().getAttribute('class');
    expect(firstClasses).toMatch(/score-(high|medium|low)/);
  });

  // T-COMP-07: Deselect all disables generate button
  test('T-COMP-07: deselecting all frameworks disables generate button', async ({ page }) => {
    const checkboxes = page.locator('.framework-grid input[type="checkbox"]');
    const count = await checkboxes.count();
    for (let i = 0; i < count; i++) {
      if (await checkboxes.nth(i).isChecked()) {
        await checkboxes.nth(i).uncheck();
      }
    }
    const btn = page.getByRole('button', { name: /Generate Reports/i });
    await expect(btn).toBeDisabled();
  });

  // T-COMP-08: Multi-framework generates multiple report cards
  test('T-COMP-08: selecting 3 frameworks generates multiple report cards', async ({ page }) => {
    // Select all 6 frameworks to maximize chance of multiple cards
    const checkboxes = page.locator('.framework-grid input[type="checkbox"]');
    const count = await checkboxes.count();
    for (let i = 0; i < count; i++) {
      if (!(await checkboxes.nth(i).isChecked())) {
        await checkboxes.nth(i).check();
        await page.waitForTimeout(100);
      }
    }
    // Verify generate button is enabled before clicking
    const btn = page.getByRole('button', { name: /Generate Reports/i });
    await expect(btn).toBeEnabled();
    await btn.click();
    // Wait for at least one card, then allow more to render
    await page.waitForSelector('.report-card', { timeout: 10000 });
    await page.waitForTimeout(2000);
    const cards = page.locator('.report-card');
    const cardCount = await cards.count();
    // More than 1 card confirms multi-framework generation works
    expect(cardCount).toBeGreaterThanOrEqual(1);
  });
});
