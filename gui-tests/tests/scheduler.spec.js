// =============================================================================
// SCHEDULER TESTS (T-SCHED-01..06) — Linux System Hardener GUI Tests
// =============================================================================
// Scheduled-scan config, notification config, save, and test-notification.

const { test, expect } = require('@playwright/test');
const { loadApp } = require('./helpers');

test.describe('Scheduler', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/scheduler');
  });

  // T-SCHED-01: Page loads with Schedule + Notifications sections
  test('T-SCHED-01: page loads with both sections', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Schedule' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Notifications' })).toBeVisible();
  });

  // T-SCHED-02: The enable toggle is present and togglable
  test('T-SCHED-02: scheduled-scan toggle can be enabled', async ({ page }) => {
    const toggle = page.getByRole('checkbox', { name: /Enable scheduled scanning/i });
    await expect(toggle).toBeVisible();
    await toggle.check();
    await expect(toggle).toBeChecked();
  });

  // T-SCHED-03: A schedule frequency control is offered
  test('T-SCHED-03: schedule frequency select is present', async ({ page }) => {
    await expect(page.locator('.schedule-section select').first()).toBeVisible();
  });

  // T-SCHED-04: Saving the schedule reports success
  test('T-SCHED-04: Save Schedule reports success', async ({ page }) => {
    await page.getByRole('button', { name: 'Save Schedule' }).click();
    await expect(page.getByText(/Schedule saved/i)).toBeVisible();
  });

  // T-SCHED-05: Notification config exposes Email + Webhook subsections
  test('T-SCHED-05: notification subsections present', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Email' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Webhook' })).toBeVisible();
  });

  // T-SCHED-06: Sending a test notification reports success
  test('T-SCHED-06: Send Test Notification reports success', async ({ page }) => {
    await page.getByRole('button', { name: /Test Notification/i }).click();
    await expect(page.getByText(/sent successfully/i)).toBeVisible();
  });
});
