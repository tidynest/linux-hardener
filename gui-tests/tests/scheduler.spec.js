// =============================================================================
// SCHEDULER TESTS (T-SCHED-01..06) - Linux Hardener GUI Tests
// =============================================================================
// Scheduled-scan config, notification config, save, and test-notification.

const { test, expect } = require('@playwright/test');
const { loadApp } = require('./helpers');

test.describe('Scheduler', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/scheduler');
  });

  // T-SCHED-01: Page loads with Schedule + Notifications sections
  //
  // `exact` matters here. Playwright matches an accessible name by substring
  // unless told otherwise, so 'Schedule' also matched the page's own
  // <h1>Scheduler</h1> and the locator resolved to two elements.
  test('T-SCHED-01: page loads with both sections', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Schedule', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Notifications', exact: true })).toBeVisible();
  });

  // T-SCHED-02: The enable toggle is present and togglable
  //
  // The checkbox carries the state but cannot be clicked: the switch track
  // drawn over it intercepts the pointer, which is how a real operator's click
  // reaches it too. Clicking the label is what they actually do, and the label
  // wraps the input, so it toggles.
  //
  // The assertion is that the state flipped rather than that it ended up
  // checked, which would hold without the click ever landing if the shipped
  // default were already enabled.
  test('T-SCHED-02: scheduled-scan toggle can be enabled', async ({ page }) => {
    const toggle = page.getByRole('checkbox', { name: /Enable scheduled scanning/i });
    await expect(toggle).toBeVisible();
    const before = await toggle.isChecked();
    await page.getByText('Enable scheduled scanning').click();
    await expect(toggle).toBeChecked({ checked: !before });
  });

  // T-SCHED-03: A schedule frequency control is offered
  test('T-SCHED-03: schedule frequency select is present', async ({ page }) => {
    await expect(page.locator('.schedule-section select').first()).toBeVisible();
  });

  // T-SCHED-04: Saving the schedule reports success
  //
  // The page lifted schedule and notifications into one form with a single
  // control, labelled "Save", and it reports through a live status region
  // naming the file it wrote rather than the words "Schedule saved". `exact`
  // keeps the name off "Saving...", which is the same button mid-flight.
  // The page carries two live regions with role="status", the save region and
  // the notification-test region, and neither has an accessible name to tell
  // them apart, so the save region is reached by its class. Naming them would
  // be the better fix and belongs in the interface rather than here.
  test('T-SCHED-04: Save reports success', async ({ page }) => {
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.locator('.scheduler-save-region')).toContainText(/Saved to/i);
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
