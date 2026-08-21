// =============================================================================
// SCHEDULER TESTS (T-SCHED-01..08) - Linux Hardener GUI Tests
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

  // T-SCHED-07: The two paused-schedule notes appear only while scanning is off
  //
  // Both notes render behind a `<Show when=!enabled>` and both carry
  // `.scheduler-override-note`, which the page's "Custom schedule active" note
  // uses as well, so they are reached by their text rather than by that class.
  //
  // Both directions are asserted because either alone is vacuous: a note that
  // rendered unconditionally would pass a presence check with the toggle in any
  // state, and a note that never rendered at all would pass an absence check.
  // Only the flip distinguishes a note that is bound to the toggle from one
  // that merely exists.
  //
  // The initial state is normalised rather than assumed. The mock ships the
  // scheduler disabled, but a fixture change that flipped that default would
  // otherwise turn this into a test of the enabled state alone, silently.
  test('T-SCHED-07: paused-schedule notes appear only while scanning is off', async ({ page }) => {
    const toggle = page.getByRole('checkbox', { name: /Enable scheduled scanning/i });
    const label = page.getByText('Enable scheduled scanning');
    const kept = page.getByText(/These settings are saved, but not used while scanning is off/i);
    const notSent = page.getByText(/so these are not sent automatically/i);

    if (await toggle.isChecked()) await label.click();
    await expect(toggle).not.toBeChecked();
    await expect(kept).toBeVisible();
    await expect(notSent).toBeVisible();

    await label.click();
    await expect(toggle).toBeChecked();
    await expect(kept).toHaveCount(0);
    await expect(notSent).toHaveCount(0);
  });

  // T-SCHED-06: Sending a test notification reports success
  test('T-SCHED-06: Send Test Notification reports success', async ({ page }) => {
    await page.getByRole('button', { name: /Test Notification/i }).click();
    await expect(page.getByText(/sent successfully/i)).toBeVisible();
  });

  // T-SCHED-08: The form does not exist before the config it is made of
  //
  // The page loads its config in a `spawn_local` on mount and populates the
  // form from an Effect when it arrives. A form rendered immediately is
  // therefore editable before it has any data, and the hydration lands on top
  // of whatever was done in that window: switching scheduled scanning on there
  // switched itself back off. T-SCHED-07 caught it once, on opensuse on
  // 2026-08-21, and it read as a distribution fault because the mock's latency
  // is `150 + random * 200` and five distributions won the coin flip.
  //
  // This test does not flip a coin. `__mockLatency` widens that one command
  // until the pre-load window is somewhere a test can stand inside, and the
  // assertion is that nothing editable is standing there with it.
  //
  // Absence first, and it is the whole point rather than a preamble: if the
  // gate is ever removed the toggle is present at that moment and this fails,
  // which is exactly the reintroduced bug. The Save button is checked too and
  // is the more expensive half - a save fired before the load would write the
  // form's empty defaults over the real config, reaching the file rather than
  // the screen.
  //
  // Then the positive half, so the gate cannot pass by never opening: the
  // toggle appears on its own, takes an edit, and keeps it while the schedule
  // select proves the config is the loaded one. That select is reached
  // positionally because its <label> is not associated with it; the Schedule
  // block precedes Notifications, so it is the first `.form-select` on the
  // page. Associating them is the better fix and belongs in the interface.
  test('T-SCHED-08: nothing is editable before the config lands', async ({ page }) => {
    await page.addInitScript(() => {
      window.__mockLatency = { get_scheduler_config: 3000 };
    });
    await loadApp(page, '/scheduler');

    const toggle = page.getByRole('checkbox', { name: /Enable scheduled scanning/i });
    const save = page.getByRole('button', { name: 'Save', exact: true });
    const schedule = page.locator('select.form-select').first();

    // Absence of the controls comes first and the hint comes last, because
    // the order decides which assertion a regression reports. With the hint
    // first, removing the gate fails on a missing hint and never reaches the
    // question the test exists to ask; measured on 2026-08-21 by removing it.
    await expect(toggle).toHaveCount(0);
    await expect(save).toBeDisabled();
    await expect(page.getByText(/Loading configuration/i)).toBeVisible();

    await expect(toggle).toBeVisible({ timeout: 10000 });
    await expect(schedule).toHaveValue('Daily at 2:00 AM');
    await expect(save).toBeEnabled();

    await page.getByText('Enable scheduled scanning').click();
    await expect(toggle).toBeChecked();
  });
});
