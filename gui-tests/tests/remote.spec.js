// =============================================================================
// REMOTE ROUTE TESTS (T-REMOTE-01..03) - Linux Hardener GUI Tests
// =============================================================================
//
// The redesign folded remote scanning into the Hosts page. There is no separate
// Remote Scanning screen and no connect/disconnect lifecycle: an operator
// selects hosts and scans them, and /remote survives only as a redirect for
// links written before the redesign.
//
// This file used to cover seven things against that screen. What happened to
// each, stated rather than quietly dropped:
//
//   T-REMOTE-01 host inventory      -> kept below, against the Hosts page
//   T-REMOTE-02 not-connected guide -> gone; the concept no longer exists
//   T-REMOTE-03 connect             -> gone; same reason
//   T-REMOTE-04 remote scan         -> covered by fleet.spec.js T-FLEET-04
//   T-REMOTE-05 disconnect          -> gone; same reason
//   T-REMOTE-06 Add Host form       -> kept below
//   T-REMOTE-07 two-step delete     -> NOT carried over. The affordance is not
//       on the collapsed row and this session could not open the expander to
//       see whether it survived, so writing a test for it would be a guess.
//       Host deletion is currently uncovered and wants a test once someone can
//       confirm where the control lives.

const { test, expect } = require('@playwright/test');
const { loadApp } = require('./helpers');

test.describe('Remote route', () => {
  // T-REMOTE-01: /remote redirects to the Hosts page
  //
  // The redirect exists for pre-redesign links and nothing else covered it.
  test('T-REMOTE-01: /remote redirects to Hosts', async ({ page }) => {
    await loadApp(page, '/remote');
    await expect(page.getByRole('heading', { name: 'Hosts', level: 1 })).toBeVisible();
  });

  // T-REMOTE-02: The saved-host inventory is listed there
  test('T-REMOTE-02: the saved hosts are listed', async ({ page }) => {
    await loadApp(page, '/remote');
    await expect(page.getByRole('checkbox', { name: 'Select web-01' })).toBeVisible();
    await expect(page.getByRole('checkbox', { name: 'Select db-01' })).toBeVisible();
  });

  // T-REMOTE-03: "Add Host" opens the host form
  //
  // Two buttons carry this name: the toolbar's, which opens the form, and the
  // form's own submit. In document order the toolbar's comes first.
  //
  // The absence of a textbox is asserted before the click as well as its
  // presence after. Without that, a form that were always in the DOM would
  // satisfy the second assertion whether or not the click did anything, and
  // the test would pass while covering nothing.
  test('T-REMOTE-03: Add Host opens the host form', async ({ page }) => {
    await loadApp(page, '/remote');
    await expect(page.getByRole('textbox')).toHaveCount(0);
    await page.getByRole('button', { name: 'Add Host' }).first().click();
    await expect(page.getByRole('textbox').first()).toBeVisible();
  });
});
