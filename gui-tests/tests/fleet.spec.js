// =============================================================================
// FLEET SCAN TESTS (T-FLEET-01..07) - Linux Hardener GUI Tests
// =============================================================================
// Read-only multi-host scan: host selection, per-host results, expandable rows,
// and the failed-host path.
//
// The redesign folded remote scanning into this page and renamed it Hosts.
// There is no `.fleet-host-option`, no results table and no `.fleet-row`: hosts
// are checkboxes named "Select <host>", the scan button carries its own
// selection count, and an unscanned host says so in its row.
//
// Whether a host has been scanned is therefore readable without knowing how a
// result is drawn, which is what the assertions below use: two hosts start as
// "Not scanned yet", and scanning one leaves one.

const { test, expect } = require('@playwright/test');
const { loadApp } = require('./helpers');

const selectHost = (page, name) => page.getByRole('checkbox', { name: `Select ${name}` });
const scanButton = (page) => page.getByRole('button', { name: /Scan Selected/i });
const unscanned = (page) => page.getByText('Not scanned yet');
// Named for the host, so a row is reached by which host it is rather than by
// where it sits in the list. The label was a constant "Expand host" until #135.
const expandHost = (page, name) => page.getByRole('button', { name: `Expand ${name}` });
// exact, because "Delete" is a prefix of nothing here but "Confirm" and
// "Cancel" are common button words and a substring match is the default.
const button = (page, name) => page.getByRole('button', { name, exact: true });

test.describe('Fleet Scan', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/fleet');
  });

  // T-FLEET-01: Page loads
  test('T-FLEET-01: page loads with heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Hosts', level: 1 })).toBeVisible();
  });

  // T-FLEET-02: Nothing is scanned before a scan
  test('T-FLEET-02: both hosts start unscanned', async ({ page }) => {
    await expect(unscanned(page)).toHaveCount(2);
  });

  // T-FLEET-03: Saved hosts listed; scan button disabled until a host is picked
  test('T-FLEET-03: lists saved hosts and disables Scan until selection', async ({ page }) => {
    await expect(selectHost(page, 'web-01')).toBeVisible();
    await expect(selectHost(page, 'db-01')).toBeVisible();
    await expect(scanButton(page)).toBeDisabled();
  });

  // T-FLEET-04: Selecting a host enables Scan; running it scans that host alone
  test('T-FLEET-04: scanning a host populates its result', async ({ page }) => {
    await selectHost(page, 'web-01').check();
    const btn = scanButton(page);
    await expect(btn).toBeEnabled();
    await btn.click();
    // web-01 has a result now; db-01 was not selected and still has none.
    await expect(unscanned(page)).toHaveCount(1);
  });

  // T-FLEET-05: A scanned row expands to show that host's detail
  test('T-FLEET-05: expanding a scanned host shows its detail', async ({ page }) => {
    await selectHost(page, 'web-01').check();
    await scanButton(page).click();
    await expect(unscanned(page)).toHaveCount(1);
    const expander = expandHost(page, 'web-01');
    await expander.click();
    await expect(expander).toHaveAttribute('aria-expanded', 'true');
  });

  // T-FLEET-06: A host that fails to scan says so rather than crashing
  //
  // db-01 is the mock's failing host, refused on port 2222.
  test('T-FLEET-06: failed host shows its failure', async ({ page }) => {
    await selectHost(page, 'db-01').check();
    await scanButton(page).click();
    await expect(page.getByText(/Failed|connection refused/i).first()).toBeVisible();
  });

  // T-FLEET-07: Scanning both hosts leaves neither unscanned
  test('T-FLEET-07: scanning multiple hosts yields a result each', async ({ page }) => {
    await selectHost(page, 'web-01').check();
    await selectHost(page, 'db-01').check();
    await scanButton(page).click();
    await expect(unscanned(page)).toHaveCount(0);
  });

  // T-FLEET-08: Deleting a saved host takes two actions, not one
  //
  // A single-step delete of a saved host is data loss: the profile, its
  // credentials path and its history key go with it. The middle assertion is
  // the one that matters and the one a passing test can lose silently, so it
  // is made before the confirm: after the FIRST click the host must still be
  // listed. A delete that fired on one click would satisfy every other line
  // here.
  //
  // No scan first, deliberately. The actions row renders for a saved host
  // whether or not it has been scanned, and scanning would make this test
  // depend on the scan path as well as on the delete path.
  test('T-FLEET-08: deleting a saved host needs a confirmation step', async ({ page }) => {
    await expandHost(page, 'web-01').click();
    await button(page, 'Delete').click();

    // The prompt FIRST, and the order is load-bearing rather than stylistic.
    //
    // Measured on 2026-08-09 against a deliberately mutated build that deleted
    // on the first click: with the host checked first, that assertion PASSED.
    // `delete_remote_host` and the re-list that follows it are async, and
    // `toBeVisible` resolves the instant the element is there, so the check
    // beat the deletion it exists to detect. Asserting presence is asserting
    // that nothing has happened yet, which is not something a test can wait
    // for.
    //
    // Awaiting the prompt is what gives the app its turn. Under a correct
    // two-step delete it appears at once; under a one-click delete it never
    // appears and this line fails, which is the mutation's real signal. The
    // host check below is then a corroborating guard against a build that
    // arms AND deletes, and it is meaningful only because the await above has
    // already let that deletion land.
    await expect(page.getByText('Delete?')).toBeVisible();
    await expect(selectHost(page, 'web-01')).toBeVisible();

    await button(page, 'Confirm').click();

    await expect(selectHost(page, 'web-01')).toHaveCount(0);
    // The other host is asserted too: a delete that emptied the list would
    // pass the line above while doing something far worse than the bug.
    await expect(selectHost(page, 'db-01')).toBeVisible();
  });

  // T-FLEET-09: The armed state is reversible, and reverting it deletes nothing
  test('T-FLEET-09: cancelling an armed delete leaves the host saved', async ({ page }) => {
    await expandHost(page, 'db-01').click();
    await button(page, 'Delete').click();
    await expect(page.getByText('Delete?')).toBeVisible();

    await button(page, 'Cancel').click();

    // Disarmed, not merely hidden: the plain Delete button is back, which is
    // the state a second delete attempt has to start from.
    await expect(page.getByText('Delete?')).toHaveCount(0);
    await expect(button(page, 'Delete')).toBeVisible();
    await expect(selectHost(page, 'db-01')).toBeVisible();
    await expect(selectHost(page, 'web-01')).toBeVisible();
  });
});
