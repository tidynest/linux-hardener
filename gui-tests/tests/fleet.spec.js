// =============================================================================
// FLEET SCAN TESTS (T-FLEET-01..11) - Linux Hardener GUI Tests
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

  // T-FLEET-10: An expanded host renders its persisted scan history
  //
  // This is the assertion the mock's missing `get_host_history` case hid.
  // `HostPanel` fires that command from a `spawn_local` on mount and takes the
  // result through `.unwrap_or_default()` at `host_panel.rs:85`, so a rejected
  // invoke renders exactly the no-history state a host with no persisted scans
  // renders. T-FLEET-05, T-FLEET-08 and T-FLEET-09 all expand a row and none of
  // them could tell those two apart.
  //
  // web-01 carries the assertion for that reason. The empty state passes
  // whether or not the command answered, so only a host with rows separates a
  // working handler from a swallowed rejection: run this against a mock without
  // the `get_host_history` case and the count is 0.
  //
  // db-01 is checked second and deliberately has no rows in the fixture, so the
  // empty-state branch is reached from a real answer. Without it a fixture that
  // returned rows for every host would make the first half pass for the wrong
  // reason and leave the branch an operator sees on a fresh install untested.
  //
  // The panel is behind a `<Show>`, so collapsing removes it rather than hiding
  // it, and the count assertion between the two halves is what stops db-01's
  // reading from being web-01's panel still on the page.
  test('T-FLEET-10: an expanded host renders its persisted scan history', async ({ page }) => {
    const nodes = page.locator('.host-panel .timeline-node');
    const web = expandHost(page, 'web-01');

    await web.click();
    await expect(nodes).toHaveCount(3);
    // The newest session: eight findings, and worse than the one before it.
    // `direction` is an Option<String> and the only nullable field in the
    // payload, so it is the one a mock drift drops silently.
    await expect(nodes.first()).toContainText('8 findings');
    await expect(nodes.first()).toContainText('worse');

    await web.click();
    await expect(page.locator('.host-panel')).toHaveCount(0);

    await expandHost(page, 'db-01').click();
    await expect(page.getByText(/No persisted history for this host/i)).toBeVisible();
    await expect(nodes).toHaveCount(0);
  });

  // T-FLEET-11: The expanded host says which identifier scheme scored it
  //
  // The fleet has always scored each host under its own resolved profile and
  // never said so, which is the follow-up #11 left: an operator reading
  // "RHEL-10-701130" in the control list had no way to tell a RHEL 10 scheme
  // from canonical ids that had gone strange.
  //
  // Both arms are asserted, and they need two different hosts. web-01 is the
  // fixture's rhel10 host, so its CIS and STIG rows each carry the scheme that
  // scored them. The generic arm cannot use db-01: it fails, renders no
  // compliance table, and a badge count of 0 there would hold whether or not
  // the badge was suppressed for Generic, which is no assertion at all. An
  // ad-hoc target scans clean in this fixture and is generic, so it renders
  // the same two framework rows web-01 does with no badge on either, and the
  // contrast between the two halves is what has content.
  //
  // The framework rows are counted in the generic half before the badges are.
  // Without it a build that dropped the whole Compliance detail section, or a
  // mock drift that emptied `compliance`, would satisfy "no badges" perfectly.
  test('T-FLEET-11: the profile that scored a host is named on its rows', async ({ page }) => {
    const badges = page.locator('.host-panel .host-profile-badge');

    await selectHost(page, 'web-01').check();
    await scanButton(page).click();
    await expect(unscanned(page)).toHaveCount(1);

    const web = expandHost(page, 'web-01');
    await web.click();
    await expect(badges).toHaveCount(2);
    await expect(badges).toHaveText([
      'CIS RHEL 10 Benchmark v1.0.1',
      'DISA RHEL 10 STIG V1R1',
    ]);

    // Collapse before the second host: the panel is behind a `<Show>`, so this
    // removes it rather than hiding it, and the locator above is panel-rooted.
    await web.click();
    await expect(page.locator('.host-panel')).toHaveCount(0);

    // The generic half. The target is added, selected and scanned like any
    // other row; `adhoc_canonical` fills the default port in, so the row is
    // named "admin@10.0.0.9:22" rather than what was typed.
    await page.getByRole('button', { name: 'Add ad-hoc target' }).click();
    await page.getByRole('textbox', { name: 'Ad-hoc SSH target' }).fill('admin@10.0.0.9');
    await button(page, 'Add').click();

    const adhoc = 'admin@10.0.0.9:22';
    await expect(selectHost(page, adhoc)).toBeVisible();
    await selectHost(page, 'web-01').uncheck();
    await selectHost(page, adhoc).check();
    await scanButton(page).click();

    await expandHost(page, adhoc).click();
    // The rows exist, so the absence below is a suppressed badge and not a
    // missing table.
    await expect(page.locator('.host-panel .host-compliance-table tbody tr')).toHaveCount(2);
    await expect(badges).toHaveCount(0);
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
