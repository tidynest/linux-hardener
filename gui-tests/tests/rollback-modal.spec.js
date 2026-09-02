// =============================================================================
// ROLLBACK MODAL LIFECYCLE - Linux Hardener GUI Tests
// =============================================================================
// The divergence section of the rollback modal's Result stage has its own
// coverage (T-DIVG-01..05 in hardening.spec.js, a contrast route, a theme
// screenshot state). Everything AROUND that section shipped on reading alone:
// the Confirm preview, the preview that could not be read, the Restoring stage
// and the Escape that must not reach it, the two rejection paths, the reload
// section that had never rendered because the mock omitted `rollback_reloads`
// entirely (an omission `#[serde(default)]` reads as an empty vec, so nothing
// errored and nothing rendered), and the header predicate whose
// `reloads_ok()` half no fixture could pose.
//
// The modes this spec selects are documented at the top of tauri-mock.js.
// `runRollback` in helpers.js drives the divergence result; the tests here
// need the stages BEFORE and BESIDE it, so they drive the modal directly.
// =============================================================================

const { test, expect } = require('@playwright/test');
const { loadApp, runRollback } = require('./helpers');

// History tab -> first checkpoint's Roll back button -> the modal's own
// confirm button. Stops BEFORE confirming, which is what distinguishes this
// from helpers.runRollback: every test in the first describe needs the
// Confirm stage on screen, not the result.
async function openConfirm(page) {
  await page.getByRole('tab', { name: 'History' }).click();
  await page.getByRole('button', { name: 'Roll back', exact: true }).first().click();
  // The title arrives with the modal; the file list arrives when
  // get_checkpoint_detail resolves. Waiting on the list rather than the title
  // means the assertions below read a populated Confirm stage rather than a
  // loading one, which is the distinction b35a0dcf was written to make.
  await expect(page.locator('.rollback-file-list')).toBeVisible({ timeout: 10000 });
}

// openConfirm plus the modal's own confirm press. Reaches for the button by
// class, for the reason helpers.runRollback states: its name carries a file
// count, and "Roll back" as a substring also matches every button in the
// history list behind the modal.
async function confirmRollback(page) {
  await openConfirm(page);
  await page.locator('.modal-actions button.btn-danger').click();
}

test.describe('Rollback modal: Confirm stage', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/hardening');
  });

  // T-RBM-01: the preview a destructive action must show before it runs
  //
  // The three files come from get_checkpoint_detail's fixture: two captured
  // with content, one metadata-only. Both kind labels are asserted because the
  // caveat sentence below only makes sense if the list it explains carries the
  // distinction: a preview that labelled every row identically would render
  // the caveat a lie about its own list.
  test('T-RBM-01: confirm previews the captured files and their kinds', async ({ page }) => {
    await openConfirm(page);

    await expect(page.locator('#rollback-modal-title')).toHaveText(
      "Roll back to 'Pre-hardening checkpoint'?",
    );
    await expect(page.locator('.rollback-sub')).toContainText('Captured');

    const rows = page.locator('.rollback-file-list li');
    await expect(rows).toHaveCount(3);
    await expect(page.locator('.rollback-file-kind')).toHaveCount(3);
    await expect(page.locator('.rollback-file-kind', { hasText: 'content + permissions' }))
      .toHaveCount(2);
    await expect(page.locator('.rollback-file-kind', { hasText: 'permissions only' }))
      .toHaveCount(1);
    await expect(page.locator('.rollback-caveat')).toContainText(
      'permissions restored, not their contents',
    );
    await expect(
      page.locator('.modal-actions button.btn-danger'),
    ).toHaveText('Roll back 3 files');
  });

  // T-RBM-02: Cancel dismisses without running anything
  //
  // The absence half is anchored on the mock's call log rather than on the
  // DOM: a modal that closed while a rollback ran behind it would pass any
  // "the dialog is gone" assertion forever, because a result that never
  // rendered is indistinguishable from a rollback that never started. The log
  // is what turns "closed" into "closed and nothing ran".
  test('T-RBM-02: cancel closes the modal and never invokes run_rollback', async ({ page }) => {
    await openConfirm(page);
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();

    await expect(page.locator('.modal')).toHaveCount(0);
    // The list behind the modal is the same one that was there before.
    await expect(page.getByRole('button', { name: 'Roll back', exact: true })).toHaveCount(3);
    const calls = await page.evaluate(() => window.__mockCalls);
    expect(calls).not.toContain('run_rollback');
  });

  // T-RBM-03: a preview that cannot be read says so, and stays usable
  //
  // The Err arm of the detail fetch (b35a0dcf). The expander under
  // `checkpoint_source=detail_denied` already had T-HIST-15; this is the same
  // rejection arriving in the MODAL, whose buttons must survive it: the
  // checkpoint itself is readable by the restore even when its file list is
  // not, and a modal that only said "loading" would be lying twice.
  test('T-RBM-03: an unreadable preview is named and the rollback is still offered', async ({ page }) => {
    await loadApp(page, '/hardening', 'checkpoint_source=detail_denied');
    await page.getByRole('tab', { name: 'History' }).click();
    await page.getByRole('button', { name: 'Roll back', exact: true }).first().click();

    await expect(page.locator('.rollback-body')).toContainText(
      'captured file list could not be read',
    );
    // The reason goes in its own line rather than the sentence: the sentence
    // is what the operator must decide on, the reason is what they would paste
    // into a bug report.
    await expect(page.locator('.rollback-caveat')).toContainText('Checkpoint not found');
    await expect(page.locator('.modal-actions button.btn-danger'))
      .toHaveText('Roll back without preview');

    // And the offer is honest: confirming still reaches a result. A button
    // that relabelled itself and then did nothing would pass every assertion
    // above.
    await page.locator('.modal-actions button.btn-danger').click();
    await expect(page.locator('.rollback-summary')).toBeVisible({ timeout: 15000 });
  });
});

test.describe('Rollback modal: Restoring and the inert Escape', () => {
  // T-RBM-04: the in-flight stage, held open by the fixture
  //
  // `rollback_mode=hold` parks run_rollback on window.__releaseRollback, so
  // the Restoring stage can be stood in rather than raced: the mock's own
  // 150-350 ms latency resolves in the same tick as the click on faster
  // machines, and a test that waited for "Restoring..." would be asserting a
  // frame it had no right to see.
  //
  // The second half is the one worth pinning: `can_dismiss` must read false
  // while a rollback is in flight, because an Escape that closed the modal
  // mid-restore would report `did_rollback=false` to a parent that is about to
  // refresh a list that no longer matches the host. The release at the end
  // proves the hold was the fixture's doing and the modal still completes.
  test('T-RBM-04: restoring shows its stage and Escape does not dismiss it', async ({ page }) => {
    await loadApp(page, '/hardening', 'rollback_mode=hold');
    await confirmRollback(page);

    await expect(page.locator('.rollback-restoring')).toBeVisible();
    await expect(page.locator('.rollback-progress')).toContainText('Do not close this window');

    await page.keyboard.press('Escape');
    await expect(page.locator('.modal')).toHaveCount(1);
    await expect(page.locator('.rollback-restoring')).toBeVisible();

    // The mock sleeps 150-350 ms before it reaches the `hold` arm that
    // installs the release function, while the Restoring stage renders on
    // the click itself, so the three assertions above pass inside that sleep.
    // First execution (2026-09-02, all six distributions) called the release
    // before it existed: "window.__releaseRollback is not a function".
    await page.waitForFunction(() => typeof window.__releaseRollback === 'function');
    await page.evaluate(() => window.__releaseRollback());
    await expect(page.locator('.rollback-summary')).toBeVisible({ timeout: 15000 });
  });
});

test.describe('Rollback modal: rejection paths', () => {
  // T-RBM-05: a cancelled pkexec prompt is a return, not an error
  //
  // The fixture throws the backend's exact auth-cancel text, because the
  // modal matches it by substring: a paraphrase would pass this test while
  // testing the mock. What is asserted is the full consequence: back on the
  // Confirm stage (the title again), the modal still open, and no banner - an
  // operator who dismissed a polkit prompt has not failed at anything.
  test('T-RBM-05: a cancelled auth prompt returns to Confirm without a banner', async ({ page }) => {
    await loadApp(page, '/hardening', 'rollback_mode=cancelled');
    await confirmRollback(page);

    await expect(page.locator('#rollback-modal-title')).toHaveText(
      "Roll back to 'Pre-hardening checkpoint'?",
    );
    await expect(page.locator('.modal')).toHaveCount(1);
    await expect(page.locator('.error-banner')).toHaveCount(0);
  });

  // T-RBM-06: a real failure closes the modal and names itself in the banner
  //
  // Both halves matter: the banner without the closed modal would leave a
  // dead dialog over a list that no longer matches the host, and the closed
  // modal without the banner would fail in silence, which is the failure mode
  // this application keeps finding in itself. The prefix is the modal's own
  // wording ("Rollback failed: {e}"), so asserting it pins the error reached
  // the state that renders it rather than the browser console.
  test('T-RBM-06: a failed rollback closes the modal and raises the banner', async ({ page }) => {
    await loadApp(page, '/hardening', 'rollback_mode=error');
    await confirmRollback(page);

    await expect(page.locator('.modal')).toHaveCount(0);
    const banner = page.locator('.error-banner');
    await expect(banner).toBeVisible();
    await expect(banner).toContainText('Rollback failed:');
    await expect(banner).toContainText('checkpoint database could not be opened');
  });
});

test.describe('Rollback modal: Result stage', () => {
  test.beforeEach(async ({ page }) => {
    await loadApp(page, '/hardening');
  });

  // T-RBM-07: the success header, the summary, and the reload section
  //
  // The reload section is the part that had NEVER rendered before
  // 2026-09-01: the mock omitted rollback_reloads and serde's default read it
  // empty, so `.rollback-file-list` held only restore rows and no test could
  // have noticed. The kernel row is real in shape: the fixture's restored
  // paths are kernel paths, and the reload a kernel restore triggers is
  // `sysctl --system`.
  test('T-RBM-07: a restored checkpoint reports its summary and its reload', async ({ page }) => {
    await runRollback(page);

    await expect(page.locator('.rollback-outcome.ok h3')).toHaveText('Restored');
    await expect(page.locator('.rollback-outcome')).toHaveClass(/rollback-outcome ok/);
    await expect(page.locator('.rollback-summary')).toContainText('2 of 2 files restored.');
    await expect(page.locator('.rollback-body', { hasText: 'Configuration reload:' }))
      .toBeVisible();
    await expect(page.locator('.rollback-file-list li.restore-ok code', { hasText: 'kernel-hardening' }))
      .toBeVisible();
    await expect(page.locator('.restore-action', { hasText: 'sysctl --system' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Done' })).toBeVisible();
  });

  // T-RBM-08: files all green, header still failed
  //
  // `rollback_mode=reload_failed` restores every file and fails the reload,
  // which poses the `reloads_ok()` half of the header predicate on its own:
  // until this fixture, `rollback_success` false was the only route to the
  // failure header, and a regression that dropped the reload check from the
  // predicate would have passed every existing test while celebrating a
  // rollback whose restored configuration nothing re-read. The file rows being
  // `restore-ok` is what makes this a discrimination test rather than a
  // duplicate of the partial route: the failure must come from the reload.
  test('T-RBM-08: a failed reload fails the header over an all-green file list', async ({ page }) => {
    await loadApp(page, '/hardening', 'rollback_mode=reload_failed');
    await runRollback(page);

    await expect(page.locator('.rollback-outcome.fail h3')).toHaveText('Rollback failed');
    await expect(page.locator('.rollback-outcome')).toHaveClass(/rollback-outcome fail/);
    // Every restore row is green: the failure is the reload's alone.
    await expect(page.locator('.rollback-file-list li.restore-ok code', { hasText: '/etc/sysctl.d/99-hardener.conf' }))
      .toBeVisible();
    await expect(page.locator('.rollback-file-list li.restore-fail')).toHaveCount(1);
    await expect(page.locator('.rollback-file-list li.restore-fail .restore-error'))
      .toContainText('sysctl --system could not be executed');
  });

  // T-RBM-09: Done closes over a refreshed list
  //
  // The parent's on_close(true) exists so the checkpoint list behind the modal
  // refreshes after a rollback changed what the host holds. The refresh
  // itself is the backend's; what a browser test can pin is that Done dismisses
  // into a page whose history section is still alive rather than emptied, and
  // that the dismissal was the modal's own doing (no banner, no leftover
  // backdrop).
  test('T-RBM-09: Done dismisses into a live history section', async ({ page }) => {
    await runRollback(page);
    await page.getByRole('button', { name: 'Done' }).click();

    await expect(page.locator('.modal-backdrop')).toHaveCount(0);
    await expect(page.locator('.error-banner')).toHaveCount(0);
    await expect(page.locator('.history-section')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Roll back', exact: true })).toHaveCount(3);
  });
});
