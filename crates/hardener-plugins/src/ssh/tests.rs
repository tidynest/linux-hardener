#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`ssh`].
//!
//! Split out of `ssh.rs`. This file sits in the `ssh/` directory beside it,
//! so `super` still resolves to `crate::ssh` and every import carried across
//! unchanged, private items included.

use super::*;
use hardener_core::MockExecutor;
use std::sync::Arc;

/// The guard at the top of `divergences_after_rollback` is deletable in
/// silence unless something exercises it directly: with the guard removed by
/// hand, `cargo test -p hardener-plugins` still passed, because the generic
/// self-scoping probe in `reload_tests.rs` exercises only a stub, never this
/// plugin's own predicate. Both halves are asserted, because the empty-result
/// half alone would also pass against a probe that can never report anything.
/// No `systemctl` command is registered on the mock, so `is-active sshd`
/// fails outright, which is the cheapest reliable way to make the owned-path
/// half produce a row.
#[tokio::test]
async fn ssh_divergences_after_rollback_is_scoped_to_restored_ssh_paths() {
    let ctx = Context::with_executor(Arc::new(MockExecutor::new()));
    let plugin = SshHardeningPlugin::new();

    let unrelated = plugin
        .divergences_after_rollback(&ctx, &[std::path::PathBuf::from("/etc/audit/audit.rules")])
        .await;
    assert!(
        unrelated.is_empty(),
        "no restored path was under /etc/ssh, so the probe must not have run"
    );

    let owned = plugin
        .divergences_after_rollback(&ctx, &[std::path::PathBuf::from(SSHD_ADMIN_CONFIG_PATH)])
        .await;
    assert!(
        !owned.is_empty(),
        "a restored path under /etc/ssh must let the probe run"
    );
}

/// Ties the predicate to the constants `apply` actually checkpoints, so the
/// two cannot drift apart unnoticed. Asserted against the constants
/// themselves, not their literal values: `tests/ssh_mock_tests.rs` compiles
/// as a separate crate and cannot see `SSHD_ADMIN_CONFIG_PATH` or
/// `dropin::DROPIN_PATH` (both are private), so a copy of this test living
/// there had to assert on string literals instead - which stayed green
/// through a change to either constant's value, catching nothing. This file
/// sits inside `crate::ssh`, where both names are visible, so a rename or a
/// value change fails here instead of passing silently.
#[test]
fn every_path_ssh_checkpoints_is_one_it_reloads_for() {
    let plugin = SshHardeningPlugin::new();
    for path in [SSHD_ADMIN_CONFIG_PATH, dropin::DROPIN_PATH] {
        assert!(
            plugin.reloads_for_path(Path::new(path)),
            "ssh checkpoints {path} but would not reload for it"
        );
    }
}

/// Every control this plugin declares assessed must have a route to being
/// reported unchecked. See
/// [`crate::tests::assert_every_covered_control_is_reportable`] for why.
///
/// Nothing is excused here. `unchecked_ssh_checks` iterates the same two tables
/// through the same mapping function as `coverage()`, so every declared control
/// is reachable by construction; this is what would notice a mapping added from
/// anywhere else.
///
/// Lives here rather than in `tests/ssh_mock_tests.rs` because
/// `unchecked_ssh_checks` is private, and the alternative - a `pub` wrapper
/// existing only for a test - puts test scaffolding into the shipped API.
// assertions-in-helper: the invariant has one definition, in
// crate::tests::assert_every_covered_control_is_reportable, so that eight
// plugins state it once rather than eight times. Both of its assertions,
// including the two vacuity guards, fire from there.
#[test]
fn every_covered_ssh_control_can_be_reported_unchecked() {
    crate::tests::assert_every_covered_control_is_reportable(
        "ssh",
        &coverage(),
        &unchecked_ssh_checks("read failed", UncheckedBlocker::Environment),
        &[],
    );
}
