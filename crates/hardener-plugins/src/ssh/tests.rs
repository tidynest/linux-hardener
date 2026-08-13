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
/// reported unchecked.
///
/// This is the invariant the whole #159/#166 defect class violates: a plugin
/// declares a control in `coverage()`, some host state makes its evidence
/// unreachable, nothing records that, and the generator passes the control on
/// the mere absence of a finding. `coverage()` and `unchecked_ssh_checks`
/// happen to iterate the same two tables through the same mapping function, so
/// they cannot drift today. A mapping added to `coverage()` from anywhere else
/// would break that quietly, and this is what would notice.
///
/// Lives here rather than in `tests/ssh_mock_tests.rs` because
/// `unchecked_ssh_checks` is private, and the alternative - a `pub` wrapper
/// existing only for a test - puts test scaffolding into the shipped API.
#[test]
fn every_covered_ssh_control_can_be_reported_unchecked() {
    let reportable: std::collections::HashSet<String> =
        unchecked_ssh_checks("read failed", UncheckedBlocker::Environment)
            .into_iter()
            .flat_map(|u| u.unchecked_compliance)
            .map(|m| m.compliance_control_id)
            .collect();

    let covered = coverage();
    assert!(
        !covered.is_empty(),
        "a plugin covering nothing would satisfy the check below without \
         asserting anything, which is the one way this test can go quiet"
    );

    let unreportable: Vec<&str> = covered
        .iter()
        .map(|m| m.compliance_control_id.as_str())
        .filter(|id| !reportable.contains(*id))
        .collect();
    assert!(
        unreportable.is_empty(),
        "declared assessed but mapped by no unchecked entry, so a host where \
         the evidence is unreachable passes them silently: {unreportable:?}"
    );
}
