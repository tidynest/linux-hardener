#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`divergence`].

use super::*;
use hardener_common::executor::MockExecutor;
use std::sync::Arc;

/// The probe reads `/proc/sys` for the parameter and `/etc/sysctl.d` for what
/// still names it. A mock carrying neither is the "nothing to say" baseline.
fn ctx_with(mock: MockExecutor) -> Context {
    Context::with_executor(Arc::new(mock))
}

/// #138 exactly: the value the apply set is still in the running kernel and
/// no surviving file names it, so the reload had nothing to read.
#[tokio::test]
async fn a_runtime_value_no_file_names_is_reported() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter must be reported");
    assert_eq!(row.divergence_state, DivergenceState::Diverged);
    assert!(
        row.divergence_detail
            .contains("no configuration file names it"),
        "the sentence must state the measured fact: {}",
        row.divergence_detail
    );
}

/// A surviving file naming the pre-apply value is the case
/// `verify-rollback.sh` seeds today, and it must produce no row at all.
#[tokio::test]
async fn a_value_a_surviving_file_names_is_not_reported() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/00-baseline.conf",
                "net.ipv4.conf.all.log_martians = 0\n",
            )
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "0\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    assert!(
        !rows
            .iter()
            .any(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians"),
        "the configuration and the running kernel agree, so there is nothing to say"
    );
}

/// A file naming a different value from the one running is a divergence in
/// its own right, and the sentence carries both numbers so the operator does
/// not have to go and look.
#[tokio::test]
async fn a_file_disagreeing_with_the_running_kernel_is_reported_with_both_values() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/00-baseline.conf",
                "net.ipv4.conf.all.log_martians = 0\n",
            )
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("a disagreement must be reported");
    assert_eq!(row.divergence_state, DivergenceState::Diverged);
    assert!(row.divergence_detail.contains('0') && row.divergence_detail.contains('1'));
}

/// An unreadable `/proc/sys` says nothing about the host, and must not be
/// recorded as agreement. This is the container case: nspawn mounts
/// `/proc/sys` read-only and the host's own values show through.
#[tokio::test]
async fn an_unreadable_runtime_value_is_unverifiable_rather_than_silent() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_read_permission_denied("/proc/sys/net/ipv4/conf/all/log_martians"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("an unreadable probe must still produce a row");
    assert_eq!(row.divergence_state, DivergenceState::Unverifiable);
}

/// A glob-assigning file may or may not name a parameter. Reporting it as
/// "no file names this" would turn an unanswered question into a claim.
///
/// The row that matters is the parameter's own: a generic "something is
/// unresolved" row would pass even if the per-parameter loop went on to emit
/// a confident `Diverged` claim for the very parameter the glob might name,
/// which is exactly how #138's false claim slipped through review once.
#[tokio::test]
async fn a_glob_assigning_file_makes_the_answer_unverifiable() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_file(
                "/etc/sysctl.d/99-glob.conf",
                "net.ipv4.conf.*.log_martians = 1\n",
            )
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    let row = rows
        .iter()
        .find(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians")
        .expect("the parameter a glob might name must carry its own row");
    assert_eq!(
        row.divergence_state,
        DivergenceState::Unverifiable,
        "an unresolved glob might name this parameter, so a Diverged claim is unearned: {}",
        row.divergence_detail
    );
    assert!(
        !rows
            .iter()
            .any(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians"
                && r.divergence_state == DivergenceState::Diverged),
        "no Diverged row may exist for a parameter an unresolved source might name"
    );
}

/// Classification row five: nothing names the parameter, and the running
/// value is looser than the baseline. An operator who deliberately loosened
/// below the baseline has left little for a rollback to have undone, so this
/// case produces no row at all, even with an empty `/etc/sysctl.d`. A
/// regression that dropped the `!` from the strictness guard, or that pushed
/// a row regardless of strictness, would still pass every other test here.
#[tokio::test]
async fn nothing_names_it_and_runtime_is_looser_produces_no_row() {
    let ctx = ctx_with(
        MockExecutor::new()
            .with_directory("/etc/sysctl.d")
            .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "0\n"),
    );

    let rows = sysctl_divergences(&ctx).await;

    assert!(
        !rows
            .iter()
            .any(|r| r.divergence_subject == "net.ipv4.conf.all.log_martians"),
        "a value looser than the baseline that nothing names is not this rollback's doing"
    );
}
