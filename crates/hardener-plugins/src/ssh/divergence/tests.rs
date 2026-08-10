#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a
// test module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`divergence`].

use super::*;
use hardener_common::executor::{CommandOutput, MockExecutor};
use std::sync::Arc;

/// One host builder, the way `firewall/divergence/tests.rs:26` has one.
/// `active` and `enabled` are the trimmed stdout `systemctl is-active sshd`
/// and `systemctl is-enabled sshd` would print; their exit codes are set the
/// way the real commands set them, non-zero for "inactive"/"disabled"/
/// "masked" alike, because the probe must read the printed word rather than
/// lean on the exit code.
fn sshd_host(active: &str, active_exit: i32, enabled: &str, enabled_exit: i32) -> Context {
    Context::with_executor(Arc::new(
        MockExecutor::new()
            .with_command_exists("systemctl", true)
            .with_command(
                "systemctl",
                &["is-active", "sshd"],
                CommandOutput {
                    stdout: active.to_string(),
                    stderr: String::new(),
                    exit_code: active_exit,
                },
            )
            .with_command(
                "systemctl",
                &["is-enabled", "sshd"],
                CommandOutput {
                    stdout: enabled.to_string(),
                    stderr: String::new(),
                    exit_code: enabled_exit,
                },
            ),
    ))
}

/// #142 as measured on the arch container: sshd stayed `active` across a
/// mask that made the rollback's restart impossible, and the plugin's
/// silence was the gap.
#[tokio::test]
async fn a_masked_and_running_sshd_is_diverged() {
    let ctx = sshd_host("active\n", 0, "masked\n", 1);

    let rows = sshd_divergences(&ctx).await;

    assert_eq!(rows.len(), 1, "one subject, one row");
    assert_eq!(rows[0].divergence_subject, "sshd");
    assert_eq!(rows[0].divergence_state, DivergenceState::Diverged);
    assert!(
        rows[0].divergence_detail.contains("masked"),
        "the reason has to name what proved the restart could not take: {}",
        rows[0].divergence_detail
    );
}

/// A unit that is running and not masked is exactly what a successful
/// restart looks like from the outside, and the probe must not read
/// "running" alone as evidence of anything.
#[tokio::test]
async fn a_running_unmasked_sshd_reports_nothing() {
    let ctx = sshd_host("active\n", 0, "enabled\n", 0);

    assert!(sshd_divergences(&ctx).await.is_empty());
}

/// A masked and STOPPED sshd is serving nothing, so there is nothing there
/// to disagree with the restored file. Paired deliberately with the masked
/// and running case above: getting this backwards would report a divergence
/// on any host where sshd is simply not running.
#[tokio::test]
async fn a_masked_and_stopped_sshd_reports_nothing() {
    let ctx = sshd_host("inactive\n", 3, "masked\n", 1);

    assert!(sshd_divergences(&ctx).await.is_empty());
}

/// A plain stopped-and-unmasked sshd is the ordinary "never running here"
/// host, and is silence for the same reason: nothing is being served.
#[tokio::test]
async fn a_stopped_sshd_reports_nothing() {
    let ctx = sshd_host("inactive\n", 3, "disabled\n", 1);

    assert!(sshd_divergences(&ctx).await.is_empty());
}

/// `systemctl is-active` failing to run at all must not be read as "not
/// running": the probe could not look, and has to say so.
#[tokio::test]
async fn an_unreadable_activity_is_unverifiable() {
    let ctx = Context::with_executor(Arc::new(MockExecutor::new()));

    let rows = sshd_divergences(&ctx).await;

    assert_eq!(rows.len(), 1, "an unrunnable probe is one row, not silence");
    assert_eq!(rows[0].divergence_subject, "sshd");
    assert_eq!(rows[0].divergence_state, DivergenceState::Unverifiable);
}

/// sshd is running, so the mask reading is what decides the answer, and that
/// second command failing to run must not be read as "not masked": the
/// probe could not confirm the restart could take, and has to say so rather
/// than assume the healthy case.
#[tokio::test]
async fn a_running_sshd_with_unreadable_enablement_is_unverifiable() {
    let ctx = Context::with_executor(Arc::new(
        MockExecutor::new()
            .with_command_exists("systemctl", true)
            .with_command(
                "systemctl",
                &["is-active", "sshd"],
                CommandOutput {
                    stdout: "active\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            ),
        // No `is-enabled` registration: execute_command fails outright for
        // that call, distinct from succeeding with a non-zero exit.
    ));

    let rows = sshd_divergences(&ctx).await;

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].divergence_state, DivergenceState::Unverifiable);
}

/// Output that is none of the words this probe recognises for activity is
/// not evidence of anything, and must not be forced into either running or
/// not running.
#[tokio::test]
async fn unrecognised_activity_output_is_unverifiable() {
    let ctx = sshd_host("activating\n", 3, "enabled\n", 0);

    let rows = sshd_divergences(&ctx).await;

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].divergence_state, DivergenceState::Unverifiable);
}

/// `systemctl is-enabled` printing nothing at all, while still exiting, is
/// not evidence that the unit is unmasked: it is evidence this probe could
/// not read the state.
#[tokio::test]
async fn empty_enablement_output_is_unverifiable() {
    let ctx = sshd_host("active\n", 0, "", 1);

    let rows = sshd_divergences(&ctx).await;

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].divergence_state, DivergenceState::Unverifiable);
}

/// `masked-runtime` is `masked` for this boot: the unit cannot be started
/// until the next one. It is therefore the same proof as `masked` that the
/// restart `reload_after_rollback` attempted could not have taken, and it
/// reached this probe as an ordinary unrecognised word, fell to the
/// catch-all, and was read as NOT masked.
///
/// That made it worse than the `service-minimisation` case in #149, which
/// deferred its two `-runtime` words to `Unverifiable`. `Unverifiable` claims
/// nothing. Here the catch-all returns an EMPTY vector, which this codebase
/// reads as "everything checkable came back", so the probe positively
/// asserted that nothing had diverged in exactly the state it exists to
/// catch. A masked-runtime sshd left running is the #142 finding with one
/// word changed.
#[tokio::test]
async fn a_masked_runtime_and_running_sshd_is_diverged() {
    let ctx = sshd_host("active\n", 0, "masked-runtime\n", 1);

    let rows = sshd_divergences(&ctx).await;

    assert_eq!(rows.len(), 1, "one subject, one row");
    assert_eq!(rows[0].divergence_subject, "sshd");
    assert_eq!(
        rows[0].divergence_state,
        DivergenceState::Diverged,
        "masked-runtime refuses starts for this boot exactly as masked does, \
         so a unit still running under it proves the restart could not have \
         taken: {}",
        rows[0].divergence_detail
    );
    assert!(
        rows[0].divergence_detail.contains("masked"),
        "the reason has to name what proved the restart could not take: {}",
        rows[0].divergence_detail
    );
}

/// The other half of the same change, and the reason it is two tests rather
/// than one: a masked-runtime unit that is NOT running must still report
/// nothing. `Activity::NotRunning` short-circuits before the enablement is
/// ever read, so this holds for the same reason `a_masked_and_stopped_sshd`
/// does, and pinning it means widening the Masked arm cannot start reporting
/// a divergence for a stopped unit.
#[tokio::test]
async fn a_masked_runtime_and_stopped_sshd_reports_nothing() {
    let ctx = sshd_host("inactive\n", 3, "masked-runtime\n", 1);

    let rows = sshd_divergences(&ctx).await;

    assert!(
        rows.is_empty(),
        "a stopped unit is not a divergence whatever its masking: {rows:?}"
    );
}
