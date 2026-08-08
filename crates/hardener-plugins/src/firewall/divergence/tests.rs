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
use hardener_common::executor::{CommandOutput, MockExecutor};
use std::sync::Arc;

/// `ufw status` on a host that carries any rules, which is the shape this
/// probe exists to read: the status line, a blank line, the `To / Action /
/// From` header, its separator, and at least one rule row.
const UFW_STATUS_ACTIVE_WITH_RULES: &str = "Status: active\n\
\n\
To                         Action      From\n\
--                         ------      ----\n\
22/tcp                     ALLOW       Anywhere\n\
22/tcp (v6)                ALLOW       Anywhere (v6)\n";

fn ufw_host(status: &str, conf: &str) -> Context {
    Context::with_executor(Arc::new(
        MockExecutor::new()
            .with_command_exists("ufw", true)
            .with_command_exists("firewall-cmd", false)
            .with_command_exists("nft", false)
            .with_command(
                "ufw",
                &["status"],
                CommandOutput {
                    stdout: status.to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_file("/etc/ufw/ufw.conf", conf),
    ))
}

/// #139 as measured on the arch container: /etc/ufw came back byte for byte
/// and ufw is still enforcing.
#[tokio::test]
async fn a_live_ufw_over_a_disabled_config_is_reported() {
    let ctx = ufw_host(UFW_STATUS_ACTIVE_WITH_RULES, "ENABLED=no\n");

    let rows = firewall_divergences(&ctx).await;

    assert_eq!(rows.len(), 1, "one subject, one row");
    assert_eq!(rows[0].divergence_subject, "ufw");
    assert_eq!(rows[0].divergence_state, DivergenceState::Diverged);
    assert!(
        rows[0].divergence_detail.contains("reboot"),
        "the consequence is what the operator acts on: {}",
        rows[0].divergence_detail
    );
}

/// The opposite direction is a weaker host than its own files describe, and
/// is reported just as loudly.
#[tokio::test]
async fn a_stopped_ufw_over_an_enabled_config_is_reported() {
    let ctx = ufw_host("Status: inactive\n", "ENABLED=yes\n");

    let rows = firewall_divergences(&ctx).await;

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].divergence_state, DivergenceState::Diverged);
}

/// Agreement is silence. `Status: inactive` must not match on the substring
/// "active", which is the shell bug this project has already been bitten by.
#[tokio::test]
async fn a_host_whose_state_matches_its_config_reports_nothing() {
    let ctx = ufw_host("Status: inactive\n", "ENABLED=no\n");

    assert!(firewall_divergences(&ctx).await.is_empty());
}

/// `ufw status` needs root. An unprivileged rollback must say it could not
/// look rather than say nothing.
#[tokio::test]
async fn an_unreadable_config_is_unverifiable() {
    let ctx = Context::with_executor(Arc::new(
        MockExecutor::new()
            .with_command_exists("ufw", true)
            .with_command_exists("firewall-cmd", false)
            .with_command_exists("nft", false)
            .with_command(
                "ufw",
                &["status"],
                CommandOutput {
                    stdout: UFW_STATUS_ACTIVE_WITH_RULES.to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_read_permission_denied("/etc/ufw/ufw.conf"),
    ));

    let rows = firewall_divergences(&ctx).await;

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].divergence_state, DivergenceState::Unverifiable);
}

/// A probe that cannot run must not be read as "not enforcing". A host whose
/// `ufw status` fails outright, while the restored config says ENABLED=yes,
/// must report that the running state is unknown rather than assert a
/// divergence it never measured.
#[tokio::test]
async fn a_failed_status_probe_is_unverifiable_not_diverged() {
    let ctx = Context::with_executor(Arc::new(
        MockExecutor::new()
            .with_command_exists("ufw", true)
            .with_command_exists("firewall-cmd", false)
            .with_command_exists("nft", false)
            .with_command(
                "ufw",
                &["status"],
                CommandOutput {
                    stdout: String::new(),
                    stderr: "ufw: permission denied".to_string(),
                    exit_code: 1,
                },
            )
            .with_file("/etc/ufw/ufw.conf", "ENABLED=yes\n"),
    ));

    let rows = firewall_divergences(&ctx).await;

    assert_eq!(rows.len(), 1, "a failed reading is one row, not silence");
    assert_eq!(rows[0].divergence_state, DivergenceState::Unverifiable);
    assert!(
        rows.iter()
            .all(|r| r.divergence_state != DivergenceState::Diverged),
        "an unread running state must never be reported as a measured divergence"
    );
}

/// Output that is neither of the two lines ufw actually prints is not
/// evidence of anything, and must not be forced into either enforcing or
/// not-enforcing.
#[tokio::test]
async fn unrecognised_status_output_is_unverifiable() {
    let ctx = ufw_host("Status: unknown\n", "ENABLED=yes\n");

    let rows = firewall_divergences(&ctx).await;

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].divergence_state, DivergenceState::Unverifiable);
}

/// `ufw status` can succeed and still print nothing that looks like a status
/// line at all, distinct from printing one that does not match either known
/// value. That output is not evidence that ufw is enforcing, nor that it is
/// not: it is evidence that this probe could not read the state, and must be
/// reported as unverifiable rather than defaulted to either side.
#[tokio::test]
async fn a_status_output_with_no_status_line_is_unverifiable() {
    let ctx = ufw_host("", "ENABLED=yes\n");

    let rows = firewall_divergences(&ctx).await;

    assert_eq!(rows.len(), 1, "one subject, one row");
    assert_eq!(rows[0].divergence_state, DivergenceState::Unverifiable);
    assert!(
        rows.iter()
            .all(|r| r.divergence_state != DivergenceState::Diverged),
        "an unread running state must never be reported as a measured divergence"
    );
}

/// #139's own scenario, pinned by name. A host that carries any rules, which
/// is this probe's whole reason for existing, prints `ufw status` as several
/// lines. Matching the entire trimmed output against `Status: active` reads
/// exactly this host as unverifiable instead of diverged; this must fail
/// against the code that does that, and pass once the status line alone is
/// what gets compared.
#[tokio::test]
async fn a_multiline_active_ufw_over_a_disabled_config_diverges() {
    let ctx = ufw_host(UFW_STATUS_ACTIVE_WITH_RULES, "ENABLED=no\n");

    let rows = firewall_divergences(&ctx).await;

    assert_eq!(rows.len(), 1, "one subject, one row");
    assert_eq!(
        rows[0].divergence_state,
        DivergenceState::Diverged,
        "a live ufw carrying rules must not be read as unverifiable just \
         because its status output has more than one line: {:?}",
        rows[0].divergence_detail
    );
}

/// The `Err` arm of `read_live_enforcement`, the one sub-path of
/// `Unverifiable` this file had not exercised: the command fails to execute
/// at all, distinct from running and exiting non-zero.
#[tokio::test]
async fn a_status_probe_that_cannot_be_run_is_unverifiable() {
    let ctx = Context::with_executor(Arc::new(
        MockExecutor::new()
            .with_command_exists("ufw", true)
            .with_command_exists("firewall-cmd", false)
            .with_command_exists("nft", false)
            .with_file("/etc/ufw/ufw.conf", "ENABLED=yes\n"),
        // No `.with_command("ufw", &["status"], ..)` registration: the mock
        // executor returns `Err` for a program/argument pair nothing has
        // registered, which is how `execute_command` fails outright rather
        // than returning a non-zero exit.
    ));

    let rows = firewall_divergences(&ctx).await;

    assert_eq!(rows.len(), 1, "an unrunnable probe is one row, not silence");
    assert_eq!(rows[0].divergence_state, DivergenceState::Unverifiable);
}

/// firewalld restores a directory its daemon re-reads, so the reload
/// converges it and this probe has nothing to add.
#[tokio::test]
async fn a_firewalld_host_produces_no_rows() {
    let ctx = Context::with_executor(Arc::new(
        MockExecutor::new()
            .with_command_exists("firewall-cmd", true)
            .with_command_exists("ufw", false)
            .with_command_exists("nft", false)
            .with_command(
                "firewall-cmd",
                &["--state"],
                CommandOutput {
                    stdout: "running\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            ),
    ));

    assert!(firewall_divergences(&ctx).await.is_empty());
}

/// No backend detected at all: `ufw`, `firewall-cmd` and `nft` are all
/// absent. There is no configuration for the host to disagree with, so this
/// is silence, the same as the firewalld case above, not a fourth outcome.
#[tokio::test]
async fn a_host_with_no_firewall_backend_produces_no_rows() {
    let ctx = Context::with_executor(Arc::new(
        MockExecutor::new()
            .with_command_exists("ufw", false)
            .with_command_exists("firewall-cmd", false)
            .with_command_exists("nft", false),
    ));

    assert!(firewall_divergences(&ctx).await.is_empty());
}
