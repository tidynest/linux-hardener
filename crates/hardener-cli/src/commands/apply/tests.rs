#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`apply`](super).
//!
//! Split out of `commands/apply.rs`. This file sits in the `apply/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::commands::apply` and every import carried
//! across unchanged, private items included.

use super::*;
use hardener_common::executor::{CommandOutput, MockExecutor};
// Only the severity-rule tests need this now: the production code stopped
// matching on Severity when the rule moved onto ValidationReport.
use hardener_common::types::Severity;

/// The gate must ask the executor, not the local process: a non-root
/// test process talking to an executor that reports uid 1000 and denies
/// passwordless sudo must bail with the privilege message, and that
/// message must cover the remote (--ssh) case explicitly.
#[tokio::test]
async fn run_bails_with_privilege_message_when_executor_lacks_privilege() {
    let fail = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 1,
    };
    let executor = Arc::new(
        MockExecutor::new()
            .with_command(
                "id",
                &["-u"],
                CommandOutput {
                    stdout: "1000\n".into(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_command("sudo", &["-n", "true"], fail),
    );

    let err = run(&[], true, false, OutputFormat::Json, true, executor)
        .await
        .expect_err("non-privileged executor must not be allowed to apply");

    let message = err.to_string();
    assert!(
        message.contains("Root privileges required to apply hardening changes"),
        "unexpected message: {message}"
    );
    assert!(
        message.contains("--ssh"),
        "message should mention the remote case: {message}"
    );
}

fn report_with(severity: Severity) -> ValidationReport {
    ValidationReport {
        validation_report_plugin_id: PluginId::new("ssh-hardening"),
        validation_report_is_valid: false,
        validation_report_issues: vec![hardener_core::ValidationIssue {
            validation_issue_severity: severity,
            validation_issue_message: "Failed to read /etc/ssh/sshd_config".to_string(),
            validation_issue_config_key: None,
        }],
        validation_report_estimated_changes: vec![],
        validation_report_compliant_count: 0,
        validation_report_exceptions: vec![],
    }
}

/// `--dry-run` on an unreadable config produced "0 change(s) to apply"
/// and exit 0, which an operator reads as "this host needs nothing".
/// A serious validation issue has to reach the exit code.
#[test]
fn a_serious_validation_issue_fails_the_dry_run() {
    assert!(report_with(Severity::Critical).has_blocking_issue());
    assert!(report_with(Severity::High).has_blocking_issue());
}

/// Advisory severities must not flip the exit code, or the signal becomes
/// noise and operators learn to ignore it.
#[test]
fn an_advisory_validation_issue_does_not_fail_the_dry_run() {
    assert!(!report_with(Severity::Medium).has_blocking_issue());
    assert!(!report_with(Severity::Low).has_blocking_issue());
    assert!(!report_with(Severity::Info).has_blocking_issue());

    let clean = ValidationReport {
        validation_report_issues: vec![],
        validation_report_is_valid: true,
        ..report_with(Severity::High)
    };
    assert!(!clean.has_blocking_issue());
}

#[tokio::test]
async fn apply_host_dry_run_validates_without_mutation() {
    let executor = Arc::new(MockExecutor::new());
    let cfg = HardenerConfig::default();
    let registry = create_plugin_registry();
    let ids: Vec<_> = registry
        .list()
        .unwrap()
        .into_iter()
        .map(|m| m.plugin_id)
        .collect();

    let result = apply_host(
        executor,
        &ids,
        true,
        &cfg,
        None,
        None,
        &OutputFormat::Json,
        true,
    )
    .await;

    assert!(
        result.results.is_empty(),
        "dry-run must not produce apply results"
    );
    // Some plugins may error against a bare MockExecutor (missing files/commands);
    // assert we got at least one validation report and zero apply results.
    assert!(
        !result.validation_reports.is_empty(),
        "dry-run should validate at least one plugin (some plugins error on a bare MockExecutor)"
    );
}

/// `apply` carried its own narrower copy of the enablement rule, reading
/// only `[global] disabled_plugins`. A host whose config turned ssh off in
/// its own section was hardened anyway, and `scan` on that same host had
/// already stopped showing it.
///
/// Neither outcome of running the plugin can pass here: a plugin that
/// validates contributes a report, and one that errors against the bare
/// MockExecutor sets `had_failure`. Only skipping it produces both.
#[tokio::test]
async fn a_section_disabled_plugin_is_skipped_by_apply() {
    let mut config = HardenerConfig::default();
    config.ssh.enabled = false;

    let result = apply_host(
        Arc::new(MockExecutor::new()),
        &[PluginId::new("ssh-hardening")],
        true,
        &config,
        None,
        None,
        &OutputFormat::Json,
        true,
    )
    .await;

    assert!(
        result.validation_reports.is_empty(),
        "a plugin its own section disables must never be validated"
    );
    assert!(
        !result.had_failure,
        "skipping a disabled plugin is not a failure"
    );
    // Named, not merely absent: `run` refuses to exit 0 when this accounts
    // for every plugin the operator selected.
    assert_eq!(result.skipped, vec![PluginId::new("ssh-hardening")]);
}

/// The `[global] enabled_plugins` allow-list is the other half of the same
/// divergence: `scan` narrowed its selection by it while `apply` ignored it
/// entirely, so the two commands disagreed about which plugins the config
/// selects.
#[tokio::test]
async fn a_global_allow_list_narrows_apply_too() {
    let mut config = HardenerConfig::default();
    config.global.enabled_plugins = vec!["kernel-hardening".to_string()];

    let result = apply_host(
        Arc::new(MockExecutor::new()),
        &[PluginId::new("ssh-hardening")],
        true,
        &config,
        None,
        None,
        &OutputFormat::Json,
        true,
    )
    .await;

    assert!(
        result.validation_reports.is_empty(),
        "a plugin absent from a non-empty allow-list must never be validated"
    );
    assert!(!result.had_failure);
}
