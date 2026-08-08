#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`output`](super).
//!
//! Split out of `output.rs`. This file sits in the `output/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::output` and every import carried
//! across unchanged, private items included.
//!
//! 408 test lines covering the renderers, which are the surface every CLI verdict reaches the operator through.

use super::*;
use hardener_core::Finding;
use hardener_types::RollbackDivergence;

#[test]
fn test_format_severity_critical() {
    let formatted = format_severity(&Severity::Critical);
    assert!(formatted.to_string().contains("CRIT"));
}

#[test]
fn test_format_severity_high() {
    let formatted = format_severity(&Severity::High);
    assert!(formatted.to_string().contains("HIGH"));
}

#[test]
fn test_format_severity_medium() {
    let formatted = format_severity(&Severity::Medium);
    assert!(formatted.to_string().contains("MED"));
}

#[test]
fn test_format_severity_low() {
    let formatted = format_severity(&Severity::Low);
    assert!(formatted.to_string().contains("LOW"));
}

#[test]
fn test_format_severity_info() {
    let formatted = format_severity(&Severity::Info);
    assert!(formatted.to_string().contains("INFO"));
}

#[test]
fn format_change_error_indents_and_carries_the_message() {
    let line = format_change_error("permission denied writing /etc/sysctl.d/99-hardening.conf");
    assert!(line.starts_with("    "));
    assert!(line.contains("permission denied writing /etc/sysctl.d/99-hardening.conf"));
}

use hardener_core::plugin::{Change, ChangeType, FindingCategory, PluginId};

fn change(change_type: ChangeType, success: bool) -> Change {
    Change {
        change_description: "test change".to_string(),
        change_type,
        change_success: success,
        change_error: (!success).then(|| "nft: command failed".to_string()),
    }
}

fn apply_result(changes: Vec<Change>) -> ApplyResult {
    ApplyResult {
        apply_plugin_id: PluginId::new("firewall-hardening"),
        apply_success: false,
        apply_changes: changes,
        apply_checkpoint_id: None,
        apply_error: None,
    }
}

#[test]
fn apply_summary_reports_failures_numerically() {
    let result = apply_result(vec![
        change(ChangeType::FirewallRule, true),
        change(ChangeType::FirewallRule, false),
        change(ChangeType::FirewallRule, false),
        change(ChangeType::FirewallRule, false),
        change(ChangeType::FirewallRule, false),
        change(ChangeType::Skipped, true),
    ]);
    assert_eq!(
        apply_summary(&result),
        "1 of 5 change(s) applied, 4 failed, 1 skipped"
    );
}

#[test]
fn apply_summary_keeps_plain_wording_when_nothing_failed() {
    let all_good = apply_result(vec![
        change(ChangeType::KernelParameter, true),
        change(ChangeType::KernelParameter, true),
    ]);
    assert_eq!(apply_summary(&all_good), "2 change(s) applied");

    let with_skip = apply_result(vec![
        change(ChangeType::KernelParameter, true),
        change(ChangeType::Skipped, true),
    ]);
    assert_eq!(apply_summary(&with_skip), "1 change(s) applied, 1 skipped");
}

#[test]
fn apply_summary_reads_no_changes_when_only_a_checkpoint() {
    // The sole recorded entry is the rollback checkpoint: nothing was
    // hardened, so the summary must say so rather than "1 change applied".
    let checkpoint_only = apply_result(vec![change(ChangeType::Checkpoint, true)]);
    assert_eq!(apply_summary(&checkpoint_only), "no changes needed");
}

#[test]
fn apply_summary_excludes_checkpoint_from_applied_count() {
    let result = apply_result(vec![
        change(ChangeType::Checkpoint, true),
        change(ChangeType::KernelParameter, true),
        change(ChangeType::KernelParameter, true),
    ]);
    assert_eq!(apply_summary(&result), "2 change(s) applied");
}

fn validation_report(issues: Vec<hardener_core::ValidationIssue>) -> ValidationReport {
    ValidationReport {
        validation_report_plugin_id: PluginId::new("ssh-hardening"),
        validation_report_is_valid: issues.is_empty(),
        validation_report_issues: issues,
        validation_report_estimated_changes: vec![],
        validation_report_compliant_count: 0,
        validation_report_exceptions: vec![],
    }
}

/// The same ambiguity from the other direction: a plugin whose only drift
/// is documented by an exception also reports zero pending changes.
/// Printing the count alone reports a deliberate deviation as an absence.
#[test]
fn validation_lines_surface_settings_left_alone_by_an_exception() {
    let mut report = validation_report(vec![]);
    report.validation_report_exceptions =
        vec!["PermitRootLogin: left at 'yes' (POLICY EXCEPTION: Legacy jump host)".to_string()];

    let lines = validation_report_lines(&report);
    let joined = lines.join("\n");

    assert!(
        joined.contains("PermitRootLogin") && joined.contains("Legacy jump host"),
        "the excepted setting must be printed, got: {joined}"
    );
    assert!(
        joined.contains("0 change(s) to apply"),
        "an exception must not be counted as a pending change, got: {joined}"
    );
}

/// A plugin that could not read its config reports zero pending changes,
/// which is exactly what a host needing none reports. The issue is the
/// only thing distinguishing them, so it must reach the operator.
#[test]
fn validation_lines_surface_issues_not_just_pending_changes() {
    let lines = validation_report_lines(&validation_report(vec![hardener_core::ValidationIssue {
        validation_issue_severity: Severity::High,
        validation_issue_message: "Failed to read /etc/ssh/sshd_config".to_string(),
        validation_issue_config_key: Some("sshd_config".to_string()),
    }]));

    assert!(
        lines
            .iter()
            .any(|l| l.contains("Failed to read /etc/ssh/sshd_config")),
        "the issue must be rendered: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("HIGH")),
        "severity must be shown so a blocking problem is distinguishable: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("sshd_config")),
        "the config key must be shown: {lines:?}"
    );
}

#[test]
fn a_valid_report_renders_unchanged() {
    let lines = validation_report_lines(&validation_report(vec![]));
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("0 change(s) to apply"));
}

#[test]
fn compliant_suffix_only_appears_when_positive() {
    assert_eq!(compliant_suffix(0), "");
    assert_eq!(compliant_suffix(18), " (18 already compliant)");
}

#[test]
fn checkpoint_list_footer_discloses_the_cap() {
    // 25 exist, 20 shown: the footer names both counts and the escape hatch.
    assert_eq!(
        checkpoint_list_footer(20, 25),
        Some("showing 20 of 25; use --all to see all".to_string())
    );
    // Nothing hidden (--all, or a list at/under the limit): no footer.
    assert_eq!(checkpoint_list_footer(25, 25), None);
    assert_eq!(checkpoint_list_footer(0, 0), None);
}

fn metadata(name: &str) -> PluginMetadata {
    PluginMetadata {
        plugin_category: FindingCategory::Audit,
        plugin_description: "test".to_string(),
        plugin_id: PluginId::new("audit-hardening"),
        plugin_name: name.to_string(),
        plugin_version: "0.1.0".to_string(),
    }
}

fn unchecked(id: &str, title: &str) -> UncheckedCheck {
    UncheckedCheck {
        unchecked_check_id: id.to_string(),
        unchecked_title: title.to_string(),
        unchecked_category: FindingCategory::Audit,
        unchecked_reason: "listing loaded audit rules (auditctl -l) requires root".to_string(),
        unchecked_blocker: hardener_types::UncheckedBlocker::Privilege,
        unchecked_compliance: vec![],
    }
}

fn finding(title: &str) -> Finding {
    Finding {
        finding_category: FindingCategory::Audit,
        finding_current_value: "off".to_string(),
        finding_description: "test description".to_string(),
        finding_explanation: String::new(),
        finding_id: "audit-001".to_string(),
        finding_impact: String::new(),
        finding_recommended_value: "on".to_string(),
        finding_remediation_steps: vec![],
        finding_severity: Severity::Medium,
        finding_title: title.to_string(),
        finding_compliance: vec![],
        finding_exception: hardener_types::ExceptionOutcome::NotConfigured,
        finding_exception_key: None,
    }
}

fn scan_result(
    success: bool,
    findings: Vec<Finding>,
    unchecked: Vec<UncheckedCheck>,
) -> ScanResult {
    ScanResult {
        scan_plugin_id: PluginId::new("audit-hardening"),
        scan_success: success,
        scan_findings: findings,
        scan_unchecked: unchecked,
        scan_duration_us: 0,
        scan_error: (!success).then(|| "auditctl -l: permission denied".to_string()),
    }
}

/// The machine-facing half of the same honesty problem. Without these two
/// keys a plugin whose scan failed serialises identically to a compliant
/// one, so every JSON consumer reads a failure as a pass.
#[test]
fn json_entry_carries_scan_success_and_error() {
    let entries = scan_json(&[(
        metadata("Audit Rules Hardening"),
        scan_result(false, vec![], vec![]),
    )]);

    assert_eq!(entries[0]["scan_success"], serde_json::json!(false));
    assert_eq!(
        entries[0]["scan_error"],
        serde_json::json!("auditctl -l: permission denied")
    );

    // A successful scan still says so explicitly, so a consumer can trust
    // the key's presence rather than inferring from its absence.
    let clean = scan_json(&[(
        metadata("Audit Rules Hardening"),
        scan_result(true, vec![], vec![]),
    )]);
    assert_eq!(clean[0]["scan_success"], serde_json::json!(true));
    assert_eq!(clean[0]["scan_error"], serde_json::json!(null));
}

/// A failed scan carries no findings, which is exactly what a compliant
/// host looks like. The terminal must never render that as a tick.
#[test]
fn a_failed_scan_never_renders_as_a_clean_plugin() {
    let lines = scan_plugin_lines(
        &metadata("Audit Rules Hardening"),
        &scan_result(false, vec![], vec![]),
    );

    assert!(
        !lines.iter().any(|l| l.contains("No issues found")),
        "a failed scan must not claim a clean result: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("scan did not complete")),
        "the failure must be stated: {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("auditctl -l: permission denied")),
        "the reason must survive to the operator: {lines:?}"
    );
}

/// A finding the configuration documents as an accepted deviation is not
/// a violation. The terminal rendered it with its severity, byte-identical
/// to a live finding, so an operator could not tell which of their
/// findings their own policy already accounts for. Every other renderer in
/// the project labels it.
#[test]
fn a_policy_excepted_finding_is_not_rendered_as_a_violation() {
    let mut excepted = finding("Root login permitted");
    excepted.finding_exception = hardener_types::ExceptionOutcome::Applied(
        hardener_types::FindingPolicyException::default(),
    );
    let lines = scan_plugin_lines(
        &metadata("Audit Rules Hardening"),
        &scan_result(true, vec![excepted], vec![]),
    );
    let rendered = lines.join("\n");

    assert!(
        rendered.contains(hardener_types::POLICY_EXCEPTION_LABEL),
        "a documented deviation must be labelled: {rendered:?}"
    );
    assert!(
        !rendered.contains("[MED"),
        "a documented deviation must not render as a severity: {rendered:?}"
    );
}

/// A finding whose configured exception did not apply is still a live
/// violation, so it keeps its real severity, but the operator must be told
/// the exception did nothing rather than left to assume it was covered.
#[test]
fn a_declined_exception_gets_its_own_line_and_keeps_its_severity() {
    let mut declined = finding("Root login permitted");
    declined.finding_severity = Severity::High;
    declined.finding_exception =
        hardener_types::ExceptionOutcome::Declined(hardener_types::FindingExceptionDeclined {
            exception_declined_reason: hardener_types::DeclineReason::ValueMismatch {
                documented: "yes".to_string(),
                observed: "prohibit-password".to_string(),
            },
            exception_reason: "legacy jump host".to_string(),
        });
    let lines = scan_plugin_lines(
        &metadata("Audit Rules Hardening"),
        &scan_result(true, vec![declined], vec![]),
    );
    let joined = lines.join("\n");

    assert!(
        joined.contains("exception not applied"),
        "the operator must be told their exception did nothing: {joined}"
    );
    assert!(
        joined.contains("'prohibit-password'"),
        "and what the host actually has: {joined}"
    );
    assert!(
        joined.contains("[HIGH"),
        "a declined finding is live, so it must keep its real severity: {joined}"
    );
    assert!(
        !joined.contains(&format!("[{}]", hardener_types::POLICY_EXCEPTION_LABEL)),
        "a declined finding must not wear the exception label in the severity slot, \
         which is what an applied exception does instead: {joined}"
    );
}

/// A declined finding already carries a `finding_exception_key`, the operator
/// having written the exception at that key already. The hint that tells an
/// operator with no exception how to write one must not also print here: it
/// would tell them to write the exception they already wrote, right next to
/// the line explaining why that exception did not work.
#[test]
fn a_declined_exception_is_not_told_how_to_except_it_again() {
    let mut declined = finding("Root login permitted");
    declined.finding_severity = Severity::High;
    declined.finding_exception_key = Some("permit-root-login".to_string());
    declined.finding_exception =
        hardener_types::ExceptionOutcome::Declined(hardener_types::FindingExceptionDeclined {
            exception_declined_reason: hardener_types::DeclineReason::ValueMismatch {
                documented: "yes".to_string(),
                observed: "prohibit-password".to_string(),
            },
            exception_reason: "legacy jump host".to_string(),
        });
    let lines = scan_plugin_lines(
        &metadata("Audit Rules Hardening"),
        &scan_result(true, vec![declined], vec![]),
    );
    let joined = lines.join("\n");

    assert!(
        !joined.contains("accept as a documented deviation"),
        "an operator whose exception was declined already wrote one; \
         telling them to write it again is telling them to repeat what \
         did not work: {joined}"
    );
    assert!(
        joined.contains("exception not applied"),
        "the declined line must still be present: {joined}"
    );
}

#[test]
fn unchecked_only_plugin_gets_a_named_header_and_deduped_lines() {
    let entries = vec![
        unchecked("audit-time-change", "Audit rule: time-change"),
        unchecked("audit-time-change", "Audit rule: time-change"),
        unchecked("audit-time-change", "Audit rule: time-change"),
        unchecked("audit-time-change", "Audit rule: time-change"),
        unchecked("audit-identity", "Audit rule: identity"),
    ];
    let lines = scan_plugin_lines(
        &metadata("Audit Rules Hardening"),
        &scan_result(true, vec![], entries),
    );

    let header = &lines[0];
    assert!(
        header.contains("Audit Rules Hardening"),
        "header must name the plugin: {header}"
    );
    assert!(
        header.contains("5 check(s) require root; run with sudo for a full scan"),
        "header must keep the honest raw count: {header}"
    );

    let time_change: Vec<_> = lines
        .iter()
        .filter(|l| l.contains("Audit rule: time-change"))
        .collect();
    assert_eq!(time_change.len(), 1, "duplicates must collapse: {lines:?}");
    assert!(
        time_change[0].contains("(x4)"),
        "collapsed line must carry its multiplier: {}",
        time_change[0]
    );
    assert!(
        lines.iter().any(|l| l.contains("Audit rule: identity")),
        "unique entries must survive dedupe: {lines:?}"
    );
}

#[test]
fn mixed_plugin_nests_findings_and_unchecked_under_one_header() {
    let lines = scan_plugin_lines(
        &metadata("PAM Hardening"),
        &scan_result(
            true,
            vec![finding("Password history not enforced")],
            vec![unchecked("pam-minlen", "PAM setting: minlen")],
        ),
    );

    let named: Vec<_> = lines
        .iter()
        .filter(|l| l.contains("PAM Hardening"))
        .collect();
    assert_eq!(named.len(), 1, "exactly one plugin header: {lines:?}");
    assert!(
        lines[0].contains("PAM Hardening"),
        "header first: {lines:?}"
    );
    assert!(lines[0].contains("1 finding(s)"));
    assert!(
        lines
            .iter()
            .any(|l| l.contains("1 check(s) require root; run with sudo for a full scan")),
        "unchecked sub-header nests under the same plugin: {lines:?}"
    );
    assert!(lines.iter().any(|l| l.contains("PAM setting: minlen")));
}

#[test]
fn clean_plugin_line_is_unchanged() {
    let lines = scan_plugin_lines(
        &metadata("SSH Hardening"),
        &scan_result(true, vec![], vec![]),
    );
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("SSH Hardening"));
    assert!(lines[0].contains("No issues found"));
}

/// An exception is keyed per check, and nothing in the interface named that
/// key: a finding's id is derived from it by a transform that loses
/// information, so reading the source was the only way to learn it. The scan
/// is where an operator is looking at the finding they want to keep.
#[test]
fn a_keyed_finding_names_the_exception_that_would_accept_it() {
    let mut keyed = finding("Bluetooth service is enabled");
    keyed.finding_exception_key = Some("bluetooth".to_string());
    let lines = scan_plugin_lines(
        &metadata("Audit Rules Hardening"),
        &scan_result(true, vec![keyed], vec![]),
    );
    let rendered = lines.join("\n");

    assert!(
        rendered.contains(r#"[audit.exceptions."bluetooth"]"#),
        "the scan must name the complete config.toml path an exception needs: {rendered:?}",
    );
}

/// A key with a dot in it is not a bare TOML key. An operator pasting an
/// unquoted net.ipv4.ip_forward would create three nested tables rather than
/// one exception, and the file would parse, so nothing would tell them.
#[test]
fn a_dotted_exception_key_is_quoted() {
    let mut keyed = finding("IP forwarding is enabled");
    keyed.finding_exception_key = Some("net.ipv4.ip_forward".to_string());
    let lines = scan_plugin_lines(
        &metadata("Audit Rules Hardening"),
        &scan_result(true, vec![keyed], vec![]),
    );

    assert!(
        lines.join("\n").contains(r#""net.ipv4.ip_forward""#),
        "a dotted key must be quoted, or it names three tables instead of one key",
    );
}

/// The operator who already wrote one does not need telling how.
#[test]
fn an_already_excepted_finding_is_not_told_how_to_except_it() {
    let mut excepted = finding("Bluetooth service is enabled");
    excepted.finding_exception_key = Some("bluetooth".to_string());
    excepted.finding_exception = hardener_types::ExceptionOutcome::Applied(
        hardener_types::FindingPolicyException::default(),
    );
    let lines = scan_plugin_lines(
        &metadata("Audit Rules Hardening"),
        &scan_result(true, vec![excepted], vec![]),
    );

    assert!(
        !lines.join("\n").contains("exceptions."),
        "a finding already resting on an exception must not be offered another",
    );
}

/// Some findings are not about a value an operator could accept, and offering
/// them an exception would offer a setting that changes nothing.
#[test]
fn a_keyless_finding_is_offered_no_exception() {
    let lines = scan_plugin_lines(
        &metadata("Audit Rules Hardening"),
        &scan_result(
            true,
            vec![finding("PAM directive is unenforceable")],
            vec![],
        ),
    );

    assert!(
        !lines.join("\n").contains("exceptions."),
        "a finding with no exception key must not be offered one",
    );
}

/// An unrecognised plugin has no section to name, and guessing one would send
/// an operator to a table nothing reads.
#[test]
fn an_unknown_plugin_offers_no_exception_path() {
    let mut keyed = finding("Something");
    keyed.finding_exception_key = Some("some-key".to_string());
    let mut meta = metadata("Third Party Plugin");
    meta.plugin_id = PluginId::new("third-party");
    let lines = scan_plugin_lines(&meta, &scan_result(true, vec![keyed], vec![]));

    assert!(
        !lines.join("\n").contains("exceptions."),
        "an unmapped plugin must say nothing rather than guess a section",
    );
}

fn rollback_result_fixture(divergences: Vec<RollbackDivergence>) -> RollbackResult {
    RollbackResult {
        rollback_checkpoint_id: "cp-1".to_string(),
        rollback_checkpoint_name: "before apply".to_string(),
        rollback_success: true,
        rollback_files: Vec::new(),
        rollback_reloads: Vec::new(),
        rollback_divergences: divergences,
    }
}

/// An empty vector prints no header. A rollback with nothing to report must
/// not look eventful.
#[test]
fn a_clean_rollback_prints_no_divergence_block() {
    let result = rollback_result_fixture(Vec::new());

    assert!(divergence_lines(&result).is_empty());
}

/// Both states reach the operator, and each carries its subject and its
/// sentence. A row that printed only the state would send them nowhere.
#[test]
fn each_state_prints_its_subject_and_sentence() {
    let result = rollback_result_fixture(vec![
        RollbackDivergence {
            divergence_plugin_id: "kernel-hardening".to_string(),
            divergence_subject: "net.ipv4.conf.all.log_martians".to_string(),
            divergence_state: DivergenceState::Diverged,
            divergence_detail: "reads 1 and no configuration file names it".to_string(),
        },
        RollbackDivergence {
            divergence_plugin_id: "firewall-hardening".to_string(),
            divergence_subject: "ufw".to_string(),
            divergence_state: DivergenceState::Unverifiable,
            divergence_detail: "ufw status needs root".to_string(),
        },
    ]);

    let lines = divergence_lines(&result);

    let joined = lines.join("\n");
    assert!(joined.contains("net.ipv4.conf.all.log_martians"));
    assert!(joined.contains("diverged"));
    assert!(joined.contains("could not check"));
    assert!(joined.contains("ufw status needs root"));
}
