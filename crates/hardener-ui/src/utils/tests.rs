#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`utils`](super).
//!
//! Split out of `utils/mod.rs`. That file *is* the module `utils`, so its
//! tests go here in the directory it already owns; a `utils/mod/` would
//! resolve to no module at all. `super` is unchanged.

use super::*;
use crate::types::{
    Change, ChangeType, CheckpointInfo, ComplianceSummary, FileRestoreAction, FileRestoreResult,
    Finding, FindingCategory, PluginId, RollbackResult, ScanSessionInfo, Severity,
};

#[test]
fn score_band_boundaries() {
    assert_eq!(score_band(100), ScoreBand::Good);
    assert_eq!(score_band(70), ScoreBand::Good);
    assert_eq!(score_band(69), ScoreBand::Warning);
    assert_eq!(score_band(40), ScoreBand::Warning);
    assert_eq!(score_band(39), ScoreBand::Critical);
    assert_eq!(score_band(0), ScoreBand::Critical);
}

fn session(completed: Option<&str>) -> ScanSessionInfo {
    ScanSessionInfo {
        session_id: "s1".to_string(),
        started_at: "2026-07-22 14:00:00 UTC".to_string(),
        completed_at: completed.map(|s| s.to_string()),
        total_findings: 0,
        total_plugins: 8,
        status: "completed".to_string(),
    }
}

#[test]
fn last_scanned_label_cases() {
    assert_eq!(last_scanned_label(&[]), "Not scanned yet");
    assert_eq!(last_scanned_label(&[session(None)]), "Not scanned yet");
    assert_eq!(
        last_scanned_label(&[session(Some("2026-07-22 14:05:00 UTC"))]),
        "Last scanned 2026-07-22 14:05:00 UTC"
    );
}

fn report(plugin_id: &str, changes: &[&str]) -> ValidationReport {
    ValidationReport {
        validation_report_plugin_id: PluginId::new(plugin_id),
        validation_report_is_valid: true,
        validation_report_issues: vec![],
        validation_report_estimated_changes: changes.iter().map(|c| c.to_string()).collect(),
        validation_report_compliant_count: 0,
        validation_report_exceptions: vec![],
    }
}

fn scan(
    plugin_id: &str,
    success: bool,
    findings: Vec<Finding>,
    unchecked: Vec<hardener_types::UncheckedCheck>,
) -> ScanResult {
    ScanResult {
        scan_plugin_id: PluginId::new(plugin_id),
        scan_success: success,
        scan_findings: findings,
        scan_unchecked: unchecked,
        scan_duration_us: 0,
        scan_error: None,
    }
}

fn a_finding() -> Finding {
    Finding {
        finding_category: FindingCategory::Network,
        finding_current_value: "x".to_string(),
        finding_description: "d".to_string(),
        finding_explanation: "e".to_string(),
        finding_id: "f-1".to_string(),
        finding_impact: "i".to_string(),
        finding_recommended_value: "y".to_string(),
        finding_remediation_steps: vec![],
        finding_severity: Severity::High,
        finding_title: "t".to_string(),
        finding_compliance: vec![],
        finding_policy_exception: None,
    }
}

/// The honesty line had no single predecessor: the score hero said
/// "N check(s) not verified" and the findings tab said
/// "N checks not verifiable without privileges", for the same count on the
/// same host, and the second was false whenever privilege was not the
/// cause. These assertions are the specification of the one line that
/// replaced both, not a regression guard over either.
#[test]
fn honesty_line_names_privilege_only_where_privilege_is_the_answer() {
    let tally = |total: usize, needing_privilege: usize| UncheckedTally {
        total,
        needing_privilege,
    };

    assert_eq!(
        unchecked_honesty_line(tally(3, 3)),
        "3 checks not verifiable without privileges. "
    );
    assert_eq!(
        unchecked_honesty_line(tally(3, 0)),
        "3 checks not verified. "
    );
    assert_eq!(
        unchecked_honesty_line(tally(3, 2)),
        "3 checks not verified, 2 of them for want of privileges. "
    );
}

/// One check is one check, in every arm. The findings tab pluralised and
/// the score hero printed "check(s)"; unifying them must not lose the
/// former.
#[test]
fn honesty_line_says_one_check_in_the_singular() {
    let line = unchecked_honesty_line(UncheckedTally {
        total: 1,
        needing_privilege: 1,
    });
    assert!(
        line.starts_with("1 check "),
        "a single check must not read '1 checks', got: {line}"
    );
    let unreachable = unchecked_honesty_line(UncheckedTally {
        total: 1,
        needing_privilege: 0,
    });
    assert!(
        unreachable.starts_with("1 check "),
        "a single check must not read '1 checks', got: {unreachable}"
    );
}

fn an_unchecked() -> hardener_types::UncheckedCheck {
    hardener_types::UncheckedCheck {
        unchecked_check_id: "u-1".to_string(),
        unchecked_title: "t".to_string(),
        unchecked_category: FindingCategory::Network,
        unchecked_reason: "needs root".to_string(),
        unchecked_needs_privilege: true,
        unchecked_compliance: vec![],
    }
}

/// A plugin whose only drift is documented by a policy exception has no
/// pending changes, which is byte-identical to a host that needs none.
/// Dropping the exception is how the preview came to render a deliberate
/// deviation as an empty panel under "0 changes".
#[test]
fn preview_carries_a_setting_left_alone_by_an_exception() {
    let mut excepted = report("ssh-hardening", &[]);
    excepted.validation_report_exceptions =
        vec!["PermitRootLogin: left at 'yes' (POLICY EXCEPTION: Legacy jump host)".to_string()];
    let scans = [scan("ssh-hardening", true, vec![a_finding()], vec![])];

    let decisions = annotate_preview(&[excepted], &scans);

    assert!(
        decisions[0]
            .exceptions
            .iter()
            .any(|e| e.contains("PermitRootLogin") && e.contains("Legacy jump host")),
        "the excepted setting must survive into the preview, got: {:?}",
        decisions[0].exceptions
    );
    assert!(
        decisions[0].estimated_changes.is_empty(),
        "an exception is not a pending change"
    );
}

#[test]
fn preview_suppresses_plugin_verified_clean_by_scan() {
    let reports = [report("firewall-hardening", &["Enable ufw firewall"])];
    let scans = [scan("firewall-hardening", true, vec![], vec![])];
    let decisions = annotate_preview(&reports, &scans);
    assert_eq!(decisions.len(), 1);
    assert!(decisions[0].verified_compliant);
    assert!(decisions[0].estimated_changes.is_empty());
}

#[test]
fn preview_shows_plugin_with_a_finding() {
    let reports = [report(
        "kernel-hardening",
        &["Set kernel.kptr_restrict = 2"],
    )];
    let scans = [scan("kernel-hardening", true, vec![a_finding()], vec![])];
    let decisions = annotate_preview(&reports, &scans);
    assert!(!decisions[0].verified_compliant);
    assert_eq!(
        decisions[0].estimated_changes,
        vec!["Set kernel.kptr_restrict = 2".to_string()]
    );
}

#[test]
fn preview_shows_plugin_with_an_unchecked_entry() {
    let reports = [report("pam-authentication", &["6 changes"])];
    let scans = [scan(
        "pam-authentication",
        true,
        vec![],
        vec![an_unchecked()],
    )];
    let decisions = annotate_preview(&reports, &scans);
    assert!(!decisions[0].verified_compliant);
    assert_eq!(decisions[0].estimated_changes.len(), 1);
}

#[test]
fn preview_shows_plugin_absent_from_scan() {
    let reports = [report("audit-rules", &["Load audit rules"])];
    let scans = [scan("firewall-hardening", true, vec![], vec![])];
    let decisions = annotate_preview(&reports, &scans);
    assert!(!decisions[0].verified_compliant);
    assert_eq!(decisions[0].estimated_changes.len(), 1);
}

#[test]
fn preview_suppresses_nothing_when_scan_results_empty() {
    let reports = [report("firewall-hardening", &["Enable ufw firewall"])];
    let decisions = annotate_preview(&reports, &[]);
    assert!(!decisions[0].verified_compliant);
    assert_eq!(decisions[0].estimated_changes.len(), 1);
}

#[test]
fn preview_shows_plugin_when_scan_failed_despite_empty_findings() {
    // A failed scan with no findings/unchecked is uncertainty, not proof.
    let reports = [report("mac-system", &["Set SELinux enforcing"])];
    let scans = [scan("mac-system", false, vec![], vec![])];
    let decisions = annotate_preview(&reports, &scans);
    assert!(!decisions[0].verified_compliant);
    assert_eq!(decisions[0].estimated_changes.len(), 1);
}

/// The desktop half of the dry-run honesty problem: a plugin that could
/// not read its config reports no estimated changes, which renders exactly
/// like a host needing none. The issue is the only thing that separates
/// them, so the preview has to carry it.
#[test]
fn preview_carries_validation_issues_to_the_desktop() {
    let mut failed = report("ssh-hardening", &[]);
    failed.validation_report_is_valid = false;
    failed.validation_report_issues = vec![ValidationIssue {
        validation_issue_severity: Severity::High,
        validation_issue_message: "Failed to read /etc/ssh/sshd_config".to_string(),
        validation_issue_config_key: Some("sshd_config".to_string()),
    }];

    let decisions = annotate_preview(&[failed], &[]);

    assert_eq!(decisions[0].issues.len(), 1, "the issue must survive");
    assert_eq!(
        decisions[0].issues[0].validation_issue_message,
        "Failed to read /etc/ssh/sshd_config"
    );
}

/// A scan-verified plugin whose validation still reported an issue must
/// not be presented as compliant: the estimate was not produced from a
/// successful read.
#[test]
fn an_issue_survives_even_when_the_scan_verified_the_plugin() {
    let mut failed = report("ssh-hardening", &[]);
    failed.validation_report_is_valid = false;
    failed.validation_report_issues = vec![ValidationIssue {
        validation_issue_severity: Severity::Critical,
        validation_issue_message: "sshd_config is unreadable".to_string(),
        validation_issue_config_key: None,
    }];
    let scans = [scan("ssh-hardening", true, vec![], vec![])];

    let decisions = annotate_preview(&[failed], &scans);

    assert!(
        !decisions[0].issues.is_empty(),
        "a clean scan must not erase a validation issue"
    );
}

fn change(change_type: ChangeType, success: bool) -> Change {
    Change {
        change_description: "test".to_string(),
        change_type,
        change_success: success,
        change_error: None,
    }
}

fn apply_result(changes: Vec<Change>) -> ApplyResult {
    ApplyResult {
        apply_plugin_id: PluginId::new("test"),
        apply_success: true,
        apply_changes: changes,
        apply_checkpoint_id: None,
        apply_error: None,
    }
}

fn checkpoint(id: &str, created: &str) -> CheckpointInfo {
    CheckpointInfo {
        checkpoint_id: id.to_string(),
        checkpoint_name: format!("cp-{id}"),
        checkpoint_created: created.to_string(),
        checkpoint_user: "root".to_string(),
    }
}

#[test]
fn checkpoint_date_and_time_split_the_stamp() {
    assert_eq!(checkpoint_date("2026-07-22 14:30:05 UTC"), "2026-07-22");
    assert_eq!(checkpoint_time("2026-07-22 14:30:05 UTC"), "14:30:05 UTC");
    assert_eq!(checkpoint_date("weird"), "weird");
    assert_eq!(checkpoint_time("weird"), "");
}

#[test]
fn group_checkpoints_by_date_groups_contiguous_dates_in_order() {
    let cps = vec![
        checkpoint("a", "2026-07-22 14:00:00 UTC"),
        checkpoint("b", "2026-07-22 09:00:00 UTC"),
        checkpoint("c", "2026-07-21 23:00:00 UTC"),
    ];
    let groups = group_checkpoints_by_date(&cps);
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].0, "2026-07-22");
    assert_eq!(groups[0].1.len(), 2);
    assert_eq!(groups[0].1[0].checkpoint_id, "a");
    assert_eq!(groups[1].0, "2026-07-21");
    assert_eq!(groups[1].1.len(), 1);
}

#[test]
fn group_sessions_by_date_groups_contiguous_dates_in_order() {
    let mk = |id: &str, started: &str| ScanSessionInfo {
        session_id: id.to_string(),
        started_at: started.to_string(),
        completed_at: None,
        total_findings: 0,
        total_plugins: 8,
        status: "completed".to_string(),
    };
    let sessions = vec![
        mk("a", "2026-07-22 14:00:00 UTC"),
        mk("b", "2026-07-22 09:00:00 UTC"),
        mk("c", "2026-07-21 23:00:00 UTC"),
    ];
    let groups = group_sessions_by_date(&sessions);
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].0, "2026-07-22");
    assert_eq!(groups[0].1.len(), 2);
    assert_eq!(groups[0].1[0].session_id, "a");
    assert_eq!(groups[1].0, "2026-07-21");
    assert_eq!(groups[1].1.len(), 1);
}

#[test]
fn apply_change_summary_reports_failures_and_skips() {
    let result = apply_result(vec![
        change(ChangeType::KernelParameter, true),
        change(ChangeType::KernelParameter, false),
        change(ChangeType::KernelParameter, false),
        change(ChangeType::Skipped, true),
    ]);
    assert_eq!(
        apply_change_summary(&result),
        "1 changes made, 2 failed, 1 skipped"
    );
}

#[test]
fn apply_change_summary_plain_when_all_succeed() {
    let result = apply_result(vec![
        change(ChangeType::ConfigFile, true),
        change(ChangeType::ConfigFile, true),
    ]);
    assert_eq!(apply_change_summary(&result), "2 changes made");
}

#[test]
fn is_auth_cancelled_matches_backend_text() {
    assert!(is_auth_cancelled(
        "Authentication cancelled. Root privileges are required for this operation."
    ));
}

#[test]
fn is_auth_cancelled_rejects_other_errors() {
    assert!(!is_auth_cancelled("Command failed: exit status 1"));
    assert!(!is_auth_cancelled("No Polkit authentication agent found."));
    assert!(!is_auth_cancelled(""));
}

#[test]
fn parse_rate_limit_wait_secs_reads_wrapped_deep_scan_message() {
    assert_eq!(
        parse_rate_limit_wait_secs(
            "Deep scan failed: Rate limit: please wait 1 seconds before the next \
                 privileged operation."
        ),
        Some(1)
    );
}

#[test]
fn parse_rate_limit_wait_secs_reads_a_different_wait_value() {
    assert_eq!(
        parse_rate_limit_wait_secs(
            "Apply failed: Rate limit: please wait 3 seconds before the next \
                 privileged operation."
        ),
        Some(3)
    );
}

#[test]
fn parse_rate_limit_wait_secs_rejects_unrelated_errors() {
    assert_eq!(
        parse_rate_limit_wait_secs("Command failed: exit status 1"),
        None
    );
}

#[test]
fn parse_rate_limit_wait_secs_rejects_auth_cancelled() {
    assert_eq!(
        parse_rate_limit_wait_secs(
            "Authentication cancelled. Root privileges are required for this operation."
        ),
        None
    );
}

#[test]
fn apply_fully_successful_true_when_all_succeed_with_no_failures() {
    let results = vec![
        apply_result(vec![change(ChangeType::ConfigFile, true)]),
        apply_result(vec![change(ChangeType::KernelParameter, true)]),
    ];
    assert!(apply_fully_successful(&results));
}

#[test]
fn apply_fully_successful_false_on_any_change_failure() {
    let results = vec![
        apply_result(vec![change(ChangeType::ConfigFile, true)]),
        apply_result(vec![change(ChangeType::KernelParameter, false)]),
    ];
    assert!(!apply_fully_successful(&results));
}

#[test]
fn apply_fully_successful_false_when_flag_false_despite_no_change_failures() {
    // apply_success can be false (e.g. a checkpoint-save failure) even
    // with an empty/all-succeeded changes list - the flag must be
    // checked independently of failed_change_count().
    let results = vec![ApplyResult {
        apply_plugin_id: PluginId::new("test"),
        apply_success: false,
        apply_changes: vec![],
        apply_checkpoint_id: None,
        apply_error: Some("checkpoint save failed".to_string()),
    }];
    assert!(!apply_fully_successful(&results));
}

#[test]
fn apply_fully_successful_false_when_empty() {
    assert!(!apply_fully_successful(&[]));
}

#[test]
fn applied_settings_and_areas_counts_only_real_changes() {
    // Brief's hand example: one result with 3 applied, one with 0
    // applied + 2 skipped -> (3, 1).
    let results = vec![
        apply_result(vec![
            change(ChangeType::ConfigFile, true),
            change(ChangeType::KernelParameter, true),
            change(ChangeType::FirewallRule, true),
        ]),
        apply_result(vec![
            change(ChangeType::Skipped, true),
            change(ChangeType::Skipped, true),
        ]),
    ];
    assert_eq!(applied_settings_and_areas(&results), (3, 1));
}

#[test]
fn applied_settings_and_areas_zero_when_nothing_applied() {
    let results = vec![apply_result(vec![change(ChangeType::Skipped, true)])];
    assert_eq!(applied_settings_and_areas(&results), (0, 0));
}

#[test]
fn score_delta_label_reports_increase() {
    assert_eq!(score_delta_label(Some(77), 87), "Up 10 points");
}

#[test]
fn score_delta_label_reports_no_change() {
    assert_eq!(score_delta_label(Some(87), 87), "No change");
}

#[test]
fn score_delta_label_reports_decrease() {
    assert_eq!(score_delta_label(Some(90), 87), "Down 3 points");
}

#[test]
fn score_delta_label_empty_when_no_prior_score() {
    assert_eq!(score_delta_label(None, 87), "");
}

// --- Task 2a.7: apply-outcome classification (RED first) ---

const PAM_MANUAL_MARKER: &str = "inline pam.d override present";

fn manual_step_change() -> Change {
    Change {
        change_description: "PAM: edit the PAM stack manually to set X to Y".to_string(),
        change_type: ChangeType::ConfigFile,
        change_success: false,
        change_error: Some(PAM_MANUAL_MARKER.to_string()),
    }
}

fn failed_change(error: &str) -> Change {
    Change {
        change_description: "a real change".to_string(),
        change_type: ChangeType::ConfigFile,
        change_success: false,
        change_error: Some(error.to_string()),
    }
}

fn apply_result_for(plugin_id: &str, changes: Vec<Change>) -> ApplyResult {
    ApplyResult {
        apply_plugin_id: PluginId::new(plugin_id),
        apply_success: true,
        apply_changes: changes,
        apply_checkpoint_id: None,
        apply_error: None,
    }
}

#[test]
fn is_manual_action_true_for_the_pam_manual_marker() {
    assert!(is_manual_action(&manual_step_change()));
}

#[test]
fn is_manual_action_false_for_a_different_failed_error() {
    assert!(!is_manual_action(&failed_change("permission denied")));
}

#[test]
fn is_manual_action_false_for_a_successful_change() {
    assert!(!is_manual_action(&change(ChangeType::ConfigFile, true)));
}

#[test]
fn classify_applied_when_only_successes() {
    let result = apply_result(vec![change(ChangeType::ConfigFile, true)]);
    assert_eq!(classify_apply_result(&result), ApplyOutcome::Applied);
}

#[test]
fn classify_skipped_when_only_skips() {
    let result = apply_result(vec![change(ChangeType::Skipped, true)]);
    assert_eq!(classify_apply_result(&result), ApplyOutcome::Skipped);
}

#[test]
fn classify_skipped_when_no_changes_at_all() {
    let result = apply_result(vec![]);
    assert_eq!(classify_apply_result(&result), ApplyOutcome::Skipped);
}

#[test]
fn classify_manual_step_when_only_a_manual_failure() {
    let result = apply_result(vec![manual_step_change()]);
    assert_eq!(classify_apply_result(&result), ApplyOutcome::ManualStep);
}

#[test]
fn classify_failed_when_a_genuine_failure_is_present() {
    let result = apply_result(vec![failed_change("permission denied")]);
    assert_eq!(classify_apply_result(&result), ApplyOutcome::Failed);
}

#[test]
fn classify_manual_step_wins_over_an_applied_change_in_the_same_area() {
    // Brief: an applied change AND a manual failure in the same area ->
    // ManualStep (it still needs attention, so Applied cannot mask it).
    let result = apply_result(vec![
        change(ChangeType::ConfigFile, true),
        manual_step_change(),
    ]);
    assert_eq!(classify_apply_result(&result), ApplyOutcome::ManualStep);
}

#[test]
fn classify_failed_dominates_a_manual_failure_in_the_same_area() {
    // Brief: a manual failure AND a real failure in the same area ->
    // Failed - the genuine problem must never hide behind ManualStep.
    let result = apply_result(vec![
        manual_step_change(),
        failed_change("permission denied"),
    ]);
    assert_eq!(classify_apply_result(&result), ApplyOutcome::Failed);
}

#[test]
fn partial_summary_sentence_matches_the_brief_exact_example() {
    // 3 + 4 = 7 applied; firewall's 4 real failures + pam's 3 manual
    // failures = 7 failed; 7 + 7 = 14 settings meant to change.
    let kernel = apply_result_for(
        "kernel-hardening",
        vec![
            change(ChangeType::KernelParameter, true),
            change(ChangeType::KernelParameter, true),
            change(ChangeType::KernelParameter, true),
        ],
    );
    let ssh = apply_result_for(
        "ssh-hardening",
        vec![
            change(ChangeType::ConfigFile, true),
            change(ChangeType::ConfigFile, true),
            change(ChangeType::ConfigFile, true),
            change(ChangeType::ConfigFile, true),
        ],
    );
    let firewall = apply_result_for(
        "firewall-hardening",
        vec![
            failed_change("ufw: command not found"),
            failed_change("ufw: command not found"),
            failed_change("ufw: command not found"),
            failed_change("ufw: command not found"),
        ],
    );
    let pam = apply_result_for(
        "pam-hardening",
        vec![
            manual_step_change(),
            manual_step_change(),
            manual_step_change(),
        ],
    );

    let results = vec![kernel, ssh, firewall, pam];
    assert_eq!(
        partial_summary_sentence(&results),
        "7 of 14 settings applied. Firewall failed, PAM needs a manual step."
    );
}

#[test]
fn partial_summary_sentence_omits_areas_that_succeeded_or_were_skipped() {
    let ssh = apply_result_for("ssh-hardening", vec![change(ChangeType::ConfigFile, true)]);
    let mac = apply_result_for("mac-hardening", vec![change(ChangeType::Skipped, true)]);
    assert_eq!(
        partial_summary_sentence(&[ssh, mac]),
        "1 of 1 settings applied."
    );
}

// --- Task 3: Rollback classification helpers ---

fn restore(action: FileRestoreAction, success: bool) -> FileRestoreResult {
    FileRestoreResult {
        restore_path: "/etc/x".to_string(),
        restore_action: action,
        restore_success: success,
        restore_error: None,
    }
}

#[test]
fn restore_kind_reflects_captured_content() {
    assert_eq!(restore_kind(true), "content + permissions");
    assert_eq!(restore_kind(false), "permissions only");
}

#[test]
fn restore_action_label_covers_all_variants() {
    assert_eq!(
        restore_action_label(FileRestoreAction::Restored),
        "Restored"
    );
    assert_eq!(restore_action_label(FileRestoreAction::Removed), "Removed");
    assert_eq!(
        restore_action_label(FileRestoreAction::PermissionsRestored),
        "Permissions Restored"
    );
    assert_eq!(restore_action_label(FileRestoreAction::Skipped), "Skipped");
}

#[test]
fn rollback_summary_counts_successes_over_total() {
    let result = RollbackResult {
        rollback_checkpoint_id: "cp1".to_string(),
        rollback_checkpoint_name: "before".to_string(),
        rollback_success: false,
        rollback_files: vec![
            restore(FileRestoreAction::Restored, true),
            restore(FileRestoreAction::Restored, true),
            restore(FileRestoreAction::Removed, false),
        ],
    };
    assert_eq!(rollback_summary_sentence(&result), "2 of 3 files restored.");
}

// --- Task 1: Severity grouping and label/class helpers ---

fn finding(id: &str, sev: Severity) -> Finding {
    Finding {
        finding_category: crate::types::FindingCategory::Kernel,
        finding_current_value: "a".to_string(),
        finding_description: "d".to_string(),
        finding_explanation: "e".to_string(),
        finding_id: id.to_string(),
        finding_impact: "i".to_string(),
        finding_recommended_value: "b".to_string(),
        finding_remediation_steps: vec![],
        finding_severity: sev,
        finding_title: "t".to_string(),
        finding_compliance: vec![],
        finding_policy_exception: None,
    }
}

#[test]
fn groups_by_severity_critical_first_skipping_empty() {
    let fs = vec![
        finding("1", Severity::Low),
        finding("2", Severity::Critical),
        finding("3", Severity::Low),
    ];
    let groups = group_findings_by_severity(&fs);
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].0, Severity::Critical);
    assert_eq!(groups[0].1.len(), 1);
    assert_eq!(groups[1].0, Severity::Low);
    assert_eq!(groups[1].1.len(), 2);
}

/// The shipped Compliance view dropped excepted findings outright, so a
/// deviation the operator had documented was invisible: indistinguishable
/// from a finding that never existed. Both halves must survive the split.
#[test]
fn a_documented_deviation_survives_the_split_instead_of_vanishing() {
    let mut excepted = finding("2", Severity::Critical);
    excepted.finding_policy_exception = Some(crate::types::FindingPolicyException::default());
    let fs = vec![finding("1", Severity::High), excepted];

    let (live, deviations) = split_policy_excepted(&fs);
    assert_eq!(live.len(), 1, "live violations: {live:?}");
    assert_eq!(live[0].finding_id, "1");
    assert_eq!(
        deviations.len(),
        1,
        "a documented deviation must not vanish: {deviations:?}"
    );
    assert_eq!(deviations[0].finding_id, "2");
}

/// The input class that blanks a section if a caller gates rendering on
/// the severity groups alone: every finding excepted, so the live half is
/// empty while there is still evidence to show. Both `findings_tab` and
/// `host_panel` gate on both halves because of this. A contract pin, not a
/// regression test: it passes against the fixed split by construction.
#[test]
fn an_all_excepted_host_still_has_evidence_to_render() {
    let mut a = finding("1", Severity::Critical);
    let mut b = finding("2", Severity::Low);
    a.finding_policy_exception = Some(crate::types::FindingPolicyException::default());
    b.finding_policy_exception = Some(crate::types::FindingPolicyException::default());

    let (live, deviations) = split_policy_excepted(&[a, b]);
    assert!(live.is_empty(), "no live violations: {live:?}");
    assert_eq!(
        deviations.len(),
        2,
        "both deviations survive: {deviations:?}"
    );
}

#[test]
fn severity_label_and_class_map() {
    assert_eq!(severity_label(Severity::Critical), "Critical");
    assert_eq!(severity_label(Severity::Info), "Info");
    assert_eq!(severity_class(Severity::High), "severity_high");
    assert_eq!(severity_class(Severity::Low), "severity_low");
}

// --- Task 1.0: Row-strip and ad-hoc helpers (Hosts screen) ---

fn fw_posture(framework: ComplianceFramework, pct: f64) -> FleetFrameworkPosture {
    FleetFrameworkPosture {
        framework,
        summary: ComplianceSummary {
            summary_total_controls: 0,
            summary_passing: 0,
            summary_failing: 0,
            summary_manual_review: 0,
            summary_not_applicable: 0,
            summary_score_percentage: pct,
        },
    }
}

#[test]
fn framework_short_label_maps_the_awkward_ones() {
    assert_eq!(framework_short_label(ComplianceFramework::CIS), "CIS");
    assert_eq!(framework_short_label(ComplianceFramework::NIST), "800-53");
    assert_eq!(
        framework_short_label(ComplianceFramework::NIST800171),
        "800-171"
    );
    assert_eq!(framework_short_label(ComplianceFramework::PCIDSS), "PCI");
    assert_eq!(framework_short_label(ComplianceFramework::ISO27001), "ISO");
}

#[test]
fn framework_score_cells_follows_all_order_and_bands() {
    // Input out of ALL-order: CIS must still come before STIG in the output.
    let compliance = vec![
        fw_posture(ComplianceFramework::STIG, 61.4),
        fw_posture(ComplianceFramework::CIS, 84.0),
    ];
    assert_eq!(
        framework_score_cells(&compliance),
        vec![("CIS", 84, "score-good"), ("STIG", 61, "score-warning")]
    );
}

#[test]
fn framework_score_cells_rounds_then_bands() {
    assert_eq!(
        framework_score_cells(&[fw_posture(ComplianceFramework::PCIDSS, 38.7)]),
        vec![("PCI", 39, "score-critical")]
    );
    assert_eq!(framework_score_cells(&[]), Vec::new());
}

#[test]
fn adhoc_target_error_mirrors_the_backend_guard() {
    assert!(adhoc_target_error("", &[]).is_some());
    assert!(adhoc_target_error("-oProxyCommand=x", &[]).is_some());
    assert!(adhoc_target_error("admin@", &[]).is_some());
    assert!(adhoc_target_error("admin@web-01:2222", &[]).is_none());
    assert!(adhoc_target_error("root@10.242.117.2", &[]).is_none());
    assert!(adhoc_target_error("root@10.242.117.2, scan:22", &[]).is_some());
}

#[test]
fn adhoc_canonical_matches_the_user_host_port_form() {
    assert_eq!(adhoc_canonical("admin@web-01"), "admin@web-01:22");
}

#[test]
fn adhoc_target_error_rejects_a_duplicate_canonical() {
    let existing = vec!["admin@web-01:22".to_string()];
    assert!(adhoc_target_error("admin@web-01:22", &existing).is_some());
}

// --- Task 5b: fleet outcome mappers ---

fn apply_out(status: ApplyStatus) -> FleetApplyOutcome {
    FleetApplyOutcome {
        name: "web-01".to_string(),
        target: "root@web-01:22".to_string(),
        status,
    }
}
fn rollback_out(status: RollbackStatus) -> FleetRollbackOutcome {
    FleetRollbackOutcome {
        name: "web-01".to_string(),
        target: "root@web-01:22".to_string(),
        status,
    }
}

#[test]
fn apply_cells_all_compliant_reads_ok() {
    let v = fleet_apply_cells(&apply_out(ApplyStatus::Validated {
        plugins: 8,
        would_change: 0,
        compliant: 3,
        failed: 0,
    }));
    assert_eq!(v.glyph, OutcomeGlyph::Ok);
    assert_eq!(v.cells, vec![("3 already compliant".to_string(), "")]);
    assert_eq!(v.error, None);
}

#[test]
fn apply_cells_would_change_reads_pending() {
    let v = fleet_apply_cells(&apply_out(ApplyStatus::Validated {
        plugins: 8,
        would_change: 5,
        compliant: 12,
        failed: 0,
    }));
    assert_eq!(v.glyph, OutcomeGlyph::Pending);
    assert_eq!(
        v.cells,
        vec![
            ("5 would change".to_string(), "score-warning"),
            ("12 already compliant".to_string(), ""),
        ]
    );
}

#[test]
fn apply_cells_any_failed_reads_failed_glyph() {
    let v = fleet_apply_cells(&apply_out(ApplyStatus::Validated {
        plugins: 8,
        would_change: 2,
        compliant: 0,
        failed: 1,
    }));
    assert_eq!(v.glyph, OutcomeGlyph::Failed);
    assert_eq!(
        v.cells,
        vec![
            ("2 would change".to_string(), "score-warning"),
            ("1 failed".to_string(), "score-critical"),
        ]
    );
}

#[test]
fn apply_cells_applied_clean() {
    let v = fleet_apply_cells(&apply_out(ApplyStatus::Applied { ok: 5, failed: 0 }));
    assert_eq!(v.glyph, OutcomeGlyph::Ok);
    assert_eq!(v.cells, vec![("5 applied".to_string(), "score-good")]);
}

#[test]
fn apply_cells_applied_with_failures() {
    let v = fleet_apply_cells(&apply_out(ApplyStatus::Applied { ok: 3, failed: 2 }));
    assert_eq!(v.glyph, OutcomeGlyph::Failed);
    assert_eq!(
        v.cells,
        vec![
            ("3 applied".to_string(), "score-good"),
            ("2 failed".to_string(), "score-critical"),
        ]
    );
}

#[test]
fn apply_cells_applied_nothing_shows_muted_fallback() {
    let v = fleet_apply_cells(&apply_out(ApplyStatus::Applied { ok: 0, failed: 0 }));
    assert_eq!(v.glyph, OutcomeGlyph::Ok);
    assert_eq!(v.cells, vec![("No changes".to_string(), "")]);
}

#[test]
fn apply_cells_failed_carries_error_no_cells() {
    let v = fleet_apply_cells(&apply_out(ApplyStatus::Failed {
        error: "connection refused".to_string(),
    }));
    assert_eq!(v.glyph, OutcomeGlyph::Failed);
    assert!(v.cells.is_empty());
    assert_eq!(v.error.as_deref(), Some("connection refused"));
}

#[test]
fn rollback_cells_previewed_reads_pending() {
    let v = fleet_rollback_cells(&rollback_out(RollbackStatus::Previewed { checkpoints: 9 }));
    assert_eq!(v.glyph, OutcomeGlyph::Pending);
    assert_eq!(
        v.cells,
        vec![("9 checkpoints would restore".to_string(), "")]
    );
}

#[test]
fn rollback_cells_previewed_zero_reads_nothing() {
    let v = fleet_rollback_cells(&rollback_out(RollbackStatus::Previewed { checkpoints: 0 }));
    assert_eq!(v.glyph, OutcomeGlyph::Ok);
    assert_eq!(v.cells, vec![("Nothing to roll back".to_string(), "")]);
}

#[test]
fn rollback_cells_rolled_back_clean() {
    let v = fleet_rollback_cells(&rollback_out(RollbackStatus::RolledBack {
        restored: 9,
        failed: 0,
    }));
    assert_eq!(v.glyph, OutcomeGlyph::Ok);
    assert_eq!(v.cells, vec![("9 restored".to_string(), "score-good")]);
}

#[test]
fn rollback_cells_rolled_back_with_failures() {
    let v = fleet_rollback_cells(&rollback_out(RollbackStatus::RolledBack {
        restored: 4,
        failed: 2,
    }));
    assert_eq!(v.glyph, OutcomeGlyph::Failed);
    assert_eq!(
        v.cells,
        vec![
            ("4 restored".to_string(), "score-good"),
            ("2 failed".to_string(), "score-critical"),
        ]
    );
}

#[test]
fn rollback_cells_rolled_back_nothing_shows_muted_fallback() {
    let v = fleet_rollback_cells(&rollback_out(RollbackStatus::RolledBack {
        restored: 0,
        failed: 0,
    }));
    assert_eq!(v.glyph, OutcomeGlyph::Ok);
    assert_eq!(v.cells, vec![("Nothing restored".to_string(), "")]);
}

#[test]
fn rollback_cells_nothing_to_do() {
    let v = fleet_rollback_cells(&rollback_out(RollbackStatus::NothingToDo));
    assert_eq!(v.glyph, OutcomeGlyph::Ok);
    assert_eq!(v.cells, vec![("Nothing to roll back".to_string(), "")]);
}

#[test]
fn rollback_cells_failed_carries_error() {
    let v = fleet_rollback_cells(&rollback_out(RollbackStatus::Failed {
        error: "no checkpoint".to_string(),
    }));
    assert_eq!(v.glyph, OutcomeGlyph::Failed);
    assert!(v.cells.is_empty());
    assert_eq!(v.error.as_deref(), Some("no checkpoint"));
}

#[test]
fn apply_aggregate_sums_would_change_over_hosts() {
    let outcomes = vec![
        apply_out(ApplyStatus::Validated {
            plugins: 8,
            would_change: 5,
            compliant: 0,
            failed: 0,
        }),
        apply_out(ApplyStatus::Validated {
            plugins: 8,
            would_change: 7,
            compliant: 0,
            failed: 0,
        }),
    ];
    assert_eq!(
        fleet_apply_aggregate(&outcomes),
        "~12 changes across 2 hosts"
    );
}

#[test]
fn apply_aggregate_singular_host() {
    let outcomes = vec![apply_out(ApplyStatus::Validated {
        plugins: 8,
        would_change: 3,
        compliant: 0,
        failed: 0,
    })];
    assert_eq!(fleet_apply_aggregate(&outcomes), "~3 changes across 1 host");
}

#[test]
fn rollback_aggregate_sums_checkpoints_over_hosts() {
    let outcomes = vec![
        rollback_out(RollbackStatus::Previewed { checkpoints: 9 }),
        rollback_out(RollbackStatus::Previewed { checkpoints: 0 }),
    ];
    assert_eq!(
        fleet_rollback_aggregate(&outcomes),
        "9 checkpoints will restore across 2 hosts"
    );
}

// --- Task 5c: scheduler preset/cron helpers ---

#[test]
fn preset_cron_maps_known_and_unknown() {
    assert_eq!(preset_cron("Daily at 2:00 AM"), Some("0 0 2 * * *"));
    assert_eq!(preset_cron("nope"), None);
}

#[test]
fn preset_label_for_cron_reverse_maps() {
    assert_eq!(
        preset_label_for_cron("0 0 */6 * * *"),
        Some("Every 6 hours")
    );
    assert_eq!(preset_label_for_cron("0 0 2 5 * *"), None);
}

#[test]
fn effective_cron_custom_overrides_preset() {
    assert_eq!(
        effective_schedule_cron("Daily at 2:00 AM", "0 30 3 * * *"),
        "0 30 3 * * *"
    );
}

#[test]
fn effective_cron_falls_back_to_preset_when_custom_empty() {
    assert_eq!(
        effective_schedule_cron("Every 12 hours", ""),
        "0 0 */12 * * *"
    );
}

#[test]
fn effective_cron_empty_when_neither_resolves() {
    assert_eq!(effective_schedule_cron("unknown", ""), "");
}

#[test]
fn preset_round_trips() {
    for (label, _) in SCHEDULE_PRESETS {
        assert_eq!(
            preset_label_for_cron(preset_cron(label).unwrap()),
            Some(*label)
        );
    }
}
