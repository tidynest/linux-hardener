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
    Change, ChangeType, CheckpointDetail, CheckpointFileInfo, CheckpointInfo, ComplianceSummary,
    ControlStatus, DivergenceState, ExceptionOutcome, FileRestoreAction, FileRestoreResult,
    Finding, FindingCategory, PluginId, RollbackDivergence, RollbackResult, ScanResult,
    ScanSessionInfo, Severity, WrittenException,
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
        finding_exception: ExceptionOutcome::NotConfigured,
        finding_exception_key: None,
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
        unchecked_blocker: hardener_types::UncheckedBlocker::Privilege,
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
        // Not what the grouping tests measure; they only read the stamp.
        checkpoint_verified: true,
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

fn rollback_result_with(divergences: Vec<RollbackDivergence>) -> RollbackResult {
    RollbackResult {
        rollback_checkpoint_id: "cp1".to_string(),
        rollback_checkpoint_name: "before".to_string(),
        rollback_success: true,
        rollback_files: Vec::new(),
        rollback_reloads: Vec::new(),
        rollback_divergences: divergences,
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
        rollback_reloads: Vec::new(),
        rollback_divergences: Vec::new(),
    };
    assert_eq!(rollback_summary_sentence(&result), "2 of 3 files restored.");
}

/// A clean rollback's sentence is unchanged, so the ordinary case does not
/// grow a clause about nothing.
#[test]
fn a_clean_rollback_sentence_is_unchanged() {
    let result = rollback_result_with(Vec::new());

    assert_eq!(rollback_summary_sentence(&result), "0 of 0 files restored.");
}

/// A divergence is named in the summary, because the modal's file list is
/// where an operator's eye goes last and this is the part that changes what
/// they do next.
///
/// Exact match, not `contains`: "1 divergence" is a substring of
/// "1 divergences reported." too, so a `contains` assertion here would still
/// pass if the singular arm were merged into the plural one.
#[test]
fn a_divergence_is_named_in_the_summary() {
    let result = rollback_result_with(vec![RollbackDivergence {
        divergence_plugin_id: "firewall-hardening".to_string(),
        divergence_subject: "ufw".to_string(),
        divergence_state: DivergenceState::Diverged,
        divergence_detail: "ufw is enforcing while its config says ENABLED=no".to_string(),
        divergence_expected: None,
    }]);

    assert_eq!(
        rollback_summary_sentence(&result),
        "0 of 0 files restored. 1 divergence reported."
    );
}

/// Two or more divergences pluralise the clause. Exact match for the same
/// reason as the singular case above: a substring check would not catch the
/// wrong word or a dropped/miscounted digit.
#[test]
fn two_divergences_pluralise_the_summary_clause() {
    let result = rollback_result_with(vec![
        RollbackDivergence {
            divergence_plugin_id: "firewall-hardening".to_string(),
            divergence_subject: "ufw".to_string(),
            divergence_state: DivergenceState::Diverged,
            divergence_detail: "ufw is enforcing while its config says ENABLED=no".to_string(),
            divergence_expected: None,
        },
        RollbackDivergence {
            divergence_plugin_id: "ssh-hardening".to_string(),
            divergence_subject: "sshd".to_string(),
            divergence_state: DivergenceState::Diverged,
            divergence_detail: "sshd is running with PermitRootLogin yes".to_string(),
            divergence_expected: None,
        },
    ]);

    assert_eq!(
        rollback_summary_sentence(&result),
        "0 of 0 files restored. 2 divergences reported."
    );
}

fn divergence_row(state: DivergenceState) -> RollbackDivergence {
    RollbackDivergence {
        divergence_plugin_id: "pam-hardening".to_string(),
        divergence_subject: "/etc/pam.d/system-auth".to_string(),
        divergence_state: state,
        divergence_detail: "config unreadable after restore".to_string(),
        divergence_expected: None,
    }
}

/// A row the probe could not answer is named apart from a measured
/// divergence, using the doc comment's own words for it: "Not a claim that
/// anything is wrong." A summary that folded it into "divergences" would
/// make that claim anyway.
///
/// Exact match for the same reason as the diverged-only cases above.
#[test]
fn an_unverifiable_row_is_named_apart_from_a_divergence() {
    let result = rollback_result_with(vec![divergence_row(DivergenceState::Unverifiable)]);

    assert_eq!(
        rollback_summary_sentence(&result),
        "0 of 0 files restored. 1 unchecked reported."
    );
}

/// Two unverifiable rows pluralise the same way a plural divergence count
/// does.
#[test]
fn two_unverifiable_rows_pluralise_the_summary_clause() {
    let result = rollback_result_with(vec![
        divergence_row(DivergenceState::Unverifiable),
        divergence_row(DivergenceState::Unverifiable),
    ]);

    assert_eq!(
        rollback_summary_sentence(&result),
        "0 of 0 files restored. 2 unchecked reported."
    );
}

/// Both kinds together, plural forms of each: the divergence clause comes
/// first, the unchecked clause second, joined by a comma, in the shape the
/// maintainer approved for both surfaces.
#[test]
fn diverged_and_unverifiable_rows_both_appear_in_the_summary() {
    let result = rollback_result_with(vec![
        divergence_row(DivergenceState::Diverged),
        divergence_row(DivergenceState::Diverged),
        divergence_row(DivergenceState::Unverifiable),
    ]);

    assert_eq!(
        rollback_summary_sentence(&result),
        "0 of 0 files restored. 2 divergences, 1 unchecked reported."
    );
}

/// One of each: the singular forms of both clauses, not the plural ones a
/// careless `n == 1` check could still emit.
#[test]
fn one_divergence_and_one_unverifiable_row_use_singular_forms() {
    let result = rollback_result_with(vec![
        divergence_row(DivergenceState::Diverged),
        divergence_row(DivergenceState::Unverifiable),
    ]);

    assert_eq!(
        rollback_summary_sentence(&result),
        "0 of 0 files restored. 1 divergence, 1 unchecked reported."
    );
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
        finding_exception: ExceptionOutcome::NotConfigured,
        finding_exception_key: None,
    }
}

/// `finding` paired with a plugin id, which `group_findings_by_severity` and
/// `split_policy_excepted` now carry alongside every finding so a caller
/// downstream (the row control) can key an exception to the right plugin.
fn findingp(id: &str, sev: Severity) -> (String, Finding) {
    ("p".to_string(), finding(id, sev))
}

#[test]
fn groups_by_severity_critical_first_skipping_empty() {
    let fs = vec![
        findingp("1", Severity::Low),
        findingp("2", Severity::Critical),
        findingp("3", Severity::Low),
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
    excepted.finding_exception =
        ExceptionOutcome::Applied(crate::types::FindingPolicyException::default());
    let fs = vec![findingp("1", Severity::High), ("p".to_string(), excepted)];

    let (live, deviations) = split_policy_excepted(&fs);
    assert_eq!(live.len(), 1, "live violations: {live:?}");
    assert_eq!(live[0].1.finding_id, "1");
    assert_eq!(
        deviations.len(),
        1,
        "a documented deviation must not vanish: {deviations:?}"
    );
    assert_eq!(deviations[0].1.finding_id, "2");
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
    a.finding_exception =
        ExceptionOutcome::Applied(crate::types::FindingPolicyException::default());
    b.finding_exception =
        ExceptionOutcome::Applied(crate::types::FindingPolicyException::default());

    let (live, deviations) = split_policy_excepted(&[("p".to_string(), a), ("p".to_string(), b)]);
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
        // Empty on purpose: every assertion this fixture serves is about the
        // score strip, which reads the summary alone. A fixture carrying rows
        // it never looks at would suggest they were part of what is asserted.
        controls: Vec::new(),
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
    let v = fleet_apply_cells(&apply_out(ApplyStatus::Applied {
        ok: 5,
        failed: 0,
        plugins: Vec::new(),
    }));
    assert_eq!(v.glyph, OutcomeGlyph::Ok);
    assert_eq!(v.cells, vec![("5 applied".to_string(), "score-good")]);
}

#[test]
fn apply_cells_applied_with_failures() {
    let v = fleet_apply_cells(&apply_out(ApplyStatus::Applied {
        ok: 3,
        failed: 2,
        plugins: Vec::new(),
    }));
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
    let v = fleet_apply_cells(&apply_out(ApplyStatus::Applied {
        ok: 0,
        failed: 0,
        plugins: Vec::new(),
    }));
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
        reload_failed: 0,
        diverged: 0,
        unverifiable: 0,
        divergences: Vec::new(),
    }));
    assert_eq!(v.glyph, OutcomeGlyph::Ok);
    assert_eq!(v.cells, vec![("9 restored".to_string(), "score-good")]);
}

#[test]
fn rollback_cells_rolled_back_with_failures() {
    let v = fleet_rollback_cells(&rollback_out(RollbackStatus::RolledBack {
        restored: 4,
        failed: 2,
        reload_failed: 0,
        diverged: 0,
        unverifiable: 0,
        divergences: Vec::new(),
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

/// A reload failure must be named the way the CLI names it (`(N due to
/// reload)`), not silently folded into the plain failed count: an operator
/// scanning the fleet table otherwise cannot tell a checkpoint whose files
/// never came back from one whose files came back but left a service on the
/// old configuration.
#[test]
fn rollback_cells_rolled_back_with_reload_failures() {
    let v = fleet_rollback_cells(&rollback_out(RollbackStatus::RolledBack {
        restored: 2,
        failed: 2,
        reload_failed: 1,
        diverged: 0,
        unverifiable: 0,
        divergences: Vec::new(),
    }));
    assert_eq!(v.glyph, OutcomeGlyph::Failed);
    assert_eq!(
        v.cells,
        vec![
            ("2 restored".to_string(), "score-good"),
            ("2 failed (1 due to reload)".to_string(), "score-critical"),
        ]
    );
}

/// Finding 4 (final review): the fleet cell builder used to destructure
/// `diverged` and `unverifiable` with `..` and drop them, so a desktop fleet
/// rollback showed "9 restored" and nothing else while the CLI appended ", 2
/// divergences, 1 unchecked" for the identical result. A divergence earns a
/// neutral warning cell, not the critical class `failed` uses: it is
/// something to look at, not something that went wrong.
#[test]
fn rollback_cells_rolled_back_carries_divergences() {
    let v = fleet_rollback_cells(&rollback_out(RollbackStatus::RolledBack {
        restored: 9,
        failed: 0,
        reload_failed: 0,
        diverged: 2,
        unverifiable: 1,
        divergences: Vec::new(),
    }));
    assert_eq!(v.glyph, OutcomeGlyph::Ok);
    assert_eq!(
        v.cells,
        vec![
            ("9 restored".to_string(), "score-good"),
            ("2 divergences, 1 unchecked".to_string(), "score-warning"),
        ]
    );
}

#[test]
fn rollback_cells_rolled_back_nothing_shows_muted_fallback() {
    let v = fleet_rollback_cells(&rollback_out(RollbackStatus::RolledBack {
        restored: 0,
        failed: 0,
        reload_failed: 0,
        diverged: 0,
        unverifiable: 0,
        divergences: Vec::new(),
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
    assert!(
        SCHEDULE_PRESETS.len() >= 4,
        "the preset table has fallen below the 4 rows the round trip below was written against; a table cut to one proves proportionally less and an emptiness guard would pass on it"
    );
    for (label, _) in SCHEDULE_PRESETS {
        assert_eq!(
            preset_label_for_cron(preset_cron(label).unwrap()),
            Some(*label)
        );
    }
}

/// The colour a control verdict is rendered in, which two screens now share:
/// the compliance tab and the fleet host panel's per-framework drill-down.
///
/// Manual review is the one that matters. It is the honesty bucket for a
/// control the engine does not assess, so it maps to the amber `.status-manual`
/// and must never map to the red `.status-fail`: a gap in the tool's coverage
/// is not a gap in the host, and colouring it as a failure would report one as
/// the other.
#[test]
fn a_control_verdict_maps_to_its_own_colour_and_manual_review_is_never_red() {
    assert_eq!(control_status_class(&ControlStatus::Pass), "status-pass");
    assert_eq!(control_status_class(&ControlStatus::Fail), "status-fail");
    assert_eq!(
        control_status_class(&ControlStatus::ManualReview),
        "status-manual"
    );
    assert_eq!(
        control_status_class(&ControlStatus::NotApplicable),
        "status-na"
    );

    // The four are distinct, so a mapping that collapsed two verdicts into one
    // colour cannot satisfy the assertions above by accident.
    let classes = [
        control_status_class(&ControlStatus::Pass),
        control_status_class(&ControlStatus::Fail),
        control_status_class(&ControlStatus::ManualReview),
        control_status_class(&ControlStatus::NotApplicable),
    ];
    let unique: std::collections::HashSet<_> = classes.iter().collect();
    assert_eq!(unique.len(), 4, "each verdict needs its own class");
}

// --- Task 4: The written-exception row patch ---

fn finding_keyed(key: &str, current: &str) -> Finding {
    Finding {
        finding_category: crate::types::FindingCategory::Services,
        finding_current_value: current.to_string(),
        finding_description: "d".to_string(),
        finding_explanation: "e".to_string(),
        finding_id: key.to_string(),
        finding_impact: "i".to_string(),
        finding_recommended_value: "b".to_string(),
        finding_remediation_steps: vec![],
        finding_severity: Severity::Medium,
        finding_title: "t".to_string(),
        finding_compliance: vec![],
        finding_exception: ExceptionOutcome::NotConfigured,
        finding_exception_key: Some(key.to_string()),
    }
}

fn scan_result_with(findings: Vec<Finding>) -> ScanResult {
    scan_result_for("service-minimisation", findings)
}

fn scan_result_for(plugin_id: &str, findings: Vec<Finding>) -> ScanResult {
    ScanResult {
        scan_plugin_id: PluginId::new(plugin_id.to_string()),
        scan_success: true,
        scan_findings: findings,
        scan_unchecked: vec![],
        scan_duration_us: 0,
        scan_error: None,
    }
}

/// The row is a view, not the record. After a write the row shows the exception
/// without a second privileged scan, so this patch is what the operator sees
/// until the next scan replaces it.
#[test]
fn a_written_exception_patches_only_its_own_finding() {
    let mut results = vec![scan_result_with(vec![
        finding_keyed("bluetooth", "active"),
        finding_keyed("cups", "enabled"),
    ])];
    let written = WrittenException {
        section: "services".to_string(),
        key: "bluetooth".to_string(),
        value: "active".to_string(),
        reason: "laptop needs it".to_string(),
        approved_by: None,
        ticket: None,
        expires: None,
    };

    apply_written_exception(&mut results, "service-minimisation", "bluetooth", &written);

    let patched = &results[0].scan_findings[0];
    let untouched = &results[0].scan_findings[1];
    assert!(matches!(
        patched.finding_exception,
        ExceptionOutcome::Applied(_)
    ));
    assert!(matches!(
        untouched.finding_exception,
        ExceptionOutcome::NotConfigured
    ));
}

/// The reason is the evidence that makes this a documented deviation rather
/// than an unexplained gap, so it is what the patched row carries.
#[test]
fn the_patched_row_carries_the_reason_that_was_written() {
    let mut results = vec![scan_result_with(vec![finding_keyed("bluetooth", "active")])];
    let written = WrittenException {
        section: "services".to_string(),
        key: "bluetooth".to_string(),
        value: "active".to_string(),
        reason: "laptop needs it".to_string(),
        approved_by: None,
        ticket: None,
        expires: None,
    };

    apply_written_exception(&mut results, "service-minimisation", "bluetooth", &written);

    match &results[0].scan_findings[0].finding_exception {
        ExceptionOutcome::Applied(e) => assert_eq!(e.exception_reason, "laptop needs it"),
        other => panic!("expected an applied exception, got {other:?}"),
    }
}

/// A removal returns the row to NotConfigured, which is what the next scan will
/// independently report. Leaving it Applied would show a deviation the file no
/// longer documents.
#[test]
fn clearing_returns_the_row_to_not_configured() {
    let mut results = vec![scan_result_with(vec![finding_keyed("bluetooth", "active")])];
    let written = WrittenException {
        section: "services".to_string(),
        key: "bluetooth".to_string(),
        value: "active".to_string(),
        reason: "laptop needs it".to_string(),
        approved_by: None,
        ticket: None,
        expires: None,
    };
    apply_written_exception(&mut results, "service-minimisation", "bluetooth", &written);

    clear_exception(&mut results, "service-minimisation", "bluetooth");

    assert!(matches!(
        results[0].scan_findings[0].finding_exception,
        ExceptionOutcome::NotConfigured
    ));
}

/// A key matching in one plugin must not patch a same-named key in another. Two
/// plugins can key on the same word.
#[test]
fn the_patch_is_scoped_to_its_plugin() {
    let mut results = vec![
        scan_result_for("service-minimisation", vec![finding_keyed("shared", "a")]),
        scan_result_for("audit-hardening", vec![finding_keyed("shared", "b")]),
    ];
    let written = WrittenException {
        section: "services".to_string(),
        key: "shared".to_string(),
        value: "a".to_string(),
        reason: "r".to_string(),
        approved_by: None,
        ticket: None,
        expires: None,
    };

    apply_written_exception(&mut results, "service-minimisation", "shared", &written);

    assert!(matches!(
        results[1].scan_findings[0].finding_exception,
        ExceptionOutcome::NotConfigured
    ));
}

/// A date before today is refused. This is what keeps
/// `apply_written_exception`'s hardcoded `exception_is_expired: false` honest:
/// without this check the modal could hand it an exception that is already
/// expired.
#[test]
fn a_past_expiry_date_is_in_the_past() {
    assert!(is_expiry_in_the_past("2020-01-01", "2026-08-10"));
}

/// Today itself has not lapsed yet.
#[test]
fn todays_date_is_not_in_the_past() {
    assert!(!is_expiry_in_the_past("2026-08-10", "2026-08-10"));
}

/// A future date is not in the past.
#[test]
fn a_future_expiry_date_is_not_in_the_past() {
    assert!(!is_expiry_in_the_past("2027-01-01", "2026-08-10"));
}

/// No expiry chosen at all is never refused: a permanent exception is valid.
#[test]
fn an_absent_expiry_is_not_in_the_past() {
    assert!(!is_expiry_in_the_past("", "2026-08-10"));
}

/// A checkpoint detail carrying `n` captured files.
fn preview_detail(n: usize) -> CheckpointDetail {
    CheckpointDetail {
        checkpoint_id: "01J0000000000000000000000A".to_string(),
        checkpoint_name: "before ssh apply".to_string(),
        checkpoint_created: "2026-08-26 20:00".to_string(),
        checkpoint_user: "root".to_string(),
        file_count: n,
        files: (0..n)
            .map(|i| CheckpointFileInfo {
                path: format!("/etc/ssh/file{i}"),
                permissions: "644".to_string(),
                has_content: true,
            })
            .collect(),
    }
}

/// A preview still in flight says so, and the button carries no count it does
/// not have.
#[test]
fn a_loading_preview_says_it_is_loading() {
    let (body, button) = rollback_preview_wording(None);
    assert_eq!(body, "Loading captured files...");
    assert_eq!(button, "Roll back");
}

/// A settled preview counts what the rollback would touch, in both places.
#[test]
fn a_ready_preview_counts_the_files_in_body_and_button() {
    let ready = Ok(preview_detail(3));
    let (body, button) = rollback_preview_wording(Some(&ready));
    assert_eq!(
        body,
        "Restores 3 files to how they were then, overwriting the current configuration."
    );
    assert_eq!(button, "Roll back 3 files");
}

/// The defect this function exists for: a failed preview must not borrow the
/// words of one still loading. Fold the failure back into the loading arm and
/// this goes red while the loading test stays green.
#[test]
fn a_failed_preview_says_so_and_still_arms_the_button() {
    let failed: Result<CheckpointDetail, String> = Err("Checkpoint not found".to_string());
    let (body, button) = rollback_preview_wording(Some(&failed));
    assert_eq!(
        body,
        "The captured file list could not be read, so what this restores is not listed below. \
         The rollback itself is unaffected."
    );
    assert_eq!(button, "Roll back without preview");
}

/// Per-case assertions cannot see two states quietly merging into one, which
/// is what the modal did. Three states, three distinct things said.
#[test]
fn the_three_preview_states_each_say_something_of_their_own() {
    let ready = Ok(preview_detail(1));
    let failed: Result<CheckpointDetail, String> = Err("denied".to_string());
    let mut said: Vec<(String, String)> = [None, Some(&ready), Some(&failed)]
        .into_iter()
        .map(rollback_preview_wording)
        .collect();
    said.sort();
    said.dedup();
    assert_eq!(said.len(), 3, "a preview state repeated another's wording");
}

/// A detail that arrived says how much it holds.
#[test]
fn an_expander_that_loaded_counts_the_files() {
    let loaded = Ok(preview_detail(7));
    assert_eq!(checkpoint_detail_heading(&loaded), "7 files captured");
}

/// The defect this function exists for. The expander used to render nothing at
/// all on a failed read, so pressing Details did nothing an operator could see;
/// the reason went to a browser console they have no way to open.
///
/// Two claims are asserted, not one. The heading must say the list is missing,
/// **and** must say the rollback still works, because a sentence that only
/// reports the failure invites the operator to conclude the checkpoint is
/// unusable. It is not: the restore reads the checkpoint itself, through
/// `pkexec`, from a database this process never opens.
#[test]
fn an_expander_that_failed_says_so_and_says_the_rollback_still_works() {
    let failed: Result<CheckpointDetail, String> = Err("Checkpoint not found".to_string());
    let heading = checkpoint_detail_heading(&failed);

    assert!(
        heading.contains("could not be read"),
        "the failure must be stated: {heading}"
    );
    assert!(
        heading.contains("Rolling it back is unaffected"),
        "and must not leave the checkpoint reading as unusable: {heading}"
    );
}

/// A failure must not borrow the words of a detail that arrived, and must carry
/// no count. Zero files is the case that would hide such a merge: `0 files
/// captured` and a failed read are different answers about the same checkpoint,
/// and a per-case test naming a non-empty count would never meet them.
#[test]
fn a_failed_expander_is_never_confused_with_an_empty_one() {
    let empty = Ok(preview_detail(0));
    let failed: Result<CheckpointDetail, String> = Err("denied".to_string());

    let said = [
        checkpoint_detail_heading(&empty),
        checkpoint_detail_heading(&failed),
    ];

    assert_eq!(said[0], "0 files captured");
    assert_ne!(
        said[0], said[1],
        "a checkpoint that captured nothing and one this process could not read \
         must not say the same thing"
    );
}

/// The two components that report a failed checkpoint read make the same
/// promise about the rollback, and they must go on making it together. The
/// expander's sentence was written from the modal's; if the restore ever stops
/// re-reading the checkpoint, both are wrong and neither is the one you would
/// think to check.
#[test]
fn the_expander_and_the_modal_agree_that_a_failed_read_does_not_block_a_rollback() {
    let failed: Result<CheckpointDetail, String> = Err("denied".to_string());

    let expander = checkpoint_detail_heading(&failed);
    let (modal_body, modal_button) = rollback_preview_wording(Some(&failed));

    assert!(expander.contains("unaffected"));
    assert!(modal_body.contains("unaffected"));
    assert!(
        !modal_button.contains("Cannot") && modal_button.contains("Roll back"),
        "the modal still arms a working button: {modal_button}"
    );
}
