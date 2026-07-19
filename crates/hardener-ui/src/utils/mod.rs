// Mock data is available for development/testing but not currently used
#[allow(dead_code)]
mod mock_data;

use crate::types::{ApplyResult, ScanResult, ValidationReport};

/// One plugin's dry-run preview decision after cross-checking the estimate
/// against the latest persisted scan.
///
/// `verified_compliant` is true only when that scan positively proved the
/// plugin clean; when true, `estimated_changes` is emptied so the preview
/// shows "0 changes" instead of conditional guesses the real apply would
/// skip.
#[derive(Clone, Debug, PartialEq)]
pub struct PreviewDecision {
    /// Plugin the decision applies to (the validation report's plugin id).
    pub plugin_id: String,
    /// Whether the latest scan verified this plugin fully compliant.
    pub verified_compliant: bool,
    /// Estimated changes to show; empty when `verified_compliant`.
    pub estimated_changes: Vec<String>,
}

/// Annotates a dry-run preview with the latest scan's verdict per plugin.
///
/// A plugin is "verified compliant" only when the latest scan holds a
/// matching, successful [`ScanResult`] with zero findings AND zero unchecked
/// entries. Because only a privileged/deep scan can clear the root-only
/// `scan_unchecked` list, this is reached only after a deep scan on a
/// compliant host - exactly the intent.
///
/// FAIL-SAFE: a change is only ever HIDDEN, never invented, and only for a
/// plugin the latest scan positively verified. Any uncertainty - no matching
/// result, a failed scan, any finding, or any unchecked entry - shows the
/// estimate unchanged. The annotation is display-only: the privileged apply
/// re-checks everything and is authoritative, so a stale snapshot can at
/// worst under-report the preview, never cause apply to skip a real change.
pub fn annotate_preview(
    reports: &[ValidationReport],
    scan_results: &[ScanResult],
) -> Vec<PreviewDecision> {
    reports
        .iter()
        .map(|report| {
            let plugin_id = report.validation_report_plugin_id.as_str().to_string();
            // Require at least one matching scan result AND that every
            // matching result be a clean, successful scan. A missing match,
            // a failed scan, any finding, or any unchecked entry all count
            // as uncertainty and leave the estimate visible.
            let mut saw_match = false;
            let mut all_clean = true;
            for s in scan_results
                .iter()
                .filter(|s| s.scan_plugin_id.as_str() == plugin_id)
            {
                saw_match = true;
                all_clean &=
                    s.scan_success && s.scan_findings.is_empty() && s.scan_unchecked.is_empty();
            }
            let verified_compliant = saw_match && all_clean;
            let estimated_changes = if verified_compliant {
                Vec::new()
            } else {
                report.validation_report_estimated_changes.clone()
            };
            PreviewDecision {
                plugin_id,
                verified_compliant,
                estimated_changes,
            }
        })
        .collect()
}

/// Whether an error string returned from a privileged Tauri command
/// represents the user dismissing the pkexec authentication prompt, rather
/// than a genuine failure.
///
/// Errors cross the Tauri IPC boundary as plain strings, so this matches on
/// the fixed text emitted by `PrivilegedCommandError::AuthCancelled`'s
/// `Display` impl in `src-tauri/src/commands.rs`. If that text changes, this
/// must be updated to match.
pub fn is_auth_cancelled(err: &str) -> bool {
    err.contains("Authentication cancelled")
}

/// Builds the "N changes made[, K failed][, M skipped]" phrase the apply
/// summaries render. Counts come from the `ApplyResult` helpers, so the
/// number next to "made" only ever counts successes and skips never absorb
/// failures.
pub fn apply_change_summary(result: &ApplyResult) -> String {
    let mut summary = format!("{} changes made", result.applied_change_count());
    let failed = result.failed_change_count();
    let skipped = result.skipped_change_count();
    if failed > 0 {
        summary.push_str(&format!(", {failed} failed"));
    }
    if skipped > 0 {
        summary.push_str(&format!(", {skipped} skipped"));
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Change, ChangeType, Finding, FindingCategory, PluginId, Severity};

    fn report(plugin_id: &str, changes: &[&str]) -> ValidationReport {
        ValidationReport {
            validation_report_plugin_id: PluginId::new(plugin_id),
            validation_report_is_valid: true,
            validation_report_issues: vec![],
            validation_report_estimated_changes: changes.iter().map(|c| c.to_string()).collect(),
            validation_report_compliant_count: 0,
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

    fn an_unchecked() -> hardener_types::UncheckedCheck {
        hardener_types::UncheckedCheck {
            unchecked_check_id: "u-1".to_string(),
            unchecked_title: "t".to_string(),
            unchecked_category: FindingCategory::Network,
            unchecked_reason: "needs root".to_string(),
            unchecked_compliance: vec![],
        }
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
}
