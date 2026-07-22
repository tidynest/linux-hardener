// Mock data is available for development/testing but not currently used
#[allow(dead_code)]
mod mock_data;

use crate::types::{
    ApplyResult, Change, CheckpointInfo, FileRestoreAction, RollbackResult, ScanResult,
    ScanSessionInfo, ValidationReport,
};

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

/// Splits a checkpoint's `"%Y-%m-%d %H:%M:%S UTC"` timestamp into its date
/// portion (`"2026-07-22"`). Falls back to the whole string if there is no
/// space, so a malformed stamp still renders under some heading.
pub fn checkpoint_date(created: &str) -> &str {
    created.split_once(' ').map(|(d, _)| d).unwrap_or(created)
}

/// The time-and-zone remainder of a checkpoint timestamp (`"14:30:05 UTC"`);
/// empty if there is no space.
pub fn checkpoint_time(created: &str) -> &str {
    created.split_once(' ').map(|(_, t)| t).unwrap_or("")
}

/// Groups checkpoints by their date, preserving input order both within and
/// across groups.
///
/// ponytail: assumes the backend returns checkpoints already sorted by
/// timestamp, so same-date entries are contiguous and a single-pass
/// last-group merge suffices. If the sort ever changes, non-contiguous dates
/// would split into repeated headings; switch to a find-existing-group merge
/// then.
pub fn group_checkpoints_by_date(cps: &[CheckpointInfo]) -> Vec<(String, Vec<CheckpointInfo>)> {
    let mut groups: Vec<(String, Vec<CheckpointInfo>)> = Vec::new();
    for cp in cps {
        let date = checkpoint_date(&cp.checkpoint_created).to_string();
        match groups.last_mut() {
            Some((d, v)) if *d == date => v.push(cp.clone()),
            _ => groups.push((date, vec![cp.clone()])),
        }
    }
    groups
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

/// Literal prefix of the backend's rate-limit error message.
///
/// Kept as a constant so the parser and its tests share one source for the
/// exact text `PrivilegedOpGuard::acquire` in `src-tauri/src/commands.rs`
/// produces.
const RATE_LIMIT_PREFIX: &str = "Rate limit: please wait ";

/// Parses the wait time, in seconds, out of a privileged-command error
/// string, when that string is (or wraps) the backend's rate-limit message.
///
/// Setters prepend context such as "Deep scan failed: " before the backend
/// text, so this searches for `RATE_LIMIT_PREFIX` anywhere in `err` rather
/// than requiring it at the start, then reads the integer up to the
/// following `" seconds"`. Returns `None` for any other error text, or if
/// the integer fails to parse.
pub fn parse_rate_limit_wait_secs(err: &str) -> Option<u64> {
    let after_prefix = err.split(RATE_LIMIT_PREFIX).nth(1)?;
    let digits = after_prefix.split(" seconds").next()?;
    digits.parse().ok()
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

/// Whether every result in `results` succeeded outright, with zero failed
/// changes anywhere - the gate for showing the SUCCESS done view (Task
/// 2a.6) rather than the partial/mixed view (2a.7). An empty slice is
/// deliberately not a success: nothing having been applied is not the same
/// as everything having applied cleanly.
pub fn apply_fully_successful(results: &[ApplyResult]) -> bool {
    !results.is_empty()
        && results
            .iter()
            .all(|r| r.apply_success && r.failed_change_count() == 0)
}

/// Totals the done view's headline line: `(total_applied_settings,
/// areas_changed)`. The first is the sum of `applied_change_count()`
/// across every result (never `apply_changes.len()`, which would count
/// skips and failures too); the second counts only results that actually
/// changed something, so an all-skipped/all-compliant result contributes 0
/// to the total and is excluded from the area count.
pub fn applied_settings_and_areas(results: &[ApplyResult]) -> (usize, usize) {
    let total = results.iter().map(|r| r.applied_change_count()).sum();
    let areas = results
        .iter()
        .filter(|r| r.applied_change_count() > 0)
        .count();
    (total, areas)
}

/// Copy for the score-reveal delta line, comparing a `previous` score (if
/// any) to the freshly measured `current` one. `None` - no prior score to
/// compare against, e.g. the very first scan this session - makes no delta
/// claim at all, rather than misreporting a missing baseline as "no
/// change".
pub fn score_delta_label(previous: Option<i32>, current: i32) -> String {
    match previous {
        Some(prev) if current > prev => format!("Up {} points", current - prev),
        Some(prev) if current < prev => format!("Down {} points", prev - current),
        Some(_) => "No change".to_string(),
        None => String::new(),
    }
}

/// Backend error-text marker identifying a FAILED [`Change`] as the one
/// real "Manual step" the fixed status vocabulary needs, rather than a
/// genuine failure: PAM refusing to auto-edit the auth stack because an
/// inline `pam.d` directive already overrides it (see the PAM plugin's
/// effective-value scan).
///
/// ponytail: this hard-couples the UI to a literal backend error string.
/// If that literal ever drifts, `is_manual_action` silently stops matching
/// and every such change falls back to rendering as a genuine "Failed" -
/// the deliberately safe direction, since a manual step mislabelled
/// Failed is a lesser sin than a real failure mislabelled as the gentler
/// "needs a manual step".
const MANUAL_ACTION_MARKERS: &[&str] = &["inline pam.d override present"];

/// Whether `change` is the one real "Manual step" the backend can report: a
/// FAILED change whose `change_error` exactly matches a known
/// [`MANUAL_ACTION_MARKERS`] entry. A successful change, or a failed change
/// with any other error text, is not a manual step - see that constant's
/// doc comment for the deliberate fallback direction.
pub fn is_manual_action(change: &Change) -> bool {
    !change.change_success
        && change
            .change_error
            .as_deref()
            .is_some_and(|err| MANUAL_ACTION_MARKERS.contains(&err))
}

/// The partial view's (Task 2a.7) four-way outcome for one `ApplyResult` -
/// the fixed status vocabulary's structural side, since `ApplyResult`
/// itself only encodes applied/failed/skipped, never "Manual" directly.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ApplyOutcome {
    /// At least one real change applied; nothing failed.
    Applied,
    /// At least one change failed for a reason OTHER than a known manual
    /// marker - a genuine failure. Always wins over `ManualStep` (see
    /// `classify_apply_result`'s precedence).
    Failed,
    /// Every failed change matches a known manual-action marker, and none
    /// is a genuine failure.
    ManualStep,
    /// Nothing applied, nothing failed - only skips/compliant no-ops (or no
    /// changes attempted at all).
    Skipped,
}

/// Classifies one `ApplyResult` into the partial view's four-way status,
/// with a genuine failure always dominating a manual one: an area with both
/// a real failure and a manual-action failure reports `Failed`, never
/// `ManualStep`, so a real problem can never hide behind the gentler label.
///
/// Precedence:
/// 1. any failed change that is NOT a manual action -> `Failed`
/// 2. else any failed change that IS a manual action -> `ManualStep`
/// 3. else `applied_change_count() > 0` -> `Applied`
/// 4. else -> `Skipped`
pub fn classify_apply_result(result: &ApplyResult) -> ApplyOutcome {
    let mut has_genuine_failure = false;
    let mut has_manual_step = false;

    for failed in result
        .apply_changes
        .iter()
        .filter(|c| !c.is_skipped() && !c.is_checkpoint() && !c.change_success)
    {
        if is_manual_action(failed) {
            has_manual_step = true;
        } else {
            has_genuine_failure = true;
        }
    }

    if has_genuine_failure {
        ApplyOutcome::Failed
    } else if has_manual_step {
        ApplyOutcome::ManualStep
    } else if result.applied_change_count() > 0 {
        ApplyOutcome::Applied
    } else {
        ApplyOutcome::Skipped
    }
}

/// Short display label for one of the eight hardening areas, used only by
/// [`partial_summary_sentence`]'s compact one-line header. Keyed on the
/// same short id prefix `configure_section.rs`'s `PLUGINS`/
/// `plugin_display_name` match against (e.g. `"pam-hardening".starts_with
/// ("pam")`).
///
/// ponytail: deliberately a SEPARATE, shorter table from `PLUGINS`'s full
/// names ("PAM Authentication", "Kernel Hardening", ...) - those are right
/// for the row list and everywhere else, but do not fit inline in a
/// compact sentence ("PAM needs a manual step", not "PAM Authentication
/// needs a manual step"). `utils` must not depend on
/// `components::configure_section` (the dependency already runs the other
/// way), so this repeats the eight short ids rather than importing
/// `PLUGINS`; if a plugin's id prefix ever changes, both tables need
/// updating together.
const AREA_LABELS: &[(&str, &str)] = &[
    ("kernel", "Kernel"),
    ("ssh", "SSH"),
    ("firewall", "Firewall"),
    ("pam", "PAM"),
    ("service", "Service"),
    ("audit", "Audit"),
    ("permissions", "Permissions"),
    ("mac", "MAC"),
];

fn area_label(plugin_id: &str) -> &'static str {
    AREA_LABELS
        .iter()
        .find(|(id, _)| plugin_id.starts_with(id))
        .map(|(_, label)| *label)
        .unwrap_or("Unknown area")
}

/// Builds the partial view's (Task 2a.7) header sentence.
///
/// `X` = the total settings actually applied (`applied_change_count()`
/// summed across `results`); `Y` = `X` plus every failed change
/// (`failed_change_count()` summed) - the total settings that were MEANT to
/// change, deliberately excluding skips/compliant no-ops. Then names every
/// non-success area in `results` order: a `Failed` area as "{Name}
/// failed", a `ManualStep` area as "{Name} needs a manual step", joined
/// with ", " and closed with a single trailing full stop. An all-success
/// `results` never reaches this function - that is the done view (2a.6) -
/// so it is not special-cased here.
pub fn partial_summary_sentence(results: &[ApplyResult]) -> String {
    let applied: usize = results.iter().map(|r| r.applied_change_count()).sum();
    let meant_to_change: usize = applied
        + results
            .iter()
            .map(|r| r.failed_change_count())
            .sum::<usize>();

    let clauses: Vec<String> = results
        .iter()
        .filter_map(|r| {
            let name = area_label(r.apply_plugin_id.as_str());
            match classify_apply_result(r) {
                ApplyOutcome::Failed => Some(format!("{name} failed")),
                ApplyOutcome::ManualStep => Some(format!("{name} needs a manual step")),
                ApplyOutcome::Applied | ApplyOutcome::Skipped => None,
            }
        })
        .collect();

    let mut sentence = format!("{applied} of {meant_to_change} settings applied.");
    if !clauses.is_empty() {
        sentence.push(' ');
        sentence.push_str(&clauses.join(", "));
        sentence.push('.');
    }
    sentence
}

/// Display label for a `FileRestoreAction`. Relocated from
/// `history_section.rs` so it is unit-testable and shared by the modal.
pub fn restore_action_label(action: FileRestoreAction) -> &'static str {
    match action {
        FileRestoreAction::Restored => "Restored",
        FileRestoreAction::Removed => "Removed",
        FileRestoreAction::PermissionsRestored => "Permissions Restored",
        FileRestoreAction::Skipped => "Skipped",
    }
}

/// How a checkpointed file will be restored, from whether its content was
/// captured. Metadata-only files can only have their permissions restored.
pub fn restore_kind(has_content: bool) -> &'static str {
    if has_content {
        "content + permissions"
    } else {
        "permissions only"
    }
}

/// One-line rollback summary: successful restores over total files.
pub fn rollback_summary_sentence(result: &RollbackResult) -> String {
    let total = result.rollback_files.len();
    let restored = result
        .rollback_files
        .iter()
        .filter(|f| f.restore_success)
        .count();
    format!("{restored} of {total} files restored.")
}

/// Score band for the security-score visual. Design bands (authoritative):
/// `>= 70` Good, `40..=69` Warning, `< 40` Critical.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ScoreBand {
    Good,
    Warning,
    Critical,
}

/// Classifies a 0-100 score into its design band.
pub fn score_band(score: i32) -> ScoreBand {
    if score >= 70 {
        ScoreBand::Good
    } else if score >= 40 {
        ScoreBand::Warning
    } else {
        ScoreBand::Critical
    }
}

/// CSS modifier class for a band (drives colour across all seven themes).
pub fn score_band_class(band: ScoreBand) -> &'static str {
    match band {
        ScoreBand::Good => "score-good",
        ScoreBand::Warning => "score-warning",
        ScoreBand::Critical => "score-critical",
    }
}

/// Human status label for a band (paired with the colour, never colour alone).
pub fn score_band_label(band: ScoreBand) -> &'static str {
    match band {
        ScoreBand::Good => "Good",
        ScoreBand::Warning => "Needs attention",
        ScoreBand::Critical => "Critical",
    }
}

/// Header subtitle for the last scan: the most recent session's `completed_at`
/// shown as-is, or "Not scanned yet" when there is none.
///
// ponytail: absolute UTC as-is, no relative "2h ago" - a relative label needs
// the current clock (js_sys::Date), which a pure, testable helper avoids.
pub fn last_scanned_label(sessions: &[ScanSessionInfo]) -> String {
    match sessions.first().and_then(|s| s.completed_at.as_deref()) {
        Some(t) => format!("Last scanned {t}"),
        None => "Not scanned yet".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        Change, ChangeType, CheckpointInfo, FileRestoreAction, FileRestoreResult, Finding,
        FindingCategory, PluginId, RollbackResult, ScanSessionInfo, Severity,
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
}
