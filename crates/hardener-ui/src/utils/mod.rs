pub mod theme;

use crate::types::{ApplyOutcome as FleetApplyOutcome, RollbackOutcome as FleetRollbackOutcome};
use crate::types::{
    ApplyResult, Change, CheckpointDetail, CheckpointInfo, ComplianceFramework, ComplianceProfile,
    ControlStatus, ExceptionOutcome, FileRestoreAction, Finding, FindingPolicyException,
    FleetFrameworkPosture, RollbackResult, ScanResult, ScanSessionInfo, Severity, ValidationIssue,
    ValidationReport, WrittenException,
};
use hardener_types::{ApplyStatus, RollbackStatus, UncheckedTally};

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
    /// Validation issues the plugin reported while producing this estimate.
    ///
    /// Carried because an empty `estimated_changes` is ambiguous on its own: a
    /// plugin that could not read its config reports no pending changes, which
    /// renders identically to a host that needs none. These are what tell the
    /// two apart.
    pub issues: Vec<ValidationIssue>,
    /// Settings this run will leave alone because a policy exception documents
    /// the value the host already has.
    ///
    /// The third reason `estimated_changes` can be empty, and the one that was
    /// missing: a plugin whose every drifted setting is excepted rendered as
    /// "0 changes" over an empty panel, so a deliberate deviation looked
    /// exactly like a host with nothing to do. Every other renderer labels a
    /// documented deviation rather than hiding it.
    pub exceptions: Vec<String>,
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
                issues: report.validation_report_issues.clone(),
                // Kept even when the plugin is verified compliant: an
                // exception is why a setting is being left alone, and that
                // stays true whether or not anything else needs changing.
                exceptions: report.validation_report_exceptions.clone(),
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

/// Groups scan sessions by their `started_at` date, mirroring
/// [`group_checkpoints_by_date`]: presentation grouping only, assuming the
/// backend returns sessions newest-first so same-date entries are contiguous.
/// If that sort ever changes, non-contiguous dates would split into repeated
/// headings; switch to a find-existing-group merge then.
pub fn group_sessions_by_date(sessions: &[ScanSessionInfo]) -> Vec<(String, Vec<ScanSessionInfo>)> {
    let mut groups: Vec<(String, Vec<ScanSessionInfo>)> = Vec::new();
    for s in sessions {
        let date = checkpoint_date(&s.started_at).to_string();
        match groups.last_mut() {
            Some((d, v)) if *d == date => v.push(s.clone()),
            _ => groups.push((date, vec![s.clone()])),
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

/// The short label for a plugin id, matched on its prefix against
/// [`AREA_LABELS`]. An id no entry matches yields "Unknown area" rather than
/// the raw id, so a sentence built from it still reads as a sentence.
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

/// The line the History expander puts above a checkpoint's file list, for
/// either outcome of asking for it.
///
/// The expander used to render on `Option<CheckpointDetail>` and drop the
/// error: `handle_detail` logged to the browser console and set nothing, so a
/// failed read left the panel closed and the click did nothing at all. The
/// operator has no console, and a control that does nothing when pressed reads
/// as a broken button rather than as a report they cannot get. It is the same
/// defect [`rollback_preview_wording`] was written for, one row above in the
/// same component, and it survived that fix because only the modal was looked
/// at.
///
/// **The failure says the rollback is unaffected, and that is the same claim
/// the modal makes**, for the same reason: the restore goes out through
/// `pkexec` against a database this process never opens, so a list it cannot
/// read says nothing about a rollback it does not perform. If one of those two
/// sentences ever stops being true, both are wrong.
pub fn checkpoint_detail_heading(outcome: &Result<CheckpointDetail, String>) -> String {
    match outcome {
        Ok(detail) => format!("{} files captured", detail.file_count),
        Err(_) => "The captured file list could not be read, so what this \
                   checkpoint holds is not shown. Rolling it back is \
                   unaffected: the restore reads the checkpoint itself."
            .to_string(),
    }
}

/// What the rollback Confirm stage tells the operator about the captured file
/// list, as (body sentence, danger button label), for each state of the
/// preview.
///
/// `None` is a preview still arriving. `Some` is a settled answer, and a
/// settled failure is not the same thing as one still in flight. The modal
/// used to hold `Option<CheckpointDetail>` alone and drop the error, so a
/// preview that had failed rendered exactly like one still loading: the
/// "Loading captured files..." line stayed forever, beside an armed danger
/// button. An operator could confirm an overwrite of their live configuration
/// having been shown nothing at all.
///
/// A failure still labels a working button rather than a disabled one. A
/// preview this process cannot read does not mean a rollback it cannot run:
/// the restore goes out through `pkexec` against a database the desktop never
/// opens, so refusing here would block rollbacks that would have succeeded.
pub fn rollback_preview_wording(
    preview: Option<&Result<CheckpointDetail, String>>,
) -> (String, String) {
    match preview {
        None => (
            "Loading captured files...".to_string(),
            "Roll back".to_string(),
        ),
        Some(Ok(detail)) => (
            format!(
                "Restores {} files to how they were then, overwriting the \
                 current configuration.",
                detail.file_count
            ),
            format!("Roll back {} files", detail.file_count),
        ),
        Some(Err(_)) => (
            "The captured file list could not be read, so what this restores \
             is not listed below. The rollback itself is unaffected."
                .to_string(),
            "Roll back without preview".to_string(),
        ),
    }
}

/// One-line rollback summary: successful restores over total files, and what
/// the rollback left diverged or could not check.
///
/// The divergence clause is a count and not a list: the modal's own section
/// carries the sentences. It is in the summary because that is the line an
/// operator reads, and a divergence changes what they do next, differently
/// from a probe that simply could not answer.
pub fn rollback_summary_sentence(result: &RollbackResult) -> String {
    let total = result.rollback_files.len();
    let restored = result
        .rollback_files
        .iter()
        .filter(|f| f.restore_success)
        .count();
    let files = format!("{restored} of {total} files restored.");
    let (diverged, unverifiable) = result.divergence_counts();
    let clause = hardener_types::rollback_divergence_note(diverged, unverifiable);
    if clause.is_empty() {
        files
    } else {
        format!("{files} {clause} reported.")
    }
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

/// Short display code for a compliance framework, for the Hosts inventory
/// row's score strip. Distinct from `id()` (request string) and `full_name()`
/// (long label): a compact badge code.
pub fn framework_short_label(framework: ComplianceFramework) -> &'static str {
    match framework {
        ComplianceFramework::CIS => "CIS",
        ComplianceFramework::STIG => "STIG",
        ComplianceFramework::NIST => "800-53",
        ComplianceFramework::PCIDSS => "PCI",
        ComplianceFramework::HIPAA => "HIPAA",
        ComplianceFramework::GDPR => "GDPR",
        ComplianceFramework::ISO27001 => "ISO",
        ComplianceFramework::SOC2 => "SOC2",
        ComplianceFramework::NIST800171 => "800-171",
        ComplianceFramework::FedRAMP => "FedRAMP",
    }
}

/// The identifier scheme a fleet row's framework was scored under, for the
/// badge beside its short label, or `None` when there is nothing worth saying.
///
/// Delegates to `hardener_types::profile_label`, the one copy of these
/// strings, rather than restating them: the report headings and this badge
/// cannot then disagree about what scored a host.
///
/// `Generic` is suppressed here rather than there. A generic host's STIG row
/// does have an honest label ("RHEL 8 baseline IDs") and a report heading
/// wants it, but every host in a non-RHEL fleet is generic, so on this screen
/// it would badge every row with the default and say nothing about any of
/// them. A badge that never varies is noise; the profiled rows are the ones
/// that carry information.
pub fn profile_badge_label(
    profile: ComplianceProfile,
    framework: ComplianceFramework,
) -> Option<&'static str> {
    match profile {
        ComplianceProfile::Generic => None,
        ComplianceProfile::Rhel10 => hardener_types::profile_label(profile, framework),
    }
}

/// One cell of the inventory row's framework score strip: (short label, rounded
/// score, band CSS class). Built in `ComplianceFramework::ALL` order (stable
/// across hosts) from the frameworks actually present in `compliance`, so a
/// host scanned against a subset shows only what it has, always in that order.
pub fn framework_score_cells(
    compliance: &[FleetFrameworkPosture],
) -> Vec<(&'static str, i32, &'static str)> {
    ComplianceFramework::ALL
        .into_iter()
        .filter_map(|framework| {
            let posture = compliance.iter().find(|p| p.framework == framework)?;
            let score = posture.summary.summary_score_percentage.round() as i32;
            Some((
                framework_short_label(framework),
                score,
                score_band_class(score_band(score)),
            ))
        })
        .collect()
}

/// Client-side validation for one ad-hoc `user@host[:port]` target, mirroring
/// the backend guard. Lifted from `adhoc_host_input.rs` so the Hosts screen can
/// render ad-hoc targets as inventory rows from one tested source. `existing`
/// holds already-added canonical targets.
pub fn adhoc_target_error(target: &str, existing: &[String]) -> Option<String> {
    use hardener_types::remote::RemoteHostProfile;
    if target.is_empty() {
        return Some("Enter user@host[:port]".to_string());
    }
    let profile = RemoteHostProfile::from_target(target, 22, None, true);
    if !RemoteHostProfile::is_valid_hostname(&profile.hostname) {
        return Some(format!("Invalid target '{target}': invalid hostname"));
    }
    if existing.iter().any(|e| e == &adhoc_canonical(target)) {
        return Some(format!("'{target}' already added"));
    }
    None
}

/// Canonical `user@host:port` form of an ad-hoc target: the batch history key,
/// so display name and persisted key agree.
pub fn adhoc_canonical(target: &str) -> String {
    use hardener_types::remote::RemoteHostProfile;
    RemoteHostProfile::from_target(target, 22, None, true).target()
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

/// A finding paired with the id of the plugin that produced it.
///
/// An exception is keyed per plugin, and two plugins can key on the same
/// word, so a caller several frames from the scan results still needs both to
/// write or clear the right one. `findings_tab` threads this from
/// `all_findings` down to `finding_row`; `host_panel` strips the id back off
/// before rendering, since its findings list carries no accept/remove
/// control.
pub type PluginFinding = (String, Finding);

/// Groups findings by severity in Critical -> Info order, dropping empty
/// buckets. Mirrors `group_checkpoints_by_date`: presentation grouping only.
pub fn group_findings_by_severity(
    findings: &[PluginFinding],
) -> Vec<(Severity, Vec<PluginFinding>)> {
    [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]
    .into_iter()
    .filter_map(|sev| {
        let group: Vec<PluginFinding> = findings
            .iter()
            .filter(|(_, f)| f.finding_severity == sev)
            .cloned()
            .collect();
        (!group.is_empty()).then_some((sev, group))
    })
    .collect()
}

/// The honesty line beside a run's unchecked checks.
///
/// One definition for the score hero and the findings tab, which had each
/// written their own and both blamed privilege for every entry. A plugin the
/// operator disabled, a path on a filesystem with no permission bits and a
/// probe that failed for its own reasons all land in the same count, and a
/// privileged re-run reaches none of them, so the sentence names privilege only
/// where privilege is the answer.
///
/// The trailing space is deliberate: the caller may follow this with the
/// "Run with sudo" button, and the two must not run together.
pub fn unchecked_honesty_line(tally: UncheckedTally) -> String {
    let plural = if tally.total == 1 { "" } else { "s" };
    match tally.needing_privilege {
        0 => format!("{} check{plural} not verified. ", tally.total),
        privileged if privileged == tally.total => {
            format!(
                "{} check{plural} not verifiable without privileges. ",
                tally.total
            )
        }
        privileged => format!(
            "{} check{plural} not verified, {privileged} of them for want of privileges. ",
            tally.total
        ),
    }
}

/// Splits findings into live violations and documented deviations, preserving
/// order within each half.
///
/// Both halves are rendered. A deviation the operator documented is evidence,
/// so dropping it hides what their own policy records, and leaving it among the
/// violations makes a severity count read higher than the number of real
/// problems. `hardener report` resolves this the same way: an excepted finding
/// is listed under its control rather than removed from it.
///
/// See [`PluginFinding`] for why the plugin id rides along.
pub fn split_policy_excepted(
    findings: &[PluginFinding],
) -> (Vec<PluginFinding>, Vec<PluginFinding>) {
    findings
        .iter()
        .cloned()
        .partition(|(_, f)| !f.is_policy_excepted())
}

/// Whether an ISO `YYYY-MM-DD` expiry date names a day before `today`, also
/// `YYYY-MM-DD`.
///
/// `expires` empty (no expiry chosen) is never in the past. Lexicographic
/// comparison is correct for this one format: zero-padded ISO dates sort in
/// calendar order as plain strings, so no date parsing is needed to answer a
/// yes/no question.
///
/// This is what keeps [`apply_written_exception`]'s hardcoded
/// `exception_is_expired: false` honest: that patch cannot recompute expiry
/// without duplicating `PolicyException::is_expired`, so the modal that
/// collects the date is the only place left to refuse one that is already in
/// the past.
pub fn is_expiry_in_the_past(expires: &str, today: &str) -> bool {
    !expires.is_empty() && expires < today
}

/// Marks the finding this exception was written for as an applied deviation,
/// without re-scanning.
///
/// A full privileged scan to refresh one row would cost a second authentication
/// prompt for information the write already returned. The persisted history row
/// keeps what was scanned, and the next scan reports the host's own answer: this
/// patch is the view, not the record.
pub fn apply_written_exception(
    results: &mut [ScanResult],
    plugin_id: &str,
    key: &str,
    written: &WrittenException,
) {
    for finding in matching_findings(results, plugin_id, key) {
        finding.finding_exception = ExceptionOutcome::Applied(FindingPolicyException {
            exception_allowed_value: written.value.clone(),
            exception_reason: written.reason.clone(),
            exception_approved_by: written.approved_by.clone(),
            exception_approved_date: None,
            exception_ticket: written.ticket.clone(),
            exception_expires: written.expires.clone(),
            // An exception written a moment ago has not expired. Computing it
            // here from `expires` would be a second implementation of
            // `PolicyException::is_expired`, and the next scan reports the
            // host's own answer regardless.
            exception_is_expired: false,
        });
    }
}

/// Returns the finding to `NotConfigured` after its exception is removed, which
/// is what the next scan reports independently.
pub fn clear_exception(results: &mut [ScanResult], plugin_id: &str, key: &str) {
    for finding in matching_findings(results, plugin_id, key) {
        finding.finding_exception = ExceptionOutcome::NotConfigured;
    }
}

/// Findings carrying `key`, in the named plugin only. Two plugins may key on
/// the same word, and an exception written for one says nothing about the other.
fn matching_findings<'a>(
    results: &'a mut [ScanResult],
    plugin_id: &str,
    key: &str,
) -> impl Iterator<Item = &'a mut Finding> {
    let plugin_id = plugin_id.to_string();
    let key = key.to_string();
    results
        .iter_mut()
        .filter(move |r| r.scan_plugin_id.as_str() == plugin_id)
        .flat_map(|r| r.scan_findings.iter_mut())
        .filter(move |f| f.finding_exception_key.as_deref() == Some(key.as_str()))
}

/// Display label for a severity group header.
pub fn severity_label(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

/// The existing `.status-*` colour class for a control status pill.
///
/// Manual review maps to the amber `.status-manual` and never to red: it is the
/// honesty bucket for a control the engine does not assess, and colouring it as
/// a failure would report a gap in coverage as a gap in the host.
///
/// Lifted out of `compliance_tab` when the fleet host panel began rendering
/// control rows too, so the two screens cannot drift to different colours for
/// the same verdict.
pub fn control_status_class(status: &ControlStatus) -> &'static str {
    match status {
        ControlStatus::Pass => "status-pass",
        ControlStatus::Fail => "status-fail",
        ControlStatus::ManualReview => "status-manual",
        ControlStatus::NotApplicable => "status-na",
    }
}

/// The existing `severity_*` CSS class carrying that severity's colour
/// (reused for the group-header dot; no new severity colours introduced).
pub fn severity_class(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "severity_critical",
        Severity::High => "severity_high",
        Severity::Medium => "severity_medium",
        Severity::Low => "severity_low",
        Severity::Info => "severity_info",
    }
}

/// Which status glyph a fleet outcome row shows: the worst state wins
/// (`Failed` over `Pending` over `Ok`), so a host that both stages changes
/// and hit a validation error reads `Failed`, never the gentler `Pending`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OutcomeGlyph {
    Ok,
    Pending,
    Failed,
}

impl OutcomeGlyph {
    /// Decorative symbol (rows carry the meaning in text; the glyph is
    /// `aria-hidden`).
    pub fn symbol(self) -> &'static str {
        match self {
            OutcomeGlyph::Ok => "\u{2713}",      // check
            OutcomeGlyph::Pending => "\u{2022}", // bullet
            OutcomeGlyph::Failed => "\u{2717}",  // ballot X
        }
    }

    /// CSS class carrying the glyph's colour (one per band; all seven themes
    /// define the underlying `--color-*-bright` tokens).
    pub fn class(self) -> &'static str {
        match self {
            OutcomeGlyph::Ok => "fleet-glyph-ok",
            OutcomeGlyph::Pending => "fleet-glyph-pending",
            OutcomeGlyph::Failed => "fleet-glyph-failed",
        }
    }
}

/// Render-ready view of one host's fleet outcome: a status glyph, zero-or-more
/// labelled stat cells (each with a band CSS class, `""` for a muted/neutral
/// cell), and an optional full-width error message. Both apply and rollback,
/// both dry-run and executed, collapse to this one shape.
#[derive(Clone, Debug, PartialEq)]
pub struct OutcomeView {
    pub glyph: OutcomeGlyph,
    pub cells: Vec<(String, &'static str)>,
    pub error: Option<String>,
}

/// Maps one apply outcome (dry-run or executed) to its render-ready view.
/// Only non-zero counts become cells; `would_change` is a warning, `compliant`
/// is muted context, `failed` is critical, applied successes are good.
pub fn fleet_apply_cells(o: &FleetApplyOutcome) -> OutcomeView {
    match &o.status {
        ApplyStatus::Validated {
            would_change,
            compliant,
            failed,
            ..
        } => {
            let mut cells = Vec::new();
            if *would_change > 0 {
                cells.push((format!("{would_change} would change"), "score-warning"));
            }
            if *compliant > 0 {
                cells.push((format!("{compliant} already compliant"), ""));
            }
            if *failed > 0 {
                cells.push((format!("{failed} failed"), "score-critical"));
            }
            let glyph = if *failed > 0 {
                OutcomeGlyph::Failed
            } else if *would_change > 0 {
                OutcomeGlyph::Pending
            } else {
                OutcomeGlyph::Ok
            };
            OutcomeView {
                glyph,
                cells,
                error: None,
            }
        }
        ApplyStatus::Applied { ok, failed, .. } => {
            let mut cells = Vec::new();
            if *ok > 0 {
                cells.push((format!("{ok} applied"), "score-good"));
            }
            if *failed > 0 {
                cells.push((format!("{failed} failed"), "score-critical"));
            }
            if cells.is_empty() {
                cells.push(("No changes".to_string(), ""));
            }
            let glyph = if *failed > 0 {
                OutcomeGlyph::Failed
            } else {
                OutcomeGlyph::Ok
            };
            OutcomeView {
                glyph,
                cells,
                error: None,
            }
        }
        ApplyStatus::Failed { error } => OutcomeView {
            glyph: OutcomeGlyph::Failed,
            cells: Vec::new(),
            error: Some(error.clone()),
        },
    }
}

/// Maps one rollback outcome (dry-run or executed) to its render-ready view.
pub fn fleet_rollback_cells(o: &FleetRollbackOutcome) -> OutcomeView {
    match &o.status {
        RollbackStatus::Previewed { checkpoints } if *checkpoints > 0 => OutcomeView {
            glyph: OutcomeGlyph::Pending,
            cells: vec![(format!("{checkpoints} checkpoints would restore"), "")],
            error: None,
        },
        RollbackStatus::Previewed { .. } | RollbackStatus::NothingToDo => OutcomeView {
            glyph: OutcomeGlyph::Ok,
            cells: vec![("Nothing to roll back".to_string(), "")],
            error: None,
        },
        // `divergences` is deliberately not read here. The fleet table shows
        // counts and the drill-down that would show the rows is its own piece
        // of work; matching it away keeps this arm honest about that rather
        // than silently ignoring a field it looks like it handles.
        RollbackStatus::RolledBack {
            restored,
            failed,
            reload_failed,
            diverged,
            unverifiable,
            divergences: _,
        } => {
            let mut cells = Vec::new();
            if *restored > 0 {
                cells.push((format!("{restored} restored"), "score-good"));
            }
            if *failed > 0 {
                // The same sentence the CLI's `render_rollback_text` prints,
                // from the one place that writes it: a reload failure means a
                // service is still on the old configuration, a different
                // problem from a file that never came back, and the fleet
                // table must say which.
                cells.push((
                    hardener_types::rollback_failed_label(*failed, *reload_failed),
                    "score-critical",
                ));
            }
            // The same clause the CLI and the desktop's single-host modal
            // both render, from the one place that writes it. A neutral
            // warning class, not the critical one used above: a divergence is
            // something to look at, not something that failed.
            let divergence_note =
                hardener_types::rollback_divergence_note(*diverged, *unverifiable);
            if !divergence_note.is_empty() {
                cells.push((divergence_note, "score-warning"));
            }
            if cells.is_empty() {
                cells.push(("Nothing restored".to_string(), ""));
            }
            let glyph = if *failed > 0 {
                OutcomeGlyph::Failed
            } else {
                OutcomeGlyph::Ok
            };
            OutcomeView {
                glyph,
                cells,
                error: None,
            }
        }
        RollbackStatus::Failed { error } => OutcomeView {
            glyph: OutcomeGlyph::Failed,
            cells: Vec::new(),
            error: Some(error.clone()),
        },
    }
}

/// Pluralised "N host(s)" tail shared by both aggregate lines.
fn host_count_phrase(n: usize) -> String {
    if n == 1 {
        "1 host".to_string()
    } else {
        format!("{n} hosts")
    }
}

/// Confirm-modal stakes line for an apply: total staged changes across the
/// previewed hosts. Sums `would_change` over the `Validated` outcomes (other
/// variants never appear in a dry-run preview).
pub fn fleet_apply_aggregate(outcomes: &[FleetApplyOutcome]) -> String {
    let total: usize = outcomes
        .iter()
        .map(|o| match o.status {
            ApplyStatus::Validated { would_change, .. } => would_change,
            _ => 0,
        })
        .sum();
    format!(
        "~{total} changes across {}",
        host_count_phrase(outcomes.len())
    )
}

/// Confirm-modal stakes line for a rollback: total checkpoints that will
/// restore across the previewed hosts.
pub fn fleet_rollback_aggregate(outcomes: &[FleetRollbackOutcome]) -> String {
    let total: usize = outcomes
        .iter()
        .map(|o| match o.status {
            RollbackStatus::Previewed { checkpoints } => checkpoints,
            _ => 0,
        })
        .sum();
    format!(
        "{total} checkpoints will restore across {}",
        host_count_phrase(outcomes.len())
    )
}

/// Cron presets with display labels and 6-field cron expressions. The single
/// source shared by the Scheduler select and the helpers below.
pub const SCHEDULE_PRESETS: &[(&str, &str)] = &[
    ("Daily at 2:00 AM", "0 0 2 * * *"),
    ("Every 6 hours", "0 0 */6 * * *"),
    ("Every 12 hours", "0 0 */12 * * *"),
    ("Weekly on Monday", "0 0 2 * * Mon"),
];

/// Cron expression for a preset label, if it names a known preset.
pub fn preset_cron(label: &str) -> Option<&'static str> {
    SCHEDULE_PRESETS
        .iter()
        .find(|(l, _)| *l == label)
        .map(|(_, c)| *c)
}

/// Preset label whose cron matches `cron`, if any. Used on load to decide
/// whether a saved schedule is a friendly preset or a custom expression.
pub fn preset_label_for_cron(cron: &str) -> Option<&'static str> {
    SCHEDULE_PRESETS
        .iter()
        .find(|(_, c)| *c == cron)
        .map(|(l, _)| *l)
}

/// The cron the scheduler will actually run: a non-empty `custom_cron`
/// overrides the preset; otherwise the selected preset's cron; empty string if
/// neither resolves.
pub fn effective_schedule_cron(preset_label: &str, custom_cron: &str) -> String {
    if !custom_cron.is_empty() {
        return custom_cron.to_string();
    }
    preset_cron(preset_label).unwrap_or_default().to_string()
}

#[cfg(test)]
mod tests;
