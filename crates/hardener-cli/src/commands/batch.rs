//! `hardener batch scan`: scan many remote hosts concurrently.

use super::privilege::is_privileged;
use super::state::{effective_user, get_audit_logger, get_checkpoint_manager};
use crate::cli::OutputFormat as CliOutputFormat;
use crate::commands::daemon::load_scheduler_config;
use crate::commands::report::{finding_to_scan_finding, scan_grouped};
use crate::ssh_config::SshConnectionConfig;
use anyhow::{Result, anyhow, bail};
use colored::Colorize;
use hardener_common::types::{ComplianceProfile, PluginId, Severity};
use hardener_compliance::{ReportConfig, ReportGenerator, Scenario, resolve_profile};
use hardener_core::plugin::{Finding, UncheckedCheck};
use hardener_core::{ConfigLoader, HardenerConfig};
use hardener_core::{
    PluginMetadata, ScanResult, SshExecutor,
    executor::{SystemExecutor, host_key_for},
};
use hardener_distro::Distribution;
use hardener_scheduler::ScanHistoryManager;
use hardener_scheduler::db::ScanFinding;
use hardener_state::{ActionResult, ActionType, Checkpoint, CheckpointManager};
use hardener_types::ComplianceReport;
use hardener_types::remote::{HostsConfig, RemoteHostProfile};
use hardener_types::{ApplyOutcome, ApplyStatus, RollbackOutcome, RollbackStatus};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::warn;

/// Per-severity tally of one host's findings.
// Consumed by the batch-scan command wired up in a later task.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

impl SeverityCounts {
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low
    }

    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut c = SeverityCounts::default();
        for f in findings {
            match f.finding_severity {
                Severity::Critical => c.critical += 1,
                Severity::High => c.high += 1,
                Severity::Medium => c.medium += 1,
                Severity::Low => c.low += 1,
                _ => {} // Info and below are not counted in the rollup
            }
        }
        c
    }
}

/// Outcome of scanning one host.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum HostStatus {
    Scanned {
        counts: SeverityCounts,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        findings: Vec<Finding>,
        /// Checks the scan could not evaluate at its current privilege level.
        /// Additive JSON field: absent when empty, so existing consumers that
        /// index untyped `serde_json::Value` see no shape change.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        unchecked: Vec<UncheckedCheck>,
    },
    Failed {
        error: String,
    },
}

/// One host's batch result. `name` is the inventory name (or target for ad-hoc
/// hosts); `target` is `user@host:port` for display. `profile` is the
/// compliance profile resolved from the host's own `/etc/os-release`
/// (`Generic` when the host failed or detection did).
#[derive(Clone, Debug, Serialize)]
pub struct HostOutcome {
    pub name: String,
    pub target: String,
    #[serde(default)]
    pub profile: ComplianceProfile,
    #[serde(flatten)]
    pub status: HostStatus,
}

/// Tiered exit code: 0 = all clean, 1 = findings present, 2 = any host errored.
pub fn exit_code(outcomes: &[HostOutcome]) -> i32 {
    let mut code = 0;
    for o in outcomes {
        match &o.status {
            HostStatus::Failed { .. } => return 2,
            HostStatus::Scanned { counts, .. } if counts.total() > 0 => code = 1,
            HostStatus::Scanned { .. } => {}
        }
    }
    code
}

/// Parses an ad-hoc `--ssh user@host[:port]` target into a profile. The key
/// comes from the global SSH flags. Thin delegate: the parser itself lives in
/// `hardener-types` so the desktop's ad-hoc fleet hosts share it.
pub fn parse_inline(
    target: &str,
    port: u16,
    key_file: Option<String>,
    verify: bool,
) -> RemoteHostProfile {
    RemoteHostProfile::from_target(target, port, key_file, verify)
}

/// Resolves the host set to scan from inventory selection plus inline hosts.
/// De-duplicates by `name`, inventory taking precedence. Unknown `--host` names
/// are an error so a typo never silently scans nothing.
pub fn resolve_hosts(
    inventory: &HostsConfig,
    all: bool,
    names: &[String],
    inline: Vec<RemoteHostProfile>,
) -> Result<Vec<RemoteHostProfile>> {
    let mut selected: Vec<RemoteHostProfile> = if all {
        inventory.hosts.clone()
    } else {
        names
            .iter()
            .map(|n| {
                inventory
                    .hosts
                    .iter()
                    .find(|h| &h.name == n)
                    .cloned()
                    .ok_or_else(|| anyhow!("unknown host '{n}' (not in inventory)"))
            })
            .collect::<Result<Vec<_>>>()?
    };

    for profile in inline {
        if !selected.iter().any(|h| h.name == profile.name) {
            selected.push(profile);
        }
    }

    if selected.is_empty() {
        bail!("no hosts selected: use --all, --host <names>, or --ssh <user@host>");
    }
    Ok(selected)
}

/// Aggregate rollup across all hosts, for the summary line and JSON.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct BatchSummary {
    pub hosts_total: usize,
    pub hosts_scanned: usize,
    pub hosts_failed: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub total: usize,
}

impl BatchSummary {
    pub fn from_outcomes(outcomes: &[HostOutcome]) -> Self {
        let mut s = BatchSummary {
            hosts_total: outcomes.len(),
            ..Default::default()
        };
        for o in outcomes {
            match &o.status {
                HostStatus::Scanned { counts, .. } => {
                    s.hosts_scanned += 1;
                    s.critical += counts.critical;
                    s.high += counts.high;
                    s.medium += counts.medium;
                    s.low += counts.low;
                }
                HostStatus::Failed { .. } => s.hosts_failed += 1,
            }
        }
        s.total = s.critical + s.high + s.medium + s.low;
        s
    }
}

/// One framework's assessed posture for a single host.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FrameworkPosture {
    pub framework: String,
    pub score: f64,
    pub passing: usize,
    pub failing: usize,
    pub manual_review: usize,
    pub not_applicable: usize,
    pub total: usize,
}

/// Whether a host was assessed or failed to scan.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum HostReportStatus {
    Assessed { frameworks: Vec<FrameworkPosture> },
    Failed { error: String },
}

/// One host's compliance assessment outcome. `profile` names the identifier
/// scheme the host was assessed under; the text table omits it, JSON carries it.
#[derive(Clone, Debug, Serialize)]
pub struct HostReport {
    pub name: String,
    pub target: String,
    #[serde(default)]
    pub profile: ComplianceProfile,
    #[serde(flatten)]
    pub status: HostReportStatus,
}

/// Flattens one framework's `ComplianceReport` into a tabulatable posture row.
pub fn posture_from_report(report: &ComplianceReport) -> FrameworkPosture {
    let s = &report.report_summary;
    FrameworkPosture {
        framework: report.report_framework.to_string(),
        score: s.summary_score_percentage,
        passing: s.summary_passing,
        failing: s.summary_failing,
        manual_review: s.summary_manual_review,
        not_applicable: s.summary_not_applicable,
        total: s.summary_total_controls,
    }
}

/// Tiered exit code mirroring `batch scan`: 0 = every scanned host compliant
/// (no failing controls), 1 = a failing control somewhere, 2 = a host errored.
/// `ManualReview`/`NotApplicable` are not failures, so they never raise to 1.
pub fn report_exit_code(reports: &[HostReport]) -> i32 {
    let mut code = 0;
    for r in reports {
        match &r.status {
            HostReportStatus::Failed { .. } => return 2,
            HostReportStatus::Assessed { frameworks } => {
                if frameworks.iter().any(|f| f.failing > 0) {
                    code = 1;
                }
            }
        }
    }
    code
}

/// One framework's fleet-wide failing-control total, for the rollup line.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FrameworkRollup {
    pub framework: String,
    pub failing: usize,
}

/// Aggregate rollup across all hosts: host tallies plus per-framework failing
/// totals (grouped by framework, first-seen order preserved).
#[derive(Debug, Default, PartialEq, Serialize)]
pub struct ReportRollup {
    pub hosts_total: usize,
    pub hosts_assessed: usize,
    pub hosts_failed: usize,
    pub frameworks: Vec<FrameworkRollup>,
}

impl ReportRollup {
    pub fn from_reports(reports: &[HostReport]) -> Self {
        let mut r = ReportRollup {
            hosts_total: reports.len(),
            ..Default::default()
        };
        for report in reports {
            match &report.status {
                HostReportStatus::Failed { .. } => r.hosts_failed += 1,
                HostReportStatus::Assessed { frameworks } => {
                    r.hosts_assessed += 1;
                    for f in frameworks {
                        match r
                            .frameworks
                            .iter_mut()
                            .find(|fr| fr.framework == f.framework)
                        {
                            Some(fr) => fr.failing += f.failing,
                            None => r.frameworks.push(FrameworkRollup {
                                framework: f.framework.clone(),
                                failing: f.failing,
                            }),
                        }
                    }
                }
            }
        }
        r
    }
}

/// Width of the `=` rule each per-host section header pads to.
const HOST_RULE_WIDTH: usize = 72;

/// Builds the per-host section header shared by all four batch text
/// renderers: `==== name  target  [extra] ===...` padded with `=` to a fixed
/// width. The host name carries the accent colour; the fill is computed from
/// the plain text so alignment survives non-colour terminals (pipes,
/// NO_COLOR), where `colored` drops the escapes but not the characters.
fn host_header(name: &str, target: &str, extra: Option<&str>) -> String {
    let extra_plain = extra.map(|e| format!("  [{e}]")).unwrap_or_default();
    let used = 5 + name.len() + 2 + target.len() + extra_plain.len() + 1;
    let fill = "=".repeat(HOST_RULE_WIDTH.saturating_sub(used).max(4));
    let extra_shown = if extra_plain.is_empty() {
        String::new()
    } else {
        extra_plain.dimmed().to_string()
    };
    format!(
        "==== {}  {}{} {}\n",
        name.cyan().bold(),
        target,
        extra_shown,
        fill
    )
}

/// Appends one `  label:  value` detail line below a host header, with the
/// label column aligned identically across all four batch verbs.
fn push_detail(out: &mut String, label: &str, value: &str) {
    out.push_str(&format!("  {:<10} {}\n", format!("{label}:"), value));
}

/// Appends the shared `status: FAILED` + `error: ...` detail pair for a host
/// that errored before producing any per-verb result.
fn push_failed(out: &mut String, error: &str) {
    push_detail(out, "status", &"FAILED".red().bold().to_string());
    push_detail(out, "error", error);
}

/// Renders one severity tally as `N total (a crit, b high, c med, d low)`,
/// colouring each non-zero part with the shared severity palette (see
/// `output::severity_label`) and dimming zero parts so hotspots stand out.
fn format_counts(counts: &SeverityCounts) -> String {
    let part = |n: usize, word: &str, sev: Severity| {
        let text = format!("{n} {word}");
        if n == 0 {
            text.dimmed().to_string()
        } else {
            crate::output::severity_label(&text, &sev).to_string()
        }
    };
    format!(
        "{} total ({}, {}, {}, {})",
        counts.total(),
        part(counts.critical, "crit", Severity::Critical),
        part(counts.high, "high", Severity::High),
        part(counts.medium, "med", Severity::Medium),
        part(counts.low, "low", Severity::Low),
    )
}

/// Removes ANSI CSI escape sequences (`ESC [ ... <final>`) from a rendered
/// string. `colored` decides colour on stdout's tty-ness, so a string headed
/// for a file via `--output` can carry escapes it should not; JSON is
/// unaffected (serde escapes control bytes, so it never holds a raw ESC).
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        if chars.clone().next() == Some('[') {
            chars.next();
            // Consume parameter/intermediate bytes up to the final byte
            // (0x40..=0x7e), which closes the sequence (`m` for colours).
            for c2 in chars.by_ref() {
                if ('\x40'..='\x7e').contains(&c2) {
                    break;
                }
            }
        }
    }
    out
}

/// Writes rendered output to `path` for `--output`, colour-free: the escapes
/// `colored` emitted for a colour-capable stdout are stripped first, so saved
/// files match what a piped (non-tty) run prints. Shared by all four verbs.
fn write_output(path: &str, rendered: &str) -> Result<()> {
    std::fs::write(path, strip_ansi(rendered)).map_err(|e| anyhow!("failed to write {path}: {e}"))
}

/// Joins the non-zero `count label` parts of a summary footer, e.g.
/// `2 applied, 1 failed`. All-zero (an empty batch) reads `nothing to do`.
fn summary_parts(parts: &[(usize, &str)]) -> String {
    let joined: Vec<String> = parts
        .iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, label)| format!("{n} {label}"))
        .collect();
    if joined.is_empty() {
        "nothing to do".to_string()
    } else {
        joined.join(", ")
    }
}

/// Renders the human-readable fleet posture report: one section per host
/// (header names the host, target and compliance profile) + rollup footer.
pub fn render_report_text(reports: &[HostReport]) -> String {
    let mut out = String::new();
    for report in reports {
        let profile = format!("{} profile", report.profile);
        out.push_str(&host_header(&report.name, &report.target, Some(&profile)));
        match &report.status {
            HostReportStatus::Assessed { frameworks } => {
                let status = format!(
                    "{} ({} framework(s) assessed)",
                    "ok".green(),
                    frameworks.len()
                );
                push_detail(&mut out, "status", &status);
                for f in frameworks {
                    let fail = if f.failing == 0 {
                        format!("{} fail", f.failing).dimmed().to_string()
                    } else {
                        format!("{} fail", f.failing).red().to_string()
                    };
                    push_detail(
                        &mut out,
                        &f.framework,
                        &format!(
                            "{:>5.1}%  {} pass, {}, {} manual, {} n/a",
                            f.score, f.passing, fail, f.manual_review, f.not_applicable,
                        ),
                    );
                }
            }
            HostReportStatus::Failed { error } => push_failed(&mut out, error),
        }
        out.push('\n');
    }
    let rollup = ReportRollup::from_reports(reports);
    out.push_str("---\n");
    out.push_str(&format!(
        "{} of {} hosts assessed, {} failed\n",
        rollup.hosts_assessed, rollup.hosts_total, rollup.hosts_failed,
    ));
    for f in &rollup.frameworks {
        out.push_str(&format!(
            "{}: {} failing controls across the fleet\n",
            f.framework, f.failing,
        ));
    }
    out
}

/// Renders the machine-readable JSON document.
pub fn render_report_json(reports: &[HostReport]) -> String {
    let doc = serde_json::json!({
        "hosts": reports,
        "summary": ReportRollup::from_reports(reports),
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

/// Renders the human-readable scan output: one section per host + rollup.
pub fn render_text(outcomes: &[HostOutcome]) -> String {
    let mut out = String::new();
    for o in outcomes {
        out.push_str(&host_header(&o.name, &o.target, None));
        match &o.status {
            HostStatus::Scanned {
                counts, unchecked, ..
            } => {
                push_detail(&mut out, "status", &"ok".green().to_string());
                let findings = if counts.total() == 0 {
                    "none".green().to_string()
                } else {
                    format_counts(counts)
                };
                push_detail(&mut out, "findings", &findings);
                if let Some(note) = hardener_types::unchecked_summary(unchecked) {
                    push_detail(&mut out, "unchecked", &note.dimmed().to_string());
                }
            }
            HostStatus::Failed { error } => push_failed(&mut out, error),
        }
        out.push('\n');
    }
    let s = BatchSummary::from_outcomes(outcomes);
    out.push_str("---\n");
    out.push_str(&format!(
        "{} host(s): {} scanned, {} failed; findings: {} crit, {} high, {} med, {} low ({} total)\n",
        s.hosts_total,
        s.hosts_scanned,
        s.hosts_failed,
        s.critical,
        s.high,
        s.medium,
        s.low,
        s.total,
    ));
    out
}

/// Renders the machine-readable JSON document.
pub fn render_json(outcomes: &[HostOutcome]) -> String {
    let doc = serde_json::json!({
        "hosts": outcomes,
        "summary": BatchSummary::from_outcomes(outcomes),
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

/// Maps one scanned host's findings through the report generator; passes a
/// failed host straight through. The generator borrows `&self`, so one instance
/// is shared across the whole fleet.
pub fn host_report(outcome: HostOutcome, generator: &ReportGenerator) -> HostReport {
    match outcome.status {
        HostStatus::Scanned {
            findings,
            unchecked,
            ..
        } => {
            let frameworks = generator
                .generate(&findings, &unchecked)
                .iter()
                .map(posture_from_report)
                .collect();
            HostReport {
                name: outcome.name,
                target: outcome.target,
                profile: outcome.profile,
                status: HostReportStatus::Assessed { frameworks },
            }
        }
        HostStatus::Failed { error } => HostReport {
            name: outcome.name,
            target: outcome.target,
            profile: outcome.profile,
            status: HostReportStatus::Failed { error },
        },
    }
}

/// Assesses every outcome with a generator carrying that host's own resolved
/// profile, or the fleet-wide `--profile` override when one was given. The
/// per-host generator (and coverage clone) is cheap at fleet scale.
fn assess_outcomes(
    outcomes: Vec<HostOutcome>,
    scenario: Scenario,
    override_profile: Option<ComplianceProfile>,
) -> Vec<HostReport> {
    let coverage = hardener_plugins::compliance_coverage();
    outcomes
        .into_iter()
        .map(|mut outcome| {
            if let Some(profile) = override_profile {
                outcome.profile = profile;
            }
            let generator = ReportGenerator::new(
                ReportConfig {
                    scenario: scenario.clone(),
                    formats: vec![],
                    output_dir: None,
                    profile: outcome.profile,
                },
                coverage.clone(),
            );
            host_report(outcome, &generator)
        })
        .collect()
}

/// Options for `hardener batch report`.
pub struct BatchReportOptions {
    pub all: bool,
    pub host: Vec<String>,
    pub ssh: Vec<String>,
    pub concurrency: usize,
    pub config: Option<PathBuf>,
    pub framework: Option<String>,
    pub profile: Option<String>,
    pub scenario: Option<String>,
    pub format: CliOutputFormat,
    pub output: Option<String>,
    pub quiet: bool,
    pub global_key: Option<String>,
    pub global_timeout: u64,
    pub global_no_verify: bool,
}

/// CLI entry point for `hardener batch report`. Reuses the `batch scan` engine
/// (`scan_all`) verbatim, then assesses each host's findings against the chosen
/// framework/scenario and prints a fleet posture table.
pub async fn run_report(opts: BatchReportOptions) -> anyhow::Result<()> {
    let scenario = match crate::commands::report::resolve_scenario(
        opts.framework,
        opts.scenario,
        opts.quiet,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    // An explicit --profile forces one identifier scheme fleet-wide; without
    // it, each host is assessed under its own detected profile.
    let override_profile = match opts
        .profile
        .as_deref()
        .map(crate::commands::report::parse_profile)
        .transpose()
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    let config = Arc::new(load_batch_config(opts.config.as_ref(), opts.quiet));
    let outcomes = resolve_and_scan(
        opts.all,
        &opts.host,
        &opts.ssh,
        opts.concurrency,
        opts.quiet,
        opts.global_key,
        opts.global_timeout,
        opts.global_no_verify,
        "Assessing",
        config,
    )
    .await;

    let reports = assess_outcomes(outcomes, scenario, override_profile);

    let rendered = match opts.format {
        CliOutputFormat::Json => render_report_json(&reports),
        _ => render_report_text(&reports),
    };
    match opts.output {
        Some(path) => write_output(&path, &rendered)?,
        None => println!("{rendered}"),
    }

    std::process::exit(report_exit_code(&reports));
}

/// Builds the core SSH config for one host profile, applying global key/timeout
/// fallbacks for hosts (chiefly ad-hoc) that do not specify their own.
fn host_ssh_config(p: &RemoteHostProfile, timeout: u64) -> hardener_core::SshConfig {
    SshConnectionConfig {
        user: p.user.clone(),
        host: p.hostname.clone(),
        port: p.port,
        identity_file: p.key_file.as_ref().map(std::path::PathBuf::from),
        timeout: Duration::from_secs(timeout),
        strict_host_key_checking: p.host_key_checking,
    }
    .to_core_config()
}

/// Builds the `user@host:port` display string for a profile. Delegates to the
/// shared canonical form so the GUI's history keys match the CLI's.
fn display_target(p: &RemoteHostProfile) -> String {
    p.target()
}

/// Opens the shared history database for batch persistence. Best-effort: on any
/// error, returns `None` and batch scanning proceeds without persistence.
async fn open_batch_history() -> Option<Arc<ScanHistoryManager>> {
    let path = match load_scheduler_config() {
        Ok(config) => config.storage.database_path,
        Err(e) => {
            warn!("batch history disabled: scheduler config unavailable: {e}");
            return None;
        }
    };
    match ScanHistoryManager::new(&path).await {
        Ok(manager) => Some(Arc::new(manager)),
        Err(e) => {
            warn!("batch history disabled: history database open failed: {e}");
            None
        }
    }
}

/// Persists one host's grouped scan results as a completed session. Best-effort:
/// failures are logged and never affect the host's scan outcome.
async fn persist_host(
    history: &ScanHistoryManager,
    host_key: &str,
    grouped: &[(PluginMetadata, ScanResult)],
) {
    let plugins: Vec<String> = grouped
        .iter()
        .map(|(m, _)| m.plugin_id.to_string())
        .collect();
    let session_id = match history.create_session("batch", host_key, &plugins).await {
        Ok(id) => id,
        Err(e) => {
            warn!("batch history: create_session for {host_key} failed: {e}");
            return;
        }
    };
    let findings: Vec<ScanFinding> = grouped
        .iter()
        .flat_map(|(meta, result)| {
            result
                .scan_findings
                .iter()
                .map(move |f| finding_to_scan_finding(meta, f))
        })
        .collect();
    if let Err(e) = history
        .complete_session(&session_id, &findings, None, None)
        .await
    {
        warn!("batch history: complete_session for {host_key} failed: {e}");
        // Mark the half-written session failed so it doesn't linger as a ghost
        // `running` row; still best-effort, so ignore any error from this too.
        let _ = history.fail_session(&session_id, &e.to_string()).await;
    }
}

/// Best-effort per-host profile resolution: reads `/etc/os-release` through
/// the host's own executor and resolves it. Any failure (unreadable file,
/// unparseable content) falls back to `Generic` and never fails the scan.
pub(crate) async fn detect_host_profile(executor: &dyn SystemExecutor) -> ComplianceProfile {
    if let Ok(content) = executor
        .read_file(std::path::Path::new("/etc/os-release"))
        .await
        && let Ok(distro) = Distribution::from_os_release(&content)
    {
        resolve_profile(&distro)
    } else {
        ComplianceProfile::Generic
    }
}

/// Scans one host using an already-built executor. Split out so tests can inject
/// a `MockExecutor`; production callers pass a connected `SshExecutor`.
async fn scan_with_executor(
    name: String,
    target: String,
    host_key: String,
    executor: Arc<dyn SystemExecutor>,
    history: Option<Arc<ScanHistoryManager>>,
    config: &HardenerConfig,
) -> HostOutcome {
    match scan_grouped(true, executor.clone(), &CliOutputFormat::Json, config).await {
        Ok(grouped) => {
            if let Some(history) = &history {
                persist_host(history, &host_key, &grouped.results).await;
            }
            // Shared with the single-host path so a plugin whose scan did not
            // complete, or which the config never let run, contributes its
            // unchecked entry here too, instead of this host reporting a clean
            // fleet result it never verified.
            let (findings, unchecked) =
                crate::commands::report::flatten_scans(&grouped.results, &grouped.skipped);
            let counts = SeverityCounts::from_findings(&findings);
            HostOutcome {
                name,
                target,
                profile: detect_host_profile(executor.as_ref()).await,
                status: HostStatus::Scanned {
                    counts,
                    findings,
                    unchecked,
                },
            }
        }
        Err(e) => HostOutcome {
            name,
            target,
            profile: ComplianceProfile::Generic,
            status: HostStatus::Failed {
                error: e.to_string(),
            },
        },
    }
}

/// Connects to one host then scans it, capturing any connection error.
async fn scan_one(
    profile: RemoteHostProfile,
    timeout: u64,
    history: Option<Arc<ScanHistoryManager>>,
    config: &HardenerConfig,
) -> HostOutcome {
    let target = display_target(&profile);
    let host_key = host_key_of(&profile, &target);
    match SshExecutor::connect(host_ssh_config(&profile, timeout)).await {
        Ok(exec) => {
            scan_with_executor(
                profile.name,
                target,
                host_key,
                Arc::new(exec),
                history,
                config,
            )
            .await
        }
        Err(e) => HostOutcome {
            name: profile.name,
            target,
            profile: ComplianceProfile::Generic,
            status: HostStatus::Failed {
                error: e.to_string(),
            },
        },
    }
}

/// Overlays completed `(index, T)` results onto the input-ordered pre-fill.
/// Slots whose task never reported (panicked/dropped) keep their placeholder, so
/// the result is always input-length and in input order regardless of completion
/// order.
fn assemble_ordered<T>(mut prefill: Vec<T>, completed: Vec<(usize, T)>) -> Vec<T> {
    for (idx, outcome) in completed {
        if let Some(slot) = prefill.get_mut(idx) {
            *slot = outcome;
        }
    }
    prefill
}

/// Runs `op` on every profile with at most `concurrency` concurrent tasks,
/// preserving input order in the returned vec. `prefill` produces the
/// placeholder value for each profile (shown if the task panics or is dropped).
async fn run_on_all<T, F, Fut>(
    profiles: Vec<RemoteHostProfile>,
    concurrency: usize,
    prefill: impl Fn(&RemoteHostProfile) -> T,
    op: F,
) -> Vec<T>
where
    T: Send + 'static,
    F: Fn(RemoteHostProfile) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = T> + Send + 'static,
{
    let prefilled: Vec<T> = profiles.iter().map(&prefill).collect();
    let permits = Arc::new(Semaphore::new(concurrency.max(1)));
    let op = Arc::new(op);
    let mut set = tokio::task::JoinSet::new();
    for (idx, profile) in profiles.into_iter().enumerate() {
        let permits = permits.clone();
        let op = op.clone();
        set.spawn(async move {
            let _permit = permits.acquire_owned().await.expect("semaphore open");
            (idx, op(profile).await)
        });
    }
    let mut completed: Vec<(usize, T)> = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(pair) = res {
            completed.push(pair);
        }
    }
    assemble_ordered(prefilled, completed)
}

/// Returns the history key for a profile: inventory hosts use their friendly
/// `name`; ad-hoc hosts (where `name == hostname`) use the `user@host:port`
/// target string so the key is unambiguous across different SSH users/ports.
fn host_key_of(profile: &RemoteHostProfile, target: &str) -> String {
    if profile.name == profile.hostname {
        target.to_string()
    } else {
        profile.name.clone()
    }
}

/// Scans all profiles with at most `concurrency` running at once, preserving the
/// input order in the returned vec.
async fn scan_all(
    profiles: Vec<RemoteHostProfile>,
    concurrency: usize,
    timeout: u64,
    history: Option<Arc<ScanHistoryManager>>,
    config: Arc<HardenerConfig>,
) -> Vec<HostOutcome> {
    run_on_all(
        profiles,
        concurrency,
        |p| HostOutcome {
            name: p.name.clone(),
            target: display_target(p),
            profile: ComplianceProfile::Generic,
            status: HostStatus::Failed {
                error: "scan task did not complete".to_string(),
            },
        },
        move |profile| {
            let history = history.clone();
            let config = config.clone();
            async move { scan_one(profile, timeout, history, &config).await }
        },
    )
    .await
}

/// Options for `hardener batch scan`.
pub struct BatchOptions {
    pub all: bool,
    pub host: Vec<String>,
    pub ssh: Vec<String>,
    pub concurrency: usize,
    pub config: Option<PathBuf>,
    pub format: CliOutputFormat,
    pub output: Option<String>,
    pub quiet: bool,
    pub global_key: Option<String>,
    pub global_timeout: u64,
    pub global_no_verify: bool,
}

/// Resolves the selected host profiles from inventory + inline `--ssh` flags,
/// applies the global key fallback, and prints the progress line. Shared by all
/// batch subcommands so the host-resolution path lives in one place. `verb` is
/// the present participle shown in the progress line ("Scanning" / "Assessing").
/// Note: SSH-config args (`global_key`, `global_no_verify`) are grouped before
/// `quiet`/`verb`; their order differs slightly from `resolve_and_scan`.
#[allow(clippy::too_many_arguments)]
fn resolve_profiles(
    all: bool,
    host: &[String],
    ssh: &[String],
    global_key: Option<String>,
    global_no_verify: bool,
    quiet: bool,
    verb: &str,
) -> Vec<RemoteHostProfile> {
    let inventory = match hardener_core::inventory::load() {
        Ok(inv) => inv,
        Err(e) => {
            eprintln!("failed to load host inventory: {e}");
            std::process::exit(2);
        }
    };

    let inline: Vec<RemoteHostProfile> = ssh
        .iter()
        .map(|t| parse_inline(t, 22, global_key.clone(), !global_no_verify))
        .collect();

    let mut profiles = match resolve_hosts(&inventory, all, host, inline) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    // The global --ssh-key fills the gap for any host (chiefly inventory hosts)
    // that does not define its own key. Ad-hoc hosts already carry it.
    if let Some(key) = global_key.as_ref() {
        for profile in profiles.iter_mut() {
            if profile.key_file.is_none() {
                profile.key_file = Some(key.clone());
            }
        }
    }

    if !quiet {
        eprintln!("{verb} {} host(s)...", profiles.len());
    }

    profiles
}

/// The config every batch verb evaluates its hosts against: the one the
/// operator named with `--config`, else the controller's own system/user config.
///
/// Every `batch` subcommand dropped the global `--config` flag, and `batch scan`
/// and `batch report` went further and stayed pinned to the compiled-in
/// defaults, so a fleet was assessed against the raw baseline and then hardened
/// to a different policy. Remote hosts are deliberately evaluated against the
/// controller's config rather than their own: the policy belongs where the
/// operator maintains it, and a target that supplied its own could otherwise
/// weaken the audit reporting on it. Matches single-host `--ssh`, which already
/// evaluates a remote host against the local config file.
fn load_batch_config(config_path: Option<&PathBuf>, quiet: bool) -> HardenerConfig {
    let loader = match config_path {
        Some(path) => ConfigLoader::new().with_cli_config(path.clone()),
        None => ConfigLoader::new(),
    };
    match loader.load() {
        Ok(config) => config,
        Err(e) => {
            if !quiet {
                eprintln!("config load failed, using defaults: {e}");
            }
            HardenerConfig::default()
        }
    }
}

/// Resolves hosts, opens history, and scans them all concurrently. Shared entry
/// point for `batch scan` and `batch report`.
#[allow(clippy::too_many_arguments)]
async fn resolve_and_scan(
    all: bool,
    host: &[String],
    ssh: &[String],
    concurrency: usize,
    quiet: bool,
    global_key: Option<String>,
    global_timeout: u64,
    global_no_verify: bool,
    verb: &str,
    config: Arc<HardenerConfig>,
) -> Vec<HostOutcome> {
    let profiles = resolve_profiles(all, host, ssh, global_key, global_no_verify, quiet, verb);
    let history = open_batch_history().await;
    scan_all(profiles, concurrency, global_timeout, history, config).await
}

/// 0 = all clean, 1 = an apply/validation failure, 2 = a host-level error.
/// Precedence 2 > 1 > 0.
pub fn apply_exit_code(outcomes: &[ApplyOutcome]) -> i32 {
    let mut code = 0;
    for o in outcomes {
        let c = match &o.status {
            ApplyStatus::Failed { .. } => 2,
            ApplyStatus::Applied { failed, .. } if *failed > 0 => 1,
            ApplyStatus::Validated { failed, .. } if *failed > 0 => 1,
            _ => 0,
        };
        code = code.max(c);
    }
    code
}

/// Maps an `ApplyHostResult` to a host `ApplyStatus`. `execute` = true means the
/// real apply path; false = dry-run (validation reports).
fn status_from_result(execute: bool, result: &super::apply::ApplyHostResult) -> ApplyStatus {
    // Nothing ran, so neither counter pair can describe this host: "0 ok, 0
    // failed" and "0 plugins validated" both read as a clean result. The
    // single-host `apply` refuses the same situation outright.
    if result.nothing_ran() {
        return ApplyStatus::Failed {
            error: format!(
                "config disabled every selected plugin ({})",
                result.skipped_list()
            ),
        };
    }

    if execute {
        let ok = result
            .results
            .iter()
            .filter(|(_, r)| r.apply_success)
            .count();
        ApplyStatus::Applied {
            ok,
            failed: result.results.len() - ok,
        }
    } else {
        let plugins = result.validation_reports.len();
        let would_change = result
            .validation_reports
            .iter()
            .map(|r| r.validation_report_estimated_changes.len())
            .sum();
        let compliant = result
            .validation_reports
            .iter()
            .map(|r| r.validation_report_compliant_count)
            .sum();
        // The same question the single-host dry run asks, through the same
        // definition. This counted `!validation_report_is_valid`, which is
        // "has anything to say" rather than "failed", so a Medium note made
        // apply_exit_code return 1 for a host `hardener apply --dry-run` exits
        // 0 on. A fleet gate and a single-host gate disagreeing about one host
        // is worse than either being strict or lax.
        let failed = result
            .validation_reports
            .iter()
            .filter(|r| r.has_blocking_issue())
            .count();
        ApplyStatus::Validated {
            plugins,
            would_change,
            compliant,
            failed,
        }
    }
}

fn render_apply_text(outcomes: &[ApplyOutcome]) -> String {
    let mut out = String::new();
    let (mut applied, mut validated, mut failed_hosts) = (0, 0, 0);
    for o in outcomes {
        out.push_str(&host_header(&o.name, &o.target, None));
        match &o.status {
            ApplyStatus::Validated {
                plugins,
                would_change,
                compliant,
                failed,
            } => {
                validated += 1;
                let status = if *failed > 0 {
                    "validated (with failures)".yellow()
                } else if *would_change > 0 {
                    "validated (changes pending)".yellow()
                } else {
                    "validated (no changes needed)".green()
                };
                push_detail(&mut out, "status", &status.to_string());
                push_detail(
                    &mut out,
                    "result",
                    &format!(
                        "{plugins} plugin(s) checked, {would_change} change(s) pending, {failed} failed{}",
                        crate::output::compliant_suffix(*compliant)
                    ),
                );
            }
            ApplyStatus::Applied { ok, failed } => {
                applied += 1;
                let status = if *failed > 0 {
                    "partially applied".yellow()
                } else {
                    "applied".green()
                };
                push_detail(&mut out, "status", &status.to_string());
                push_detail(&mut out, "result", &format!("{ok} ok, {failed} failed"));
            }
            ApplyStatus::Failed { error } => {
                failed_hosts += 1;
                push_failed(&mut out, error);
            }
        }
        out.push('\n');
    }
    out.push_str("---\n");
    out.push_str(&format!(
        "{} host(s): {}\n",
        outcomes.len(),
        summary_parts(&[
            (applied, "applied"),
            (validated, "validated"),
            (failed_hosts, "failed"),
        ]),
    ));
    out
}

fn render_apply_json(outcomes: &[ApplyOutcome]) -> String {
    serde_json::to_string_pretty(outcomes).unwrap_or_else(|_| "[]".to_string())
}

/// 0 = all clean, 1 = a checkpoint restore failed, 2 = a host-level error.
/// Precedence 2 > 1 > 0.
pub fn rollback_exit_code(outcomes: &[RollbackOutcome]) -> i32 {
    let mut code = 0;
    for o in outcomes {
        let c = match &o.status {
            RollbackStatus::Failed { .. } => 2,
            RollbackStatus::RolledBack { failed, .. } if *failed > 0 => 1,
            _ => 0,
        };
        code = code.max(c);
    }
    code
}

fn render_rollback_text(outcomes: &[RollbackOutcome]) -> String {
    let mut out = String::new();
    let (mut rolled_back, mut previewed, mut nothing, mut failed_hosts) = (0, 0, 0, 0);
    for o in outcomes {
        out.push_str(&host_header(&o.name, &o.target, None));
        match &o.status {
            RollbackStatus::Previewed { checkpoints } => {
                previewed += 1;
                push_detail(&mut out, "status", &"previewed".yellow().to_string());
                push_detail(
                    &mut out,
                    "result",
                    &format!("would restore {checkpoints} checkpoint(s)"),
                );
            }
            RollbackStatus::RolledBack { restored, failed } => {
                rolled_back += 1;
                let status = if *failed > 0 {
                    "partially rolled back".yellow()
                } else {
                    "rolled back".green()
                };
                push_detail(&mut out, "status", &status.to_string());
                push_detail(
                    &mut out,
                    "result",
                    &format!("{restored} restored, {failed} failed"),
                );
            }
            RollbackStatus::NothingToDo => {
                nothing += 1;
                push_detail(&mut out, "status", &"ok".green().to_string());
                push_detail(&mut out, "result", "nothing to roll back");
            }
            RollbackStatus::Failed { error } => {
                failed_hosts += 1;
                push_failed(&mut out, error);
            }
        }
        out.push('\n');
    }
    out.push_str("---\n");
    out.push_str(&format!(
        "{} host(s): {}\n",
        outcomes.len(),
        summary_parts(&[
            (rolled_back, "rolled back"),
            (previewed, "previewed"),
            (nothing, "nothing to do"),
            (failed_hosts, "failed"),
        ]),
    ));
    out
}

fn render_rollback_json(outcomes: &[RollbackOutcome]) -> String {
    serde_json::to_string_pretty(outcomes).unwrap_or_else(|_| "[]".to_string())
}

/// Connects to one host, probes privilege (on execute path), then applies or
/// validates all requested plugins.
async fn apply_one(
    profile: RemoteHostProfile,
    timeout: u64,
    execute: bool,
    plugin_ids: Arc<Vec<PluginId>>,
    config: Arc<HardenerConfig>,
    checkpoint: Option<CheckpointManager>,
) -> ApplyOutcome {
    let target = display_target(&profile);
    let exec: Arc<dyn SystemExecutor> =
        match SshExecutor::connect(host_ssh_config(&profile, timeout)).await {
            Ok(e) => Arc::new(e),
            Err(e) => {
                return ApplyOutcome {
                    name: profile.name,
                    target,
                    status: ApplyStatus::Failed {
                        error: e.to_string(),
                    },
                };
            }
        };
    if execute && !is_privileged(exec.as_ref()).await {
        let error = format!("not privileged on {target} (need uid 0 or passwordless sudo)");
        return ApplyOutcome {
            name: profile.name,
            target,
            status: ApplyStatus::Failed { error },
        };
    }
    let result = super::apply::apply_host(
        exec,
        &plugin_ids,
        !execute, // dry_run
        &config,
        checkpoint,
        None, // batch logs audit itself, post-phase (Task 6)
        &CliOutputFormat::Json,
        true, // quiet: per-host rows convey the outcome
    )
    .await;
    ApplyOutcome {
        name: profile.name,
        target,
        status: status_from_result(execute, &result),
    }
}

/// Resolves a plugin filter to ids. Empty filter = every plugin. Short names
/// (e.g. "kernel") expand to the full id ("kernel-hardening").
///
/// An entry naming no plugin is an error rather than a silent omission: a
/// filter that quietly shrinks let `batch apply --plugin services` report
/// success across the fleet having hardened nothing on any host.
fn resolve_plugin_ids(filter: &[String]) -> Result<Vec<PluginId>> {
    let registry = hardener_plugins::create_plugin_registry();
    // Not `unwrap_or_default()`: an empty registry and a registry that failed
    // to enumerate are different things, and treating the failure as "no
    // plugins" would silently turn the whole batch into a no-op.
    let all = registry.list()?;
    if filter.is_empty() {
        return Ok(all.iter().map(|m| m.plugin_id.clone()).collect());
    }
    super::plugin_filter::expand(&all, filter)
}

/// Maps plugin ids to their apply-checkpoint names. Apply captures each plugin's
/// pre-change state under `{plugin_id}-pre-apply` (e.g. "ssh-hardening-pre-apply"),
/// so that is the name rollback selects per plugin.
fn pre_apply_names(plugin_ids: &[PluginId]) -> Vec<String> {
    plugin_ids
        .iter()
        .map(|id| format!("{}-pre-apply", id.as_str()))
        .collect()
}

/// Connects to one host, probes privilege (execute path only), selects each
/// plugin's latest pre-apply checkpoint, and restores them (or previews).
async fn rollback_one(
    profile: RemoteHostProfile,
    timeout: u64,
    execute: bool,
    names: Arc<Vec<String>>,
    mgr: CheckpointManager,
) -> RollbackOutcome {
    let name = profile.name.clone();
    let target = display_target(&profile);
    let fail_with = |error: String| RollbackOutcome {
        name: name.clone(),
        target: target.clone(),
        status: RollbackStatus::Failed { error },
    };

    let exec: Arc<dyn SystemExecutor> =
        match SshExecutor::connect(host_ssh_config(&profile, timeout)).await {
            Ok(e) => Arc::new(e),
            Err(e) => return fail_with(e.to_string()),
        };
    if execute && !is_privileged(exec.as_ref()).await {
        return fail_with(format!(
            "not privileged on {target} (need uid 0 or passwordless sudo)"
        ));
    }

    let host_key = host_key_for(exec.as_ref());
    let selected: Vec<Checkpoint> = match mgr.latest_named_for_host(&host_key, &names).await {
        Ok(v) => v,
        Err(e) => return fail_with(e.to_string()),
    };

    let status = if selected.is_empty() {
        RollbackStatus::NothingToDo
    } else if !execute {
        RollbackStatus::Previewed {
            checkpoints: selected.len(),
        }
    } else {
        let mut restored = 0;
        let mut failed = 0;
        for cp in &selected {
            match mgr.rollback(exec.as_ref(), &cp.checkpoint_id).await {
                Ok(r) if r.rollback_success => restored += 1,
                _ => failed += 1,
            }
        }
        RollbackStatus::RolledBack { restored, failed }
    };

    RollbackOutcome {
        name,
        target,
        status,
    }
}

/// Options for `hardener batch apply`.
pub struct BatchApplyOptions {
    pub all: bool,
    pub host: Vec<String>,
    pub ssh: Vec<String>,
    pub plugin: Vec<String>,
    pub execute: bool,
    pub concurrency: usize,
    pub config: Option<PathBuf>,
    pub format: CliOutputFormat,
    pub output: Option<String>,
    pub quiet: bool,
    pub global_key: Option<String>,
    pub global_timeout: u64,
    pub global_no_verify: bool,
}

/// CLI entry point for `hardener batch apply`. Dry-run unless `--execute`.
pub async fn run_apply(opts: BatchApplyOptions) -> anyhow::Result<()> {
    let verb = if opts.execute {
        "Applying to"
    } else {
        "Validating"
    };
    let profiles = resolve_profiles(
        opts.all,
        &opts.host,
        &opts.ssh,
        opts.global_key,
        opts.global_no_verify,
        opts.quiet,
        verb,
    );
    if opts.execute && !opts.quiet {
        eprintln!("--execute: applying to {} host(s)", profiles.len());
    }

    let plugin_ids = Arc::new(resolve_plugin_ids(&opts.plugin)?);
    let config = Arc::new(load_batch_config(opts.config.as_ref(), opts.quiet));
    let checkpoint = if opts.execute {
        Some(get_checkpoint_manager().await?)
    } else {
        None
    };
    let timeout = opts.global_timeout;
    let execute = opts.execute;

    let outcomes = run_on_all(
        profiles,
        opts.concurrency,
        |p| ApplyOutcome {
            name: p.name.clone(),
            target: display_target(p),
            status: ApplyStatus::Failed {
                error: "apply task did not complete".to_string(),
            },
        },
        move |profile| {
            let plugin_ids = plugin_ids.clone();
            let config = config.clone();
            let checkpoint = checkpoint.clone();
            async move { apply_one(profile, timeout, execute, plugin_ids, config, checkpoint).await }
        },
    )
    .await;

    // Best-effort per-host audit (execute path only), sequential on a shared logger.
    if execute && let Some(logger) = get_audit_logger().await {
        let user = effective_user();
        for o in &outcomes {
            let result = match &o.status {
                ApplyStatus::Applied { failed: 0, .. } => ActionResult::Success,
                // Defensive: execute-path statuses are Applied/Failed; this guards
                // against a dry-run status ever being mis-logged as a failure.
                ApplyStatus::Validated { .. } => continue,
                _ => ActionResult::Failure,
            };
            let _ = logger
                .log_action(
                    ActionType::Apply,
                    user.clone(),
                    format!("apply @ {}", o.target),
                    result,
                )
                .await;
        }
    }

    let rendered = match opts.format {
        CliOutputFormat::Json => render_apply_json(&outcomes),
        _ => render_apply_text(&outcomes),
    };
    match opts.output {
        Some(path) => write_output(&path, &rendered)?,
        None => println!("{rendered}"),
    }
    std::process::exit(apply_exit_code(&outcomes));
}

/// Options for `hardener batch rollback`.
pub struct BatchRollbackOptions {
    pub all: bool,
    pub host: Vec<String>,
    pub ssh: Vec<String>,
    pub plugin: Vec<String>,
    pub execute: bool,
    pub concurrency: usize,
    pub format: CliOutputFormat,
    pub output: Option<String>,
    pub quiet: bool,
    pub global_key: Option<String>,
    pub global_timeout: u64,
    pub global_no_verify: bool,
}

/// CLI entry point for `hardener batch rollback`. Dry-run unless `--execute`.
pub async fn run_rollback(opts: BatchRollbackOptions) -> anyhow::Result<()> {
    let verb = if opts.execute {
        "Rolling back"
    } else {
        "Previewing rollback for"
    };
    let profiles = resolve_profiles(
        opts.all,
        &opts.host,
        &opts.ssh,
        opts.global_key,
        opts.global_no_verify,
        opts.quiet,
        verb,
    );
    if opts.execute && !opts.quiet {
        eprintln!("--execute: rolling back {} host(s)", profiles.len());
    }

    let names = Arc::new(pre_apply_names(&resolve_plugin_ids(&opts.plugin)?));
    let mgr = get_checkpoint_manager().await?;
    let timeout = opts.global_timeout;
    let execute = opts.execute;

    let outcomes = run_on_all(
        profiles,
        opts.concurrency,
        |p| RollbackOutcome {
            name: p.name.clone(),
            target: display_target(p),
            status: RollbackStatus::Failed {
                error: "rollback task did not complete".to_string(),
            },
        },
        move |profile| {
            let names = names.clone();
            let mgr = mgr.clone();
            async move { rollback_one(profile, timeout, execute, names, mgr).await }
        },
    )
    .await;

    // Best-effort per-host audit (execute path only), sequential on a shared logger.
    if execute && let Some(logger) = get_audit_logger().await {
        let user = effective_user();
        for o in &outcomes {
            let result = match &o.status {
                RollbackStatus::RolledBack { failed: 0, .. } => ActionResult::Success,
                // Nothing-to-do and dry-run previews are not failures and not logged.
                RollbackStatus::NothingToDo | RollbackStatus::Previewed { .. } => continue,
                _ => ActionResult::Failure,
            };
            let _ = logger
                .log_action(
                    ActionType::Rollback,
                    user.clone(),
                    format!("rollback @ {}", o.target),
                    result,
                )
                .await;
        }
    }

    let rendered = match opts.format {
        CliOutputFormat::Json => render_rollback_json(&outcomes),
        _ => render_rollback_text(&outcomes),
    };
    match opts.output {
        Some(path) => write_output(&path, &rendered)?,
        None => println!("{rendered}"),
    }
    std::process::exit(rollback_exit_code(&outcomes));
}

/// CLI entry point for `hardener batch scan`.
pub async fn run(opts: BatchOptions) -> anyhow::Result<()> {
    let config = Arc::new(load_batch_config(opts.config.as_ref(), opts.quiet));
    let outcomes = resolve_and_scan(
        opts.all,
        &opts.host,
        &opts.ssh,
        opts.concurrency,
        opts.quiet,
        opts.global_key,
        opts.global_timeout,
        opts.global_no_verify,
        "Scanning",
        config,
    )
    .await;

    let rendered = match opts.format {
        CliOutputFormat::Json => render_json(&outcomes),
        _ => render_text(&outcomes),
    };
    match opts.output {
        Some(path) => write_output(&path, &rendered)?,
        None => println!("{rendered}"),
    }

    std::process::exit(exit_code(&outcomes));
}

#[cfg(test)]
mod tests;
