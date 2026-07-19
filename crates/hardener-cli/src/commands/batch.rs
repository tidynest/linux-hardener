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
    PluginMetadata, SshExecutor,
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
                if !unchecked.is_empty() {
                    let note = format!(
                        "{} check(s) could not be verified without root",
                        unchecked.len()
                    );
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
    grouped: &[(PluginMetadata, Vec<Finding>, Vec<UncheckedCheck>)],
) {
    let plugins: Vec<String> = grouped
        .iter()
        .map(|(m, _, _)| m.plugin_id.to_string())
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
        .flat_map(|(meta, fs, _)| fs.iter().map(move |f| finding_to_scan_finding(meta, f)))
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
) -> HostOutcome {
    match scan_grouped(true, executor.clone(), &CliOutputFormat::Json).await {
        Ok(grouped) => {
            if let Some(history) = &history {
                persist_host(history, &host_key, &grouped).await;
            }
            let (findings, unchecked): (Vec<Finding>, Vec<UncheckedCheck>) = grouped
                .into_iter()
                .fold((Vec::new(), Vec::new()), |(mut fs, mut us), (_, f, u)| {
                    fs.extend(f);
                    us.extend(u);
                    (fs, us)
                });
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
) -> HostOutcome {
    let target = display_target(&profile);
    let host_key = host_key_of(&profile, &target);
    match SshExecutor::connect(host_ssh_config(&profile, timeout)).await {
        Ok(exec) => {
            scan_with_executor(profile.name, target, host_key, Arc::new(exec), history).await
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
            async move { scan_one(profile, timeout, history).await }
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
) -> Vec<HostOutcome> {
    let profiles = resolve_profiles(all, host, ssh, global_key, global_no_verify, quiet, verb);
    let history = open_batch_history().await;
    scan_all(profiles, concurrency, global_timeout, history).await
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
        let failed = result
            .validation_reports
            .iter()
            .filter(|r| !r.validation_report_is_valid)
            .count();
        ApplyStatus::Validated {
            plugins,
            would_change,
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
                        "{plugins} plugin(s) checked, {would_change} change(s) pending, {failed} failed"
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
fn resolve_plugin_ids(filter: &[String]) -> Vec<PluginId> {
    let registry = hardener_plugins::create_plugin_registry();
    let all = registry.list().unwrap_or_default();
    if filter.is_empty() {
        return all.iter().map(|m| m.plugin_id.clone()).collect();
    }
    super::apply::expand_plugin_ids(&all, filter)
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

    let plugin_ids = Arc::new(resolve_plugin_ids(&opts.plugin));
    let config = Arc::new(match ConfigLoader::new().load() {
        Ok(c) => c,
        Err(e) => {
            if !opts.quiet {
                eprintln!("config load failed, using defaults: {e}");
            }
            HardenerConfig::default()
        }
    });
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

    let names = Arc::new(pre_apply_names(&resolve_plugin_ids(&opts.plugin)));
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
mod tests {
    use super::*;
    use hardener_common::types::{
        ComplianceFramework, ComplianceMapping, FindingCategory, Severity,
    };
    use hardener_compliance::Scenario;

    #[test]
    #[ignore = "visual eyeball helper, run with --ignored --nocapture"]
    fn eyeball_render_all_verbs() {
        colored::control::set_override(true);
        let scan = render_text(&[
            scanned_named(
                "web-01",
                SeverityCounts {
                    critical: 7,
                    high: 13,
                    medium: 16,
                    low: 2,
                },
            ),
            failed_named("cache"),
        ]);
        let report = render_report_text(&[
            assessed_report("web-01", vec![posture(18), posture(0)]),
            failed_report("cache"),
        ]);
        let mk = |name: &str, status| ApplyOutcome {
            name: name.into(),
            target: format!("root@{name}:22"),
            status,
        };
        let apply = render_apply_text(&[
            mk("web-01", ApplyStatus::Applied { ok: 5, failed: 0 }),
            mk("db-02", ApplyStatus::Applied { ok: 3, failed: 2 }),
            mk(
                "cache",
                ApplyStatus::Failed {
                    error: "connection refused".into(),
                },
            ),
        ]);
        let rollback = render_rollback_text(&[
            ro(RollbackStatus::Previewed { checkpoints: 2 }),
            ro(RollbackStatus::NothingToDo),
        ]);
        println!(
            "--- scan ---\n{scan}\n--- report ---\n{report}\n--- apply ---\n{apply}\n--- rollback ---\n{rollback}"
        );
        colored::control::unset_override();
    }

    fn ro(status: RollbackStatus) -> RollbackOutcome {
        RollbackOutcome {
            name: "n".to_string(),
            target: "t".to_string(),
            status,
        }
    }

    #[test]
    fn strip_ansi_removes_colour_escapes_and_keeps_text() {
        // Bold-cyan + reset around the name, multi-parameter and plain runs.
        let coloured =
            "==== \x1b[1;36mweb-01\x1b[0m  u@web-01:22 ====\n  status:    \x1b[32mok\x1b[0m\n";
        let plain = strip_ansi(coloured);
        assert_eq!(
            plain, "==== web-01  u@web-01:22 ====\n  status:    ok\n",
            "escapes stripped, text and layout intact"
        );
        assert!(!plain.contains('\x1b'), "no ESC bytes remain");
        // A string with no escapes passes through byte-identical (JSON path).
        let json = "{\n  \"hosts\": []\n}";
        assert_eq!(strip_ansi(json), json);
    }

    #[test]
    fn write_output_saves_colour_free_file() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("fleet.txt");
        let path = path.to_str().unwrap();
        write_output(path, "\x1b[1;36mweb-01\x1b[0m  \x1b[31mFAILED\x1b[0m\n").unwrap();
        let saved = std::fs::read_to_string(path).unwrap();
        assert_eq!(
            saved, "web-01  FAILED\n",
            "--output files carry no ANSI escapes"
        );
    }

    #[test]
    fn rollback_exit_code_follows_precedence() {
        assert_eq!(
            rollback_exit_code(&[ro(RollbackStatus::Previewed { checkpoints: 3 })]),
            0
        );
        assert_eq!(rollback_exit_code(&[ro(RollbackStatus::NothingToDo)]), 0);
        assert_eq!(
            rollback_exit_code(&[ro(RollbackStatus::RolledBack {
                restored: 2,
                failed: 0
            })]),
            0
        );
        assert_eq!(
            rollback_exit_code(&[ro(RollbackStatus::RolledBack {
                restored: 1,
                failed: 1
            })]),
            1
        );
        assert_eq!(
            rollback_exit_code(&[ro(RollbackStatus::Failed {
                error: "x".to_string()
            })]),
            2
        );
        assert_eq!(
            rollback_exit_code(&[
                ro(RollbackStatus::RolledBack {
                    restored: 0,
                    failed: 1
                }),
                ro(RollbackStatus::Failed {
                    error: "x".to_string()
                }),
            ]),
            2
        );
    }

    #[test]
    fn render_rollback_text_sections_and_summary() {
        colored::control::set_override(false);
        let text = render_rollback_text(&[
            ro(RollbackStatus::Previewed { checkpoints: 2 }),
            ro(RollbackStatus::Failed {
                error: "down".to_string(),
            }),
        ]);
        assert!(
            text.contains("==== n"),
            "host header names the host: {text}"
        );
        assert!(text.contains("  t "), "header carries the target: {text}");
        assert!(
            text.contains("status:    previewed"),
            "preview status line: {text}"
        );
        assert!(
            text.contains("would restore 2 checkpoint(s)"),
            "preview result: {text}"
        );
        assert!(text.contains("status:    FAILED"), "failed status: {text}");
        assert!(text.contains("error:     down"), "error line: {text}");
        assert!(
            text.contains("---\n2 host(s): 1 previewed, 1 failed"),
            "summary footer omits zero categories: {text}"
        );
    }

    #[test]
    fn render_rollback_text_partial_and_nothing_to_do() {
        colored::control::set_override(false);
        let text = render_rollback_text(&[
            ro(RollbackStatus::RolledBack {
                restored: 1,
                failed: 1,
            }),
            ro(RollbackStatus::NothingToDo),
        ]);
        assert!(
            text.contains("status:    partially rolled back"),
            "partial restore is flagged: {text}"
        );
        assert!(text.contains("1 restored, 1 failed"), "counts: {text}");
        assert!(
            text.contains("nothing to roll back"),
            "nothing-to-do host says so: {text}"
        );
        assert!(
            text.contains("2 host(s): 1 rolled back, 1 nothing to do"),
            "summary footer: {text}"
        );
    }

    #[test]
    fn render_rollback_json_tags_state() {
        let json = render_rollback_json(&[ro(RollbackStatus::RolledBack {
            restored: 2,
            failed: 0,
        })]);
        assert!(json.contains("\"state\": \"rolledback\""), "json: {json}");
    }

    #[test]
    fn pre_apply_names_maps_ids_to_checkpoint_names() {
        let ids = vec![
            PluginId::new("ssh-hardening"),
            PluginId::new("kernel-hardening"),
        ];
        assert_eq!(
            pre_apply_names(&ids),
            vec![
                "ssh-hardening-pre-apply".to_string(),
                "kernel-hardening-pre-apply".to_string(),
            ]
        );
    }

    #[test]
    fn pre_apply_names_covers_every_registered_plugin() {
        // Guards the writer<->reader naming contract: rollback derives each
        // plugin's checkpoint name as `{plugin_id}-pre-apply`, which every
        // plugin's apply path must honour (see create_checkpoint_for_apply).
        // Regression for the services plugin, whose id (`service-minimisation`)
        // does not follow the `<x>-hardening` shape and once mismatched its
        // checkpoint name (`services-hardening-pre-apply`), making rollback a
        // silent no-op for it.
        let registry = hardener_plugins::create_plugin_registry();
        let ids: Vec<PluginId> = registry
            .list()
            .unwrap_or_default()
            .iter()
            .map(|m| m.plugin_id.clone())
            .collect();
        assert!(!ids.is_empty(), "registry should list plugins");
        let names = pre_apply_names(&ids);
        for (id, name) in ids.iter().zip(&names) {
            assert_eq!(name, &format!("{}-pre-apply", id.as_str()));
        }
        assert!(
            names.iter().any(|n| n == "service-minimisation-pre-apply"),
            "services plugin must be covered by rollback selection: {names:?}"
        );
    }

    fn posture(failing: usize) -> FrameworkPosture {
        FrameworkPosture {
            framework: "CIS".into(),
            score: 90.0,
            passing: 10,
            failing,
            manual_review: 2,
            not_applicable: 0,
            total: 12 + failing,
        }
    }
    fn assessed_report(name: &str, frameworks: Vec<FrameworkPosture>) -> HostReport {
        HostReport {
            name: name.into(),
            target: format!("u@{name}:22"),
            profile: ComplianceProfile::Generic,
            status: HostReportStatus::Assessed { frameworks },
        }
    }
    fn failed_report(name: &str) -> HostReport {
        HostReport {
            name: name.into(),
            target: format!("u@{name}:22"),
            profile: ComplianceProfile::Generic,
            status: HostReportStatus::Failed {
                error: "refused".into(),
            },
        }
    }

    fn report_config_server() -> ReportConfig {
        ReportConfig {
            scenario: Scenario::Server,
            formats: vec![],
            output_dir: None,
            profile: ComplianceProfile::default(),
        }
    }

    #[test]
    fn host_report_assesses_scanned_and_passes_failures_through() {
        let generator = ReportGenerator::new(
            report_config_server(),
            hardener_plugins::compliance_coverage(),
        );

        // A failed host is carried through untouched (no generator call).
        let failed = host_report(failed(), &generator);
        assert!(matches!(failed.status, HostReportStatus::Failed { .. }));

        // A scanned host (empty findings) is assessed: every framework posture has
        // coherent counts that sum to its total.
        let scanned = HostOutcome {
            name: "web-01".into(),
            target: "u@web-01:22".into(),
            profile: ComplianceProfile::Generic,
            status: HostStatus::Scanned {
                counts: SeverityCounts::default(),
                findings: vec![],
                unchecked: vec![],
            },
        };
        let report = host_report(scanned, &generator);
        match report.status {
            HostReportStatus::Assessed { frameworks } => {
                assert!(!frameworks.is_empty(), "server scenario yields frameworks");
                for f in &frameworks {
                    assert_eq!(
                        f.passing + f.failing + f.manual_review + f.not_applicable,
                        f.total,
                        "posture counts sum to total",
                    );
                }
            }
            HostReportStatus::Failed { .. } => panic!("scanned host should be assessed"),
        }
    }

    #[test]
    fn host_report_treats_unchecked_covered_control_as_manual_review_not_pass() {
        // STIG has no curated catalogue, so with a single-mapping coverage set
        // the resulting report has exactly one control: whatever the pam-minlen
        // check covers. This isolates the assertion from the curated CIS/ISO
        // catalogues, which always carry unrelated ManualReview entries.
        let stig_mapping = ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "RHEL-08-020230".into(),
            compliance_control_title: "RHEL 8 passwords must have a minimum of 15 characters"
                .into(),
            compliance_section: None,
        };
        let generator = ReportGenerator::new(
            ReportConfig {
                scenario: Scenario::Custom(vec![ComplianceFramework::STIG]),
                formats: vec![],
                output_dir: None,
                profile: ComplianceProfile::Generic,
            },
            vec![stig_mapping.clone()],
        );

        // A host that scanned with zero findings but flagged the minlen check as
        // unchecked (unreadable pwquality.conf without root) must not silently
        // report the control it covers as Pass: the absence of a finding proves
        // nothing when the check never ran.
        let unchecked = vec![UncheckedCheck {
            unchecked_check_id: "pam-minlen".into(),
            unchecked_title: "PAM setting: minlen".into(),
            unchecked_category: FindingCategory::Authentication,
            unchecked_reason: "reading /etc/security/pwquality.conf requires root".into(),
            unchecked_compliance: vec![stig_mapping],
        }];
        let outcome = HostOutcome {
            name: "web-01".into(),
            target: "u@web-01:22".into(),
            profile: ComplianceProfile::Generic,
            status: HostStatus::Scanned {
                counts: SeverityCounts::default(),
                findings: vec![],
                unchecked,
            },
        };
        let report = host_report(outcome, &generator);
        let HostReportStatus::Assessed { frameworks } = report.status else {
            panic!("scanned host should be assessed");
        };
        let stig = frameworks
            .iter()
            .find(|f| f.framework == "STIG")
            .expect("STIG framework present in the custom scenario");
        assert_eq!(stig.total, 1, "single-mapping coverage yields one control");
        assert_eq!(
            stig.manual_review, 1,
            "unchecked control must land in manual_review, not silently pass: {stig:?}"
        );
        assert_eq!(
            stig.passing, 0,
            "must not auto-pass on absence of a finding"
        );
    }

    #[test]
    fn report_rollup_aggregates_failing_per_framework() {
        let reports = vec![
            assessed_report("web-01", vec![posture(18)]),
            assessed_report("db-02", vec![posture(6)]),
            failed_report("cache"),
        ];
        let r = ReportRollup::from_reports(&reports);
        assert_eq!(r.hosts_total, 3);
        assert_eq!(r.hosts_assessed, 2);
        assert_eq!(r.hosts_failed, 1);
        assert_eq!(r.frameworks.len(), 1);
        assert_eq!(r.frameworks[0].framework, "CIS");
        assert_eq!(r.frameworks[0].failing, 24, "18 + 6 across the fleet");
    }

    #[test]
    fn report_rollup_groups_multiple_frameworks_per_host() {
        // The default `server` scenario assesses each host against CIS + STIG, so
        // the rollup must group per framework, accumulating across hosts.
        let fw = |name: &str, failing: usize| FrameworkPosture {
            framework: name.into(),
            score: 90.0,
            passing: 10,
            failing,
            manual_review: 0,
            not_applicable: 0,
            total: 10 + failing,
        };
        let reports = vec![
            assessed_report("web", vec![fw("CIS", 3), fw("STIG", 1)]),
            assessed_report("db", vec![fw("CIS", 2), fw("STIG", 4)]),
        ];
        let r = ReportRollup::from_reports(&reports);
        assert_eq!(r.hosts_assessed, 2);
        assert_eq!(r.frameworks.len(), 2, "CIS and STIG grouped separately");
        assert_eq!(
            r.frameworks[0].framework, "CIS",
            "first-seen order preserved"
        );
        assert_eq!(r.frameworks[0].failing, 5, "CIS 3 + 2");
        assert_eq!(r.frameworks[1].framework, "STIG");
        assert_eq!(r.frameworks[1].failing, 5, "STIG 1 + 4");
    }

    #[test]
    fn report_text_render_has_sections_and_rollup() {
        colored::control::set_override(false);
        let text = render_report_text(&[
            assessed_report("web-01", vec![posture(18)]),
            failed_report("cache"),
        ]);
        assert!(
            text.contains("==== web-01  u@web-01:22  [generic profile] "),
            "header carries name, target and profile: {text}"
        );
        assert!(
            text.contains("status:    ok (1 framework(s) assessed)"),
            "assessed status line: {text}"
        );
        assert!(
            text.contains("CIS:        90.0%  10 pass, 18 fail, 2 manual, 0 n/a"),
            "per-framework posture line: {text}"
        );
        assert!(text.contains("status:    FAILED"), "failed status: {text}");
        assert!(
            text.contains("error:     refused"),
            "failed section surfaces the error: {text}"
        );
        assert!(
            text.contains("---\n1 of 2 hosts assessed, 1 failed"),
            "rollup footer kept: {text}"
        );
        assert!(text.contains("CIS: 18 failing controls"));
    }

    #[test]
    fn report_json_render_is_valid_and_discriminates_status() {
        let json = render_report_json(&[
            assessed_report("web-01", vec![posture(18)]),
            failed_report("cache"),
        ]);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["hosts"][0]["status"], "assessed");
        assert_eq!(v["hosts"][0]["frameworks"][0]["framework"], "CIS");
        assert_eq!(v["hosts"][1]["status"], "failed");
        assert!(
            v["hosts"][1]["frameworks"].is_null(),
            "failed host has no frameworks"
        );
        assert_eq!(v["summary"]["hosts_assessed"], 1);
        assert_eq!(v["summary"]["frameworks"][0]["failing"], 18);
    }

    #[test]
    fn report_exit_code_tiers() {
        // All compliant -> 0
        assert_eq!(
            report_exit_code(&[assessed_report("a", vec![posture(0)])]),
            0
        );
        // A failing control -> 1
        assert_eq!(
            report_exit_code(&[assessed_report("a", vec![posture(3)])]),
            1
        );
        // A host error dominates a failing control -> 2 (failed last)
        assert_eq!(
            report_exit_code(&[assessed_report("a", vec![posture(3)]), failed_report("b")]),
            2
        );
        // A host error dominates regardless of order -> 2 (failed first)
        assert_eq!(
            report_exit_code(&[failed_report("b"), assessed_report("a", vec![posture(3)])]),
            2
        );
        // Manual-review present but zero failing is NOT a failure -> 0
        let manual_only = FrameworkPosture {
            framework: "CIS".into(),
            score: 80.0,
            passing: 7,
            failing: 0,
            manual_review: 5,
            not_applicable: 0,
            total: 12,
        };
        assert_eq!(
            report_exit_code(&[assessed_report("a", vec![manual_only])]),
            0
        );
        // Empty -> 0
        assert_eq!(report_exit_code(&[]), 0);
    }

    fn finding(sev: Severity) -> Finding {
        Finding {
            finding_category: FindingCategory::Kernel,
            finding_current_value: String::new(),
            finding_description: String::new(),
            finding_explanation: String::new(),
            finding_id: "x".into(),
            finding_impact: String::new(),
            finding_recommended_value: String::new(),
            finding_remediation_steps: vec![],
            finding_severity: sev,
            finding_title: "t".into(),
            finding_compliance: vec![],
            finding_policy_exception: None,
        }
    }

    fn scanned(total_high: usize) -> HostOutcome {
        HostOutcome {
            name: "h".into(),
            target: "u@h:22".into(),
            profile: ComplianceProfile::Generic,
            status: HostStatus::Scanned {
                counts: SeverityCounts {
                    high: total_high,
                    ..Default::default()
                },
                findings: vec![],
                unchecked: vec![],
            },
        }
    }

    fn failed() -> HostOutcome {
        HostOutcome {
            name: "h".into(),
            target: "u@h:22".into(),
            profile: ComplianceProfile::Generic,
            status: HostStatus::Failed {
                error: "boom".into(),
            },
        }
    }

    fn scanned_named(name: &str, counts: SeverityCounts) -> HostOutcome {
        HostOutcome {
            name: name.into(),
            target: format!("u@{name}:22"),
            profile: ComplianceProfile::Generic,
            status: HostStatus::Scanned {
                counts,
                findings: vec![],
                unchecked: vec![],
            },
        }
    }

    fn failed_named(name: &str) -> HostOutcome {
        HostOutcome {
            name: name.into(),
            target: format!("u@{name}:22"),
            profile: ComplianceProfile::Generic,
            status: HostStatus::Failed {
                error: "did not complete".into(),
            },
        }
    }

    #[test]
    fn exit_code_tiers() {
        assert_eq!(exit_code(&[scanned(0)]), 0);
        assert_eq!(exit_code(&[scanned(0), scanned(3)]), 1);
        assert_eq!(exit_code(&[scanned(3), failed()]), 2);
        assert_eq!(exit_code(&[]), 0);
    }

    fn inv() -> HostsConfig {
        HostsConfig {
            hosts: vec![profile("web-01"), profile("db-02")],
        }
    }
    fn profile(name: &str) -> RemoteHostProfile {
        RemoteHostProfile {
            name: name.into(),
            hostname: format!("{name}.local"),
            user: Some("admin".into()),
            port: 22,
            key_file: None,
            host_key_checking: true,
        }
    }

    #[test]
    fn resolve_all_returns_inventory() {
        let r = resolve_hosts(&inv(), true, &[], vec![]).unwrap();
        assert_eq!(r.len(), 2);
    }
    #[test]
    fn resolve_named_subset() {
        let r = resolve_hosts(&inv(), false, &["db-02".into()], vec![]).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].name, "db-02");
    }
    #[test]
    fn resolve_unknown_name_errors() {
        assert!(resolve_hosts(&inv(), false, &["nope".into()], vec![]).is_err());
    }
    #[test]
    fn resolve_dedups_inline_against_inventory() {
        let inline = vec![parse_inline("admin@web-01", 22, None, true)];
        let r = resolve_hosts(&inv(), true, &[], inline).unwrap();
        assert_eq!(r.len(), 2, "inline duplicate of inventory host is dropped");
    }
    #[test]
    fn resolve_empty_errors() {
        assert!(resolve_hosts(&HostsConfig::default(), false, &[], vec![]).is_err());
    }
    #[test]
    fn parse_inline_splits_user() {
        let p = parse_inline("root@10.0.0.5", 2222, None, false);
        assert_eq!(p.user.as_deref(), Some("root"));
        assert_eq!(p.hostname, "10.0.0.5");
        assert_eq!(p.port, 2222);
        assert!(!p.host_key_checking);
    }

    #[test]
    fn parse_inline_port_suffix_overrides_default() {
        let p = parse_inline("root@10.0.0.5:2200", 22, None, true);
        assert_eq!(p.user.as_deref(), Some("root"));
        assert_eq!(p.hostname, "10.0.0.5", "host stripped of :port");
        assert_eq!(p.port, 2200, ":port suffix overrides the default");
    }

    #[test]
    fn parse_inline_port_suffix_without_user() {
        let p = parse_inline("web-01:2022", 22, None, true);
        assert_eq!(p.user, None);
        assert_eq!(p.hostname, "web-01");
        assert_eq!(p.port, 2022);
    }

    #[test]
    fn parse_inline_non_numeric_suffix_is_part_of_host() {
        // A trailing ":word" is not a port; keep it in the host, use the default.
        let p = parse_inline("host:notaport", 22, None, true);
        assert_eq!(p.hostname, "host:notaport");
        assert_eq!(p.port, 22);
    }

    #[test]
    fn parse_inline_bare_ipv6_keeps_default_port() {
        // Unbracketed IPv6 has no unambiguous :port form; leave it intact.
        let p = parse_inline("::1", 22, None, true);
        assert_eq!(p.hostname, "::1");
        assert_eq!(p.port, 22);
    }

    #[test]
    fn counts_tally_by_severity() {
        let f = vec![
            finding(Severity::Critical),
            finding(Severity::High),
            finding(Severity::High),
            finding(Severity::Low),
        ];
        let c = SeverityCounts::from_findings(&f);
        assert_eq!(
            c,
            SeverityCounts {
                critical: 1,
                high: 2,
                medium: 0,
                low: 1
            }
        );
        assert_eq!(c.total(), 4);
    }

    #[test]
    fn summary_aggregates() {
        let outcomes = vec![scanned(2), failed(), scanned(0)];
        let s = BatchSummary::from_outcomes(&outcomes);
        assert_eq!(s.hosts_total, 3);
        assert_eq!(s.hosts_scanned, 2);
        assert_eq!(s.hosts_failed, 1);
        assert_eq!(s.high, 2);
        assert_eq!(s.total, 2);
    }

    #[test]
    fn text_render_has_rollup() {
        let text = render_text(&[scanned(1), failed()]);
        assert!(text.contains("FAILED"));
        assert!(text.contains("2 host(s): 1 scanned, 1 failed"));
    }

    #[test]
    fn json_render_is_valid() {
        let json = render_json(&[scanned(1)]);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["summary"]["hosts_scanned"], 1);
        assert_eq!(v["hosts"][0]["status"], "scanned");
    }

    #[tokio::test]
    async fn scan_with_mock_executor_yields_scanned() {
        use hardener_core::MockExecutor;
        use std::sync::Arc;
        let exec = Arc::new(MockExecutor::new());
        let outcome =
            scan_with_executor("h".into(), "u@h:22".into(), "u@h:22".into(), exec, None).await;
        assert!(
            matches!(outcome.status, HostStatus::Scanned { .. }),
            "a mock executor should yield a Scanned outcome, not a connection failure",
        );
        assert_eq!(
            outcome.profile,
            ComplianceProfile::Generic,
            "no os-release on the mock host resolves to Generic, never an error",
        );
    }

    /// Scans a mock host whose `/etc/os-release` declares Rocky Linux 10.
    async fn rocky10_outcome() -> HostOutcome {
        use hardener_core::MockExecutor;
        let exec = Arc::new(MockExecutor::new().with_file(
            "/etc/os-release",
            "NAME=\"Rocky Linux\"\nID=\"rocky\"\nVERSION_ID=\"10.0\"\n",
        ));
        scan_with_executor("r10".into(), "u@r10:22".into(), "r10".into(), exec, None).await
    }

    #[tokio::test]
    async fn scan_resolves_rocky_10_profile_and_report_carries_it() {
        let outcome = rocky10_outcome().await;
        assert!(matches!(outcome.status, HostStatus::Scanned { .. }));
        assert_eq!(outcome.profile, ComplianceProfile::Rhel10);

        // Without an override the host's own profile rides into its report
        // row, and the JSON document exposes it per host.
        let reports = assess_outcomes(vec![outcome], Scenario::Server, None);
        assert_eq!(reports[0].profile, ComplianceProfile::Rhel10);
        let json = render_report_json(&reports);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["hosts"][0]["profile"], "rhel10");
    }

    #[tokio::test]
    async fn batch_report_profile_override_forces_every_host() {
        let outcome = rocky10_outcome().await;
        assert_eq!(outcome.profile, ComplianceProfile::Rhel10);

        let reports = assess_outcomes(
            vec![outcome],
            Scenario::Server,
            Some(ComplianceProfile::Generic),
        );
        assert_eq!(
            reports[0].profile,
            ComplianceProfile::Generic,
            "an explicit --profile beats per-host detection",
        );
    }

    #[tokio::test]
    async fn scan_all_empty_is_empty() {
        let out = scan_all(vec![], 4, 1, None).await;
        assert!(out.is_empty());
    }

    #[test]
    fn parse_inline_without_user() {
        let p = parse_inline("host.only", 22, None, true);
        assert!(p.user.is_none());
        assert_eq!(p.hostname, "host.only");
        assert_eq!(p.name, "host.only");
        assert!(p.host_key_checking);
    }

    #[test]
    fn resolve_inline_only() {
        let r = resolve_hosts(
            &HostsConfig::default(),
            false,
            &[],
            vec![parse_inline("ops@cache", 22, None, true)],
        )
        .unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].name, "cache");
    }

    #[test]
    fn resolve_multiple_names_preserve_order() {
        let r = resolve_hosts(&inv(), false, &["db-02".into(), "web-01".into()], vec![]).unwrap();
        let names: Vec<&str> = r.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["db-02", "web-01"]);
    }

    #[test]
    fn resolve_all_plus_noncolliding_inline() {
        let r = resolve_hosts(
            &inv(),
            true,
            &[],
            vec![parse_inline("u@extra", 22, None, true)],
        )
        .unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(r[2].name, "extra");
    }

    #[test]
    fn counts_exclude_info() {
        let f = vec![finding(Severity::Info), finding(Severity::Critical)];
        let c = SeverityCounts::from_findings(&f);
        assert_eq!(c.critical, 1);
        assert_eq!(c.total(), 1);
    }

    #[test]
    fn summary_mixed_severities() {
        let s = BatchSummary::from_outcomes(&[scanned_named(
            "a",
            SeverityCounts {
                critical: 1,
                high: 2,
                medium: 3,
                low: 4,
            },
        )]);
        assert_eq!(s.critical, 1);
        assert_eq!(s.high, 2);
        assert_eq!(s.medium, 3);
        assert_eq!(s.low, 4);
        assert_eq!(s.total, 10);
        assert_eq!(s.hosts_scanned, 1);
        assert_eq!(s.hosts_failed, 0);
    }

    #[test]
    fn text_render_scanned_section_shows_counts() {
        colored::control::set_override(false);
        let text = render_text(&[scanned_named(
            "web-01",
            SeverityCounts {
                high: 2,
                ..Default::default()
            },
        )]);
        assert!(
            text.contains("==== web-01  u@web-01:22 "),
            "header carries name and target: {text}"
        );
        assert!(text.contains("status:    ok"), "status line: {text}");
        assert!(
            text.contains("findings:  2 total (0 crit, 2 high, 0 med, 0 low)"),
            "findings line breaks down severities: {text}"
        );
    }

    #[test]
    fn text_render_unchecked_line_only_when_nonzero() {
        colored::control::set_override(false);
        use hardener_common::types::FindingCategory;
        let unchecked = vec![UncheckedCheck {
            unchecked_check_id: "pam-minlen".into(),
            unchecked_title: "PAM setting: minlen".into(),
            unchecked_category: FindingCategory::Authentication,
            unchecked_reason: "requires root".into(),
            unchecked_compliance: vec![],
        }];
        let with = render_text(&[HostOutcome {
            name: "web-01".into(),
            target: "u@web-01:22".into(),
            profile: ComplianceProfile::Generic,
            status: HostStatus::Scanned {
                counts: SeverityCounts::default(),
                findings: vec![],
                unchecked,
            },
        }]);
        assert!(
            with.contains("unchecked: 1 check(s) could not be verified without root"),
            "non-zero unchecked is listed: {with}"
        );

        let without = render_text(&[scanned_named("web-01", SeverityCounts::default())]);
        assert!(
            !without.contains("unchecked"),
            "zero unchecked prints no line: {without}"
        );
        assert!(
            without.contains("findings:  none"),
            "clean host reads none: {without}"
        );
        assert!(without.contains("---\n"), "summary footer kept: {without}");
    }

    #[test]
    fn json_failed_host_shape() {
        let json = render_json(&[failed_named("cache")]);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["hosts"][0]["status"], "failed");
        assert!(v["hosts"][0]["error"].is_string());
        assert!(
            v["hosts"][0]["counts"].is_null(),
            "failed host has no counts"
        );
        assert!(
            v["hosts"][0]["findings"].is_null(),
            "failed host has no findings"
        );
    }

    #[test]
    fn assemble_ordered_preserves_order_and_keeps_placeholder() {
        let prefill = vec![failed_named("a"), failed_named("b"), failed_named("c")];
        // completed out of order, and index 1 ("b") never reports
        let completed = vec![
            (2, scanned_named("c", SeverityCounts::default())),
            (0, scanned_named("a", SeverityCounts::default())),
        ];
        let out = assemble_ordered(prefill, completed);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].name, "a");
        assert_eq!(out[1].name, "b");
        assert_eq!(out[2].name, "c");
        assert!(matches!(out[0].status, HostStatus::Scanned { .. }));
        assert!(
            matches!(out[1].status, HostStatus::Failed { .. }),
            "dropped task keeps placeholder"
        );
        assert!(matches!(out[2].status, HostStatus::Scanned { .. }));
    }

    #[tokio::test]
    async fn scan_all_preserves_order_and_isolates_failures() {
        // Three unreachable hosts (loopback port 1 is always refused). Each must
        // come back Failed, in input order, with none lost, exercising the real
        // spawn -> bounded-collect -> assemble_ordered wiring end to end.
        let hosts: Vec<RemoteHostProfile> = ["alpha", "bravo", "charlie"]
            .iter()
            .map(|name| RemoteHostProfile {
                name: (*name).to_string(),
                hostname: "127.0.0.1".to_string(),
                user: Some("nobody".to_string()),
                port: 1,
                key_file: None,
                host_key_checking: false,
            })
            .collect();

        let out = scan_all(hosts, 2, 1, None).await;

        assert_eq!(out.len(), 3, "every host appears, none dropped");
        assert_eq!(
            out.iter().map(|o| o.name.as_str()).collect::<Vec<_>>(),
            ["alpha", "bravo", "charlie"],
            "output preserves input order despite concurrent completion",
        );
        assert!(
            out.iter()
                .all(|o| matches!(o.status, HostStatus::Failed { .. })),
            "unreachable hosts are isolated as Failed, not aborting the batch",
        );
    }

    #[test]
    fn text_render_failed_row_shows_error() {
        let out = render_text(&[HostOutcome {
            name: "cache".into(),
            target: "u@cache:22".into(),
            profile: ComplianceProfile::Generic,
            status: HostStatus::Failed {
                error: "connection refused".into(),
            },
        }]);
        assert!(out.contains("cache"));
        assert!(
            out.contains("connection refused"),
            "failed row must surface the error"
        );
        assert!(out.contains("FAILED"));
    }

    #[tokio::test]
    async fn batch_scan_persists_session_per_host() {
        use hardener_core::MockExecutor;
        use hardener_scheduler::ScanHistoryManager;
        use hardener_scheduler::db::SessionFilter;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let mgr = Arc::new(
            ScanHistoryManager::new(&dir.path().join("scheduler.db"))
                .await
                .unwrap(),
        );

        let exec = Arc::new(MockExecutor::new());
        let outcome = scan_with_executor(
            "web-01".into(),
            "root@web-01:22".into(),
            "web-01".into(),
            exec,
            Some(mgr.clone()),
        )
        .await;
        assert!(matches!(outcome.status, HostStatus::Scanned { .. }));

        // One completed session was persisted under the host_key.
        let sessions = mgr
            .list_sessions(&SessionFilter {
                host: Some("web-01".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(sessions.len(), 1, "one session persisted for the host");
        assert_eq!(sessions[0].host_identifier, "web-01");
        assert_eq!(sessions[0].status, "completed");
    }

    #[tokio::test]
    async fn run_on_all_preserves_order_and_prefill() {
        let profiles: Vec<RemoteHostProfile> = (0..3)
            .map(|i| RemoteHostProfile {
                name: format!("h{i}"),
                hostname: format!("h{i}"),
                user: None,
                port: 22,
                key_file: None,
                host_key_checking: true,
            })
            .collect();
        let out = run_on_all(
            profiles,
            2,
            |p| format!("missing:{}", p.name),
            |p| async move { p.name.clone() },
        )
        .await;
        assert_eq!(out, vec!["h0", "h1", "h2"], "results stay in input order");
    }

    #[test]
    fn host_key_of_uses_name_for_inventory_and_target_for_adhoc() {
        // Inventory host: friendly name differs from hostname -> keyed by name.
        let inv = RemoteHostProfile {
            name: "web1".into(),
            hostname: "10.0.0.5".into(),
            user: Some("admin".into()),
            port: 22,
            key_file: None,
            host_key_checking: true,
        };
        assert_eq!(host_key_of(&inv, "root@10.0.0.5:22"), "web1");

        // Ad-hoc host: name == hostname (set by parse_inline) -> keyed by the
        // full target string so different users/ports remain distinct.
        let adhoc = RemoteHostProfile {
            name: "10.0.0.9".into(),
            hostname: "10.0.0.9".into(),
            user: Some("root".into()),
            port: 22,
            key_file: None,
            host_key_checking: false,
        };
        assert_eq!(host_key_of(&adhoc, "root@10.0.0.9:22"), "root@10.0.0.9:22");
    }

    #[test]
    fn resolve_plugin_ids_empty_means_all() {
        let all = resolve_plugin_ids(&[]);
        assert!(!all.is_empty(), "empty filter selects every plugin");
        let one = resolve_plugin_ids(&["kernel".to_string()]);
        assert_eq!(one.len(), 1, "short name resolves to one plugin");
        assert!(one[0].as_str().starts_with("kernel"));
    }

    #[test]
    fn apply_exit_code_precedence() {
        let mk = |status| ApplyOutcome {
            name: "h".into(),
            target: "h".into(),
            status,
        };
        assert_eq!(
            apply_exit_code(&[mk(ApplyStatus::Applied { ok: 3, failed: 0 })]),
            0
        );
        assert_eq!(
            apply_exit_code(&[mk(ApplyStatus::Validated {
                plugins: 3,
                would_change: 1,
                failed: 0
            })]),
            0
        );
        assert_eq!(
            apply_exit_code(&[mk(ApplyStatus::Applied { ok: 2, failed: 1 })]),
            1
        );
        assert_eq!(
            apply_exit_code(&[mk(ApplyStatus::Validated {
                plugins: 2,
                would_change: 0,
                failed: 1
            })]),
            1
        );
        assert_eq!(
            apply_exit_code(&[
                mk(ApplyStatus::Applied { ok: 0, failed: 2 }),
                mk(ApplyStatus::Failed {
                    error: "connect".into()
                }),
            ]),
            2
        );
    }

    #[test]
    fn render_apply_text_sections_and_summary() {
        colored::control::set_override(false);
        let mk = |name: &str, status| ApplyOutcome {
            name: name.into(),
            target: format!("root@{name}:22"),
            status,
        };
        let text = render_apply_text(&[
            mk("web-01", ApplyStatus::Applied { ok: 5, failed: 0 }),
            mk("db-02", ApplyStatus::Applied { ok: 3, failed: 2 }),
            mk(
                "cache",
                ApplyStatus::Failed {
                    error: "connection refused".into(),
                },
            ),
        ]);
        assert!(
            text.contains("==== web-01  root@web-01:22 "),
            "header carries name and target: {text}"
        );
        assert!(
            text.contains("status:    applied"),
            "clean apply is green ok: {text}"
        );
        assert!(text.contains("result:    5 ok, 0 failed"), "counts: {text}");
        assert!(
            text.contains("status:    partially applied"),
            "partial apply is flagged: {text}"
        );
        assert!(text.contains("status:    FAILED"), "failed status: {text}");
        assert!(
            text.contains("error:     connection refused"),
            "error surfaces: {text}"
        );
        assert!(
            text.contains("---\n3 host(s): 2 applied, 1 failed"),
            "summary footer: {text}"
        );
    }

    #[test]
    fn render_apply_text_validation_states() {
        colored::control::set_override(false);
        let mk = |name: &str, status| ApplyOutcome {
            name: name.into(),
            target: format!("root@{name}:22"),
            status,
        };
        let text = render_apply_text(&[
            mk(
                "web-01",
                ApplyStatus::Validated {
                    plugins: 8,
                    would_change: 4,
                    failed: 0,
                },
            ),
            mk(
                "db-02",
                ApplyStatus::Validated {
                    plugins: 8,
                    would_change: 0,
                    failed: 0,
                },
            ),
        ]);
        assert!(
            text.contains("status:    validated (changes pending)"),
            "pending validation is flagged: {text}"
        );
        assert!(
            text.contains("status:    validated (no changes needed)"),
            "clean validation reads clean: {text}"
        );
        assert!(
            text.contains("8 plugin(s) checked, 4 change(s) pending, 0 failed"),
            "validation detail: {text}"
        );
        assert!(
            text.contains("---\n2 host(s): 2 validated"),
            "summary footer: {text}"
        );
    }

    #[test]
    fn render_apply_json_has_state_tags() {
        let out = render_apply_json(&[ApplyOutcome {
            name: "web".into(),
            target: "root@web".into(),
            status: ApplyStatus::Applied { ok: 5, failed: 0 },
        }]);
        assert!(
            out.contains("\"state\": \"applied\""),
            "json tags the status state: {out}"
        );
        assert!(out.contains("\"ok\": 5"));
    }

    #[tokio::test]
    async fn batch_persistence_handles_concurrent_hosts() {
        use hardener_core::MockExecutor;
        use hardener_scheduler::ScanHistoryManager;
        use hardener_scheduler::db::SessionFilter;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let mgr = Arc::new(
            ScanHistoryManager::new(&dir.path().join("scheduler.db"))
                .await
                .unwrap(),
        );

        // Persist three hosts concurrently through the shared manager (exercises WAL).
        let mut set = tokio::task::JoinSet::new();
        for i in 0..3 {
            let mgr = mgr.clone();
            set.spawn(async move {
                let exec = Arc::new(MockExecutor::new());
                let key = format!("host-{i}");
                scan_with_executor(key.clone(), format!("u@{key}:22"), key, exec, Some(mgr)).await
            });
        }
        while set.join_next().await.is_some() {}

        let all = mgr.list_sessions(&SessionFilter::default()).await.unwrap();
        assert_eq!(all.len(), 3, "all concurrent host sessions persisted");
    }
}
