//! `hardener batch scan` — scan many remote hosts concurrently.

use crate::cli::OutputFormat as CliOutputFormat;
use crate::commands::daemon::load_scheduler_config;
use crate::commands::report::{finding_to_scan_finding, scan_grouped};
use crate::ssh_config::SshConnectionConfig;
use anyhow::{Result, anyhow, bail};
use hardener_common::types::Severity;
use hardener_core::plugin::Finding;
use hardener_core::{PluginMetadata, SshExecutor, executor::SystemExecutor};
use hardener_scheduler::ScanHistoryManager;
use hardener_scheduler::db::ScanFinding;
use hardener_types::remote::{HostsConfig, RemoteHostProfile};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
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
    },
    Failed {
        error: String,
    },
}

/// One host's batch result. `name` is the inventory name (or target for ad-hoc
/// hosts); `target` is `user@host:port` for display.
#[derive(Clone, Debug, Serialize)]
pub struct HostOutcome {
    pub name: String,
    pub target: String,
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

/// Parses an ad-hoc `--ssh user@host[:port]` target into a profile. A `:port`
/// suffix overrides `port` (the caller's default); the key comes from the global
/// SSH flags. ponytail: unbracketed IPv6 keeps its default port (no unambiguous
/// `host:port` form); pass bracketed `[addr]` support only if a user needs it.
pub fn parse_inline(
    target: &str,
    port: u16,
    key_file: Option<String>,
    verify: bool,
) -> RemoteHostProfile {
    let (user, rest) = match target.split_once('@') {
        Some((u, h)) => (Some(u.to_string()), h),
        None => (None, target),
    };
    let (hostname, port) = match rest.rsplit_once(':') {
        Some((host, p)) if !host.contains(':') => match p.parse::<u16>() {
            Ok(parsed) => (host.to_string(), parsed),
            Err(_) => (rest.to_string(), port),
        },
        _ => (rest.to_string(), port),
    };
    RemoteHostProfile {
        name: hostname.clone(),
        hostname,
        user,
        port,
        key_file,
        host_key_checking: verify,
    }
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

/// Renders the human-readable table + rollup line.
pub fn render_text(outcomes: &[HostOutcome]) -> String {
    let mut out = String::new();
    out.push_str("HOST            TARGET                     STATUS   CRIT HIGH MED LOW TOTAL\n");
    for o in outcomes {
        match &o.status {
            HostStatus::Scanned { counts, .. } => out.push_str(&format!(
                "{:<15} {:<26} {:<8} {:>4} {:>4} {:>3} {:>3} {:>5}\n",
                o.name,
                o.target,
                "ok",
                counts.critical,
                counts.high,
                counts.medium,
                counts.low,
                counts.total(),
            )),
            HostStatus::Failed { error } => out.push_str(&format!(
                "{:<15} {:<26} {:<8} {}\n",
                o.name, o.target, "FAILED", error,
            )),
        }
    }
    let s = BatchSummary::from_outcomes(outcomes);
    out.push_str("---\n");
    out.push_str(&format!(
        "{} hosts: {} scanned, {} failed · findings: {} crit, {} high, {} med, {} low ({} total)\n",
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

/// Builds the `user@host:port` display string for a profile.
fn display_target(p: &RemoteHostProfile) -> String {
    match &p.user {
        Some(user) => format!("{}@{}:{}", user, p.hostname, p.port),
        None => format!("{}:{}", p.hostname, p.port),
    }
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
    grouped: &[(PluginMetadata, Vec<Finding>)],
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
        .flat_map(|(meta, fs)| fs.iter().map(move |f| finding_to_scan_finding(meta, f)))
        .collect();
    if let Err(e) = history
        .complete_session(&session_id, &findings, None, None)
        .await
    {
        warn!("batch history: complete_session for {host_key} failed: {e}");
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
    match scan_grouped(true, executor, &CliOutputFormat::Json).await {
        Ok(grouped) => {
            if let Some(history) = &history {
                persist_host(history, &host_key, &grouped).await;
            }
            let findings: Vec<Finding> = grouped.into_iter().flat_map(|(_, f)| f).collect();
            let counts = SeverityCounts::from_findings(&findings);
            HostOutcome {
                name,
                target,
                status: HostStatus::Scanned { counts, findings },
            }
        }
        Err(e) => HostOutcome {
            name,
            target,
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
    // host_key: inventory hosts have a friendly name; ad-hoc hosts (parse_inline)
    // set name == hostname, so fall back to the user@host:port target for those.
    // Limitation: an inventory host deliberately named after its own hostname
    // (name == hostname, e.g. "10.0.0.1") is indistinguishable from an ad-hoc
    // host and so is keyed by user@host:port rather than the bare name.
    let host_key = if profile.name == profile.hostname {
        target.clone()
    } else {
        profile.name.clone()
    };
    match SshExecutor::connect(host_ssh_config(&profile, timeout)).await {
        Ok(exec) => {
            scan_with_executor(profile.name, target, host_key, Arc::new(exec), history).await
        }
        Err(e) => HostOutcome {
            name: profile.name,
            target,
            status: HostStatus::Failed {
                error: e.to_string(),
            },
        },
    }
}

/// Overlays completed `(index, outcome)` results onto the input-ordered pre-fill.
/// Slots whose task never reported (panicked/dropped) keep their placeholder, so
/// the result is always input-length and in input order regardless of completion
/// order.
fn assemble_ordered(
    mut prefill: Vec<HostOutcome>,
    completed: Vec<(usize, HostOutcome)>,
) -> Vec<HostOutcome> {
    for (idx, outcome) in completed {
        if let Some(slot) = prefill.get_mut(idx) {
            *slot = outcome;
        }
    }
    prefill
}

/// Scans all profiles with at most `concurrency` running at once, preserving the
/// input order in the returned vec.
async fn scan_all(
    profiles: Vec<RemoteHostProfile>,
    concurrency: usize,
    timeout: u64,
    history: Option<Arc<ScanHistoryManager>>,
) -> Vec<HostOutcome> {
    use tokio::sync::Semaphore;
    // Pre-fill every slot so a panicked task surfaces as a visible Failed host
    // rather than silently vanishing (which would desync the rollup count).
    let prefill: Vec<HostOutcome> = profiles
        .iter()
        .map(|p| HostOutcome {
            name: p.name.clone(),
            target: display_target(p),
            status: HostStatus::Failed {
                error: "scan task did not complete".to_string(),
            },
        })
        .collect();
    let permits = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for (idx, profile) in profiles.into_iter().enumerate() {
        let permits = permits.clone();
        let history = history.clone();
        set.spawn(async move {
            let _permit = permits.acquire_owned().await.expect("semaphore open");
            (idx, scan_one(profile, timeout, history).await)
        });
    }
    let mut completed: Vec<(usize, HostOutcome)> = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(pair) = res {
            completed.push(pair);
        }
    }
    assemble_ordered(prefill, completed)
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

/// CLI entry point for `hardener batch scan`.
pub async fn run(opts: BatchOptions) -> anyhow::Result<()> {
    let inventory = match hardener_core::inventory::load() {
        Ok(inv) => inv,
        Err(e) => {
            eprintln!("failed to load host inventory: {e}");
            std::process::exit(2);
        }
    };

    let inline: Vec<RemoteHostProfile> = opts
        .ssh
        .iter()
        .map(|t| parse_inline(t, 22, opts.global_key.clone(), !opts.global_no_verify))
        .collect();

    let mut profiles = match resolve_hosts(&inventory, opts.all, &opts.host, inline) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    // The global --ssh-key fills the gap for any host (chiefly inventory hosts)
    // that does not define its own key. Ad-hoc hosts already carry it.
    if let Some(key) = opts.global_key.as_ref() {
        for profile in profiles.iter_mut() {
            if profile.key_file.is_none() {
                profile.key_file = Some(key.clone());
            }
        }
    }

    if !opts.quiet {
        eprintln!("Scanning {} host(s)...", profiles.len());
    }

    let history = open_batch_history().await;
    let outcomes = scan_all(profiles, opts.concurrency, opts.global_timeout, history).await;

    let rendered = match opts.format {
        CliOutputFormat::Json => render_json(&outcomes),
        _ => render_text(&outcomes),
    };
    match opts.output {
        Some(path) => {
            std::fs::write(&path, &rendered).map_err(|e| anyhow!("failed to write {path}: {e}"))?
        }
        None => println!("{rendered}"),
    }

    std::process::exit(exit_code(&outcomes));
}

#[cfg(test)]
mod tests {
    use super::*;
    use hardener_common::types::{FindingCategory, Severity};

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
            status: HostStatus::Scanned {
                counts: SeverityCounts {
                    high: total_high,
                    ..Default::default()
                },
                findings: vec![],
            },
        }
    }

    fn failed() -> HostOutcome {
        HostOutcome {
            name: "h".into(),
            target: "u@h:22".into(),
            status: HostStatus::Failed {
                error: "boom".into(),
            },
        }
    }

    fn scanned_named(name: &str, counts: SeverityCounts) -> HostOutcome {
        HostOutcome {
            name: name.into(),
            target: format!("u@{name}:22"),
            status: HostStatus::Scanned {
                counts,
                findings: vec![],
            },
        }
    }

    fn failed_named(name: &str) -> HostOutcome {
        HostOutcome {
            name: name.into(),
            target: format!("u@{name}:22"),
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
        assert!(text.contains("2 hosts: 1 scanned, 1 failed"));
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
    fn text_render_scanned_row_shows_counts() {
        let text = render_text(&[scanned_named(
            "web-01",
            SeverityCounts {
                high: 2,
                ..Default::default()
            },
        )]);
        assert!(text.contains("web-01"));
        // The scanned row carries the high count and the row total (both 2 here).
        let row = text
            .lines()
            .find(|l| l.contains("web-01"))
            .expect("scanned row present");
        assert!(row.contains('2'), "row should show the count: {row}");
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
        // come back Failed, in input order, with none lost — exercising the real
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
