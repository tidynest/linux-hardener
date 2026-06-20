//! `hardener batch scan` — scan many remote hosts concurrently.

use crate::cli::OutputFormat as CliOutputFormat;
use crate::commands::report::run_scan;
use crate::ssh_config::SshConnectionConfig;
use anyhow::{Result, anyhow, bail};
use hardener_common::types::Severity;
use hardener_core::plugin::Finding;
use hardener_core::{SshExecutor, executor::SystemExecutor};
use hardener_types::remote::{HostsConfig, RemoteHostProfile};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;

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

/// Parses an ad-hoc `--ssh user@host` target into a profile. Port and key come
/// from the global SSH flags (defaults applied by the caller).
pub fn parse_inline(
    target: &str,
    port: u16,
    key_file: Option<String>,
    verify: bool,
) -> RemoteHostProfile {
    let (user, hostname) = match target.split_once('@') {
        Some((u, h)) => (Some(u.to_string()), h.to_string()),
        None => (None, target.to_string()),
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

/// Scans one host using an already-built executor. Split out so tests can inject
/// a `MockExecutor`; production callers pass a connected `SshExecutor`.
async fn scan_with_executor(
    name: String,
    target: String,
    executor: Arc<dyn SystemExecutor>,
) -> HostOutcome {
    match run_scan(true, executor, &CliOutputFormat::Json).await {
        Ok(findings) => {
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
async fn scan_one(profile: RemoteHostProfile, timeout: u64) -> HostOutcome {
    let target = display_target(&profile);
    match SshExecutor::connect(host_ssh_config(&profile, timeout)).await {
        Ok(exec) => scan_with_executor(profile.name, target, Arc::new(exec)).await,
        Err(e) => HostOutcome {
            name: profile.name,
            target,
            status: HostStatus::Failed {
                error: e.to_string(),
            },
        },
    }
}

/// Scans all profiles with at most `concurrency` running at once, preserving the
/// input order in the returned vec.
async fn scan_all(
    profiles: Vec<RemoteHostProfile>,
    concurrency: usize,
    timeout: u64,
) -> Vec<HostOutcome> {
    use tokio::sync::Semaphore;
    // Pre-fill every slot so a panicked task surfaces as a visible Failed host
    // rather than silently vanishing (which would desync the rollup count).
    let mut results: Vec<HostOutcome> = profiles
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
        set.spawn(async move {
            let _permit = permits.acquire_owned().await.expect("semaphore open");
            (idx, scan_one(profile, timeout).await)
        });
    }
    while let Some(res) = set.join_next().await {
        if let Ok((idx, outcome)) = res {
            results[idx] = outcome;
        }
    }
    results
}

/// CLI entry point for `hardener batch scan`.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    all: bool,
    host: Vec<String>,
    ssh: Vec<String>,
    concurrency: usize,
    format: CliOutputFormat,
    output: Option<String>,
    quiet: bool,
    global_key: Option<String>,
    global_timeout: u64,
    global_no_verify: bool,
) -> anyhow::Result<()> {
    let inventory = hardener_core::inventory::load()
        .map_err(|e| anyhow!("failed to load host inventory: {e}"))?;

    let inline: Vec<RemoteHostProfile> = ssh
        .iter()
        .map(|t| parse_inline(t, 22, global_key.clone(), !global_no_verify))
        .collect();
    let profiles = resolve_hosts(&inventory, all, &host, inline)?;

    if !quiet {
        eprintln!("Scanning {} host(s)...", profiles.len());
    }

    let outcomes = scan_all(profiles, concurrency, global_timeout).await;

    let rendered = match format {
        CliOutputFormat::Json => render_json(&outcomes),
        _ => render_text(&outcomes),
    };
    match output {
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
        let outcome = scan_with_executor("h".into(), "u@h:22".into(), exec).await;
        assert!(
            matches!(outcome.status, HostStatus::Scanned { .. }),
            "a mock executor should yield a Scanned outcome, not a connection failure",
        );
    }

    #[tokio::test]
    async fn scan_all_empty_is_empty() {
        let out = scan_all(vec![], 4, 1).await;
        assert!(out.is_empty());
    }
}
