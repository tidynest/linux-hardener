//! History command implementation.
//!
//! Provides CLI interface to view and export scan history.

use crate::cli::OutputFormat;
use crate::commands::daemon::load_scheduler_config;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Local, Utc};
use hardener_scheduler::{
    ScanHistoryManager,
    db::{ScanFindingRow, ScanSession, SessionFilter, trend_direction},
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Lists recent scan sessions.
pub async fn list(
    format: OutputFormat,
    quiet: bool,
    limit: u32,
    host: Option<String>,
    status: Option<String>,
) -> Result<()> {
    let db = open_database().await?;

    let filter = SessionFilter {
        limit: Some(limit),
        host,
        status,
        ..Default::default()
    };

    let sessions = db
        .list_sessions(&filter)
        .await
        .map_err(|e| anyhow!("Failed to list sessions: {}", e))?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&sessions)?);
        }
        _ => {
            if sessions.is_empty() {
                if !quiet {
                    println!("No scan sessions found");
                }
                return Ok(());
            }

            println!(
                "{:<36}  {:<19}  {:<10}  {:<8}  {:>4} {:>4} {:>4} {:>4}",
                "Session ID", "Started", "Status", "Trigger", "Crit", "High", "Med", "Low"
            );
            println!("{}", "-".repeat(100));

            for session in &sessions {
                let started = format_timestamp(session.started_at);
                println!(
                    "{:<36}  {:<19}  {:<10}  {:<8}  {:>4} {:>4} {:>4} {:>4}",
                    session.id,
                    started,
                    session.status,
                    session.trigger_type,
                    session.critical_count,
                    session.high_count,
                    session.medium_count,
                    session.low_count,
                );
            }

            if !quiet {
                println!("\n{} session(s) shown.", sessions.len());
            }
        }
    }

    Ok(())
}

/// Shows a per-host security trend: completed scans oldest-first, each with its
/// change from the previous scan. Derived on query from the persisted sessions —
/// no separate score is stored.
pub async fn trends(format: OutputFormat, quiet: bool, host: &str, limit: u32) -> Result<()> {
    let db = open_database().await?;

    let filter = SessionFilter {
        host: Some(host.to_string()),
        status: Some("completed".to_string()),
        limit: Some(limit),
        ..Default::default()
    };

    // list_sessions returns newest-first; a trend reads oldest-first.
    let mut sessions = db
        .list_sessions(&filter)
        .await
        .map_err(|e| anyhow!("Failed to list sessions: {}", e))?;
    sessions.reverse();

    let points: Vec<TrendPoint> = sessions
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let prev = i.checked_sub(1).map(|p| &sessions[p]);
            TrendPoint {
                session_id: s.id.clone(),
                started_at: s.started_at,
                total: s.total_findings,
                critical: s.critical_count,
                high: s.high_count,
                medium: s.medium_count,
                low: s.low_count,
                info: s.info_count,
                delta_total: prev.map(|p| s.total_findings - p.total_findings),
                direction: prev.map(|p| trend_direction(p.severity_tuple(), s.severity_tuple())),
            }
        })
        .collect();

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&points)?),
        _ => {
            if points.is_empty() {
                if !quiet {
                    println!("No completed scans for host '{}'", host);
                }
                return Ok(());
            }

            println!("Security trend for host '{}' (oldest first):\n", host);
            println!(
                "{:<19}  {:>5} {:>4} {:>4} {:>4} {:>4}  {:>7}  Trend",
                "Started", "Total", "Crit", "High", "Med", "Low", "Δtotal"
            );
            println!("{}", "-".repeat(72));

            for p in &points {
                let delta = p
                    .delta_total
                    .map(|d| format!("{:+}", d))
                    .unwrap_or_else(|| "—".to_string());
                println!(
                    "{:<19}  {:>5} {:>4} {:>4} {:>4} {:>4}  {:>7}  {}",
                    format_timestamp(p.started_at),
                    p.total,
                    p.critical,
                    p.high,
                    p.medium,
                    p.low,
                    delta,
                    p.direction.unwrap_or("baseline"),
                );
            }

            if !quiet {
                println!("\n{} scan(s) over time.", points.len());
            }
        }
    }

    Ok(())
}

/// One point in a per-host trend: a completed scan plus its change from the
/// previous (older) scan. `delta_total`/`direction` are `None` for the first.
#[derive(Serialize)]
struct TrendPoint {
    session_id: String,
    started_at: i64,
    total: i32,
    critical: i32,
    high: i32,
    medium: i32,
    low: i32,
    info: i32,
    delta_total: Option<i32>,
    direction: Option<&'static str>,
}

/// Reports hosts whose latest completed scan is worse than the previous one
/// (by severity priority). Exits 1 when any regression is found so it can gate
/// CI; 0 otherwise. Pass `host` to check a single host.
pub async fn regressions(format: OutputFormat, quiet: bool, host: Option<String>) -> Result<()> {
    let db = open_database().await?;

    let filter = SessionFilter {
        host,
        status: Some("completed".to_string()),
        // ponytail: read a generous recent window and group in memory; add a
        // distinct-host SQL query only if the history ever outgrows this.
        limit: Some(100_000),
        ..Default::default()
    };

    let sessions = db
        .list_sessions(&filter)
        .await
        .map_err(|e| anyhow!("Failed to list sessions: {}", e))?;

    let regressions = find_regressions(&sessions);

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&regressions)?),
        _ => {
            if regressions.is_empty() {
                if !quiet {
                    println!("No regressions found.");
                }
                return Ok(());
            }

            println!("Security regressions (latest scan worse than previous):\n");
            println!(
                "{:<24}  {:>5} {:>5}  {:>5} {:>5} {:>5} {:>5}  When",
                "Host", "Prev", "Cur", "ΔCrit", "ΔHigh", "ΔMed", "ΔLow"
            );
            println!("{}", "-".repeat(86));

            for r in &regressions {
                println!(
                    "{:<24}  {:>5} {:>5}  {:>+5} {:>+5} {:>+5} {:>+5}  {}",
                    truncate_string(&r.host, 24),
                    r.previous_total,
                    r.current_total,
                    r.delta_critical,
                    r.delta_high,
                    r.delta_medium,
                    r.delta_low,
                    format_timestamp(r.current_started_at),
                );
            }

            if !quiet {
                println!("\n{} host(s) regressed.", regressions.len());
            }
        }
    }

    if !regressions.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

/// Finds regressions from completed sessions ordered newest-first (as
/// `list_sessions` returns them): for each host, the two newest scans are
/// compared and a regression is reported when the newest is worse.
fn find_regressions(sessions: &[ScanSession]) -> Vec<Regression> {
    let mut by_host: BTreeMap<&str, Vec<&ScanSession>> = BTreeMap::new();
    for s in sessions {
        let slot = by_host.entry(s.host_identifier.as_str()).or_default();
        if slot.len() < 2 {
            slot.push(s);
        }
    }

    by_host
        .into_iter()
        .filter_map(|(host, scans)| {
            // scans is newest-first: [current, previous].
            let [current, previous] = scans[..] else {
                return None;
            };
            (trend_direction(previous.severity_tuple(), current.severity_tuple()) == "worse")
                .then(|| Regression::new(host, previous, current))
        })
        .collect()
}

/// A host whose latest scan regressed against the previous one.
#[derive(Serialize)]
struct Regression {
    host: String,
    previous_started_at: i64,
    current_started_at: i64,
    previous_total: i32,
    current_total: i32,
    delta_critical: i32,
    delta_high: i32,
    delta_medium: i32,
    delta_low: i32,
}

impl Regression {
    fn new(host: &str, prev: &ScanSession, cur: &ScanSession) -> Regression {
        Regression {
            host: host.to_string(),
            previous_started_at: prev.started_at,
            current_started_at: cur.started_at,
            previous_total: prev.total_findings,
            current_total: cur.total_findings,
            delta_critical: cur.critical_count - prev.critical_count,
            delta_high: cur.high_count - prev.high_count,
            delta_medium: cur.medium_count - prev.medium_count,
            delta_low: cur.low_count - prev.low_count,
        }
    }
}

/// Shows details of a specific scan session.
pub async fn show(session_id: &str, format: OutputFormat, quiet: bool) -> Result<()> {
    let db = open_database().await?;

    let session = db
        .get_session(session_id)
        .await
        .map_err(|e| anyhow!("Failed to get session: {}", e))?
        .ok_or_else(|| anyhow!("Session not found: {}", session_id))?;

    let findings = db
        .get_findings(session_id)
        .await
        .map_err(|e| anyhow!("Failed to get findings: {}", e))?;

    match format {
        OutputFormat::Json => {
            let output = SessionDetail {
                session: session.clone(),
                findings: findings.clone(),
            };
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        _ => {
            print_session_detail(&session, &findings, quiet);
        }
    }

    Ok(())
}

/// Exports a scan session to a JSON file.
pub async fn export(
    session_id: &str,
    output_path: Option<PathBuf>,
    format: OutputFormat,
    quiet: bool,
) -> Result<()> {
    let db = open_database().await?;

    let session = db
        .get_session(session_id)
        .await
        .map_err(|e| anyhow!("Failed to get session: {}", e))?
        .ok_or_else(|| anyhow!("Session not found: {}", session_id))?;

    let findings = db
        .get_findings(session_id)
        .await
        .map_err(|e| anyhow!("Failed to get findings: {}", e))?;

    let output = SessionDetail {
        session: session.clone(),
        findings,
    };

    let json = serde_json::to_string(&output)?;

    // Determine output path
    let path = output_path.unwrap_or_else(|| {
        let short_id = &session.id[..8.min(session.id.len())];
        PathBuf::from(format!("session-{}.json", short_id))
    });

    std::fs::write(&path, &json)?;

    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "exported": true,
                    "path": path.display().to_string(),
                    "session_id": session_id,
                    "findings_count": output.findings.len(),
                }))?
            );
        }
        _ => {
            if !quiet {
                println!("Exported session to: {}", path.display());
                println!("  Findings: {}", output.findings.len());
            }
        }
    }

    Ok(())
}

/// Combined session and findings for JSON export.
#[derive(Serialize)]
struct SessionDetail {
    session: ScanSession,
    findings: Vec<ScanFindingRow>,
}

/// Opens the scheduler database using config paths.
async fn open_database() -> Result<ScanHistoryManager> {
    let config = load_scheduler_config()?;
    ScanHistoryManager::new(&config.storage.database_path)
        .await
        .map_err(|e| anyhow!("Failed to open database: {}", e))
}

/// Formats a Unix timestamp as local datetime string.
fn format_timestamp(timestamp: i64) -> String {
    DateTime::from_timestamp(timestamp, 0)
        .map(|dt: DateTime<Utc>| {
            dt.with_timezone(&Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| "Unknown".to_string())
}

/// Prints session details in human-readable format.
fn print_session_detail(session: &ScanSession, findings: &[ScanFindingRow], quiet: bool) {
    println!("Session: {}", session.id);
    println!("  Host:     {}", session.host_identifier);
    println!("  Status:   {}", session.status);
    println!("  Trigger:  {}", session.trigger_type);
    println!("  Started:  {}", format_timestamp(session.started_at));

    if let Some(completed) = session.completed_at {
        println!("  Finished: {}", format_timestamp(completed));
    }

    println!("  Plugins:  {}", session.plugins().join(", "));
    println!();

    // Severity summary
    println!("Findings Summary:");
    println!(
        "  Critical: {}  High: {}  Medium: {}  Low: {}  Info: {}",
        session.critical_count,
        session.high_count,
        session.medium_count,
        session.low_count,
        session.info_count
    );

    if let Some(ref error) = session.error_message {
        println!("\nError: {}", error);
    }

    if let Some(ref path) = session.json_file_path {
        println!("\nJSON Export: {}", path);
    }

    // Show findings
    if !findings.is_empty() && !quiet {
        println!("\nFindings ({}):", findings.len());
        println!("{:<10}  {:<20}  {:<10}  Title", "Severity", "Plugin", "ID",);
        println!("{}", "-".repeat(80));

        for finding in findings {
            println!(
                "{:<10}  {:<20}  {:<10}  {}",
                finding.severity,
                finding.plugin_id,
                finding.finding_id,
                truncate_string(&finding.title, 35),
            );
        }
    }
}

/// Truncates a string to max length with ellipsis (char-aware, safe for UTF-8).
fn truncate_string(s: &str, max_len: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max_len {
        s.to_string()
    } else {
        let end = max_len.saturating_sub(3);
        format!("{}...", chars[..end].iter().collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(host: &str, started_at: i64, critical: i32, high: i32) -> ScanSession {
        ScanSession {
            id: format!("{host}-{started_at}"),
            started_at,
            completed_at: Some(started_at),
            status: "completed".into(),
            trigger_type: "batch".into(),
            host_identifier: host.into(),
            plugins_scanned: String::new(),
            total_findings: critical + high,
            critical_count: critical,
            high_count: high,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            error_message: None,
            json_file_path: None,
            hash: None,
        }
    }

    #[test]
    fn find_regressions_flags_only_worse_latest() {
        // Newest-first, as list_sessions returns.
        let sessions = vec![
            session("web", 200, 2, 0),  // latest: 2 crit — worse than prior (1 crit)
            session("web", 100, 1, 0),  // prior
            session("db", 200, 0, 1),   // latest: better than prior
            session("db", 100, 0, 3),   // prior
            session("solo", 100, 5, 5), // single scan — nothing to compare
        ];

        let regs = find_regressions(&sessions);

        assert_eq!(regs.len(), 1, "only web regressed");
        assert_eq!(regs[0].host, "web");
        assert_eq!(regs[0].delta_critical, 1);
        assert_eq!(regs[0].previous_total, 1);
        assert_eq!(regs[0].current_total, 2);
    }
}
