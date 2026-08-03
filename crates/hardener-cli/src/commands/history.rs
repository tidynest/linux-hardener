//! History command implementation.
//!
//! Provides CLI interface to view and export scan history.

use crate::cli::OutputFormat;
use crate::commands::daemon::load_scheduler_config;
use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Local, Utc};
use hardener_scheduler::{
    ScanHistoryManager,
    db::{ScanFindingRow, ScanSession, SessionFilter, is_worse, trend_direction},
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
/// change from the previous scan. Derived on query from the persisted sessions,
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
                    .unwrap_or_else(|| "-".to_string());
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
            is_worse(previous.severity_tuple(), current.severity_tuple())
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

/// The document types this tool renders somewhere and this command does not.
///
/// Deliberately a closed list rather than the inverse rule "anything that is
/// not `json`". `Path::extension` returns whatever follows the last dot of a
/// file name, which is not the same question as "what document is this": a
/// dated file name like `backups/2026.08.03` has extension `03` and
/// `session-1.5.1` has `1`. Refusing those would break working invocations to
/// no purpose, since neither operator was asking for a document at all. What is
/// worth refusing is a path naming one of the formats this tool really does
/// render, because that is a genuine expectation, reachable through `report
/// --report-format`, that this command cannot meet.
const FOREIGN_DOCUMENT_EXTENSIONS: &[&str] = &["csv", "htm", "html", "pdf", "txt"];

/// Refuses an `--output` path whose extension promises a document this exporter
/// cannot produce.
///
/// The export is one serialisation of one struct and is always JSON: the help
/// text, the reference and the default filename all say so, and there is no
/// second formatter behind this command to reach. A path naming one of the
/// report formats was answered with JSON bytes in a file called something else,
/// which exits 0 and looks like it worked.
fn refuse_extension_it_cannot_produce(path: &std::path::Path) -> Result<()> {
    let Some(extension) = path.extension().and_then(|e| e.to_str()) else {
        return Ok(());
    };
    let extension = extension.to_ascii_lowercase();
    if !FOREIGN_DOCUMENT_EXTENSIONS.contains(&extension.as_str()) {
        return Ok(());
    }
    bail!(
        "history export writes JSON and cannot produce a '{extension}' document: {}. \
         Give the path a .json extension, or none at all. The rich formats are \
         produced by `hardener report --report-format`.",
        path.display()
    )
}

/// Exports a scan session to a JSON file.
pub async fn export(
    session_id: &str,
    output_path: Option<PathBuf>,
    format: OutputFormat,
    quiet: bool,
) -> Result<()> {
    // Judged before the database is opened: there is nothing to gain by reading
    // a session out in order to refuse where it was going.
    if let Some(path) = output_path.as_deref() {
        refuse_extension_it_cannot_produce(path)?;
    }

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

    // A session records the plugins the config selected, so a short list is
    // honest and an empty one is possible. A record that will not parse is
    // neither, and must not print as though the scan covered nothing.
    match session.plugins() {
        Ok(plugins) if plugins.is_empty() => println!("  Plugins:  none"),
        Ok(plugins) => println!("  Plugins:  {}", plugins.join(", ")),
        Err(e) => println!("  Plugins:  record unreadable ({e})"),
    }
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
mod tests;
