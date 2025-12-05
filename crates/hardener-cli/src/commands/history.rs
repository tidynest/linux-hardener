//! History command implementation.
//!
//! Provides CLI interface to view and export scan history.

use crate::cli::OutputFormat;
use crate::commands::daemon::load_scheduler_config;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Local, Utc};
use hardener_scheduler::{
    db::{ScanFindingRow, ScanSession, SessionFilter},
    ScanHistoryManager,
};
use serde::Serialize;
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
        PathBuf::from(format!(
        "session-{}.json", short_id))
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
        .map(|dt: DateTime<Utc>| dt.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

/// Prints session details in human-readable format.
fn print_session_detail(session: &ScanSession, findings: &[ScanFindingRow], quiet:
bool) {
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
        println!(
            "{:<10}  {:<20}  {:<10}  Title",
            "Severity", "Plugin", "ID",
        );
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

/// Truncates a string to max length with ellipsis.
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}
