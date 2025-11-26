use colored::Colorize;
use hardener_common::types::Severity;
use hardener_core::{ApplyResult, Finding, PluginMetadata, ValidationReport};
use hardener_state::{Checkpoint, FileState};

use crate::cli::{OutputFormat, ScanMode};

pub fn status(format: &OutputFormat, message: &str) {
    match format {
        OutputFormat::Text => eprintln!("{} {}", "→".blue(), message),
        OutputFormat::Json => {} // Silent in JSON mode
    }
}

pub fn info(format: &OutputFormat, message: &str) {
    match format {
        OutputFormat::Text => println!("{} {}", "i".cyan(), message),
        OutputFormat::Json => {
            println!("{}", serde_json::json!({ "info": message }));
        }
    }
}

pub fn error(format: &OutputFormat, message: &str) {
    match format {
        OutputFormat::Text => eprintln!("{} {}", "x".red(), message),
        OutputFormat::Json => {
            eprintln!("{}", serde_json::json!({ "error": message }));
        }
    }
}

pub fn scan_results(
    format: &OutputFormat,
    results: &[(PluginMetadata, Vec<Finding>)],
    _mode: ScanMode,
) {
    match format {
        OutputFormat::Text => {
            println!("\n{}", "═══ Scan Results ═══".bold());

            let mut total_findings = 0;
            for (metadata, findings) in results {
                if findings.is_empty() {
                    println!(
                        "{} {} - {}",
                        "✓".green(),
                        metadata.plugin_name,
                        "No issues found".dimmed()
                    );
                } else {
                    println!(
                        "\n{} {} - {} finding(s)",
                        "!".yellow(),
                        metadata.plugin_name.bold(),
                        findings.len()
                    );
                    for finding in findings {
                        let severity_str = format_severity(&finding.finding_severity);
                        println!(
                            "  {} [{}] {}",
                            "•".dimmed(),
                            severity_str,
                            finding.finding_title
                        );

                        if !finding.finding_description.is_empty() {
                            println!("    {}", finding.finding_description.dimmed());
                        }
                    }
                    total_findings += findings.len();
                }
            }

            println!("\n{}", "═══════════════════".dimmed());
            println!(
                "Total: {} finding(s) across {} plugin(s)",
                total_findings,
                results.len()
            );
        }
        OutputFormat::Json => {
            let json_results: Vec<_> = results
                .iter()
                .map(|(m, f)| {
                    serde_json::json!({
                        "plugin_id": m.plugin_id.as_str(),
                        "plugin_name": m.plugin_name,
                        "findings": f,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_results).unwrap());
        }
    }
}

pub fn apply_results(format: &OutputFormat, results: &[(PluginMetadata, ApplyResult)]) {
    match format {
        OutputFormat::Text => {
            println!("\n{}", "═══ Apply Results ═══".bold());

            for (metadata, result) in results {
                if result.apply_success {
                    println!(
                        "{} {} - {} change(s) applied",
                        "✓".green(),
                        metadata.plugin_name,
                        result.apply_changes.len()
                    );
                    for change in &result.apply_changes {
                        let status = if change.change_success {
                            "✓".green()
                        } else {
                            "✗".red()
                        };
                        println!("  {} {}", status, change.change_description);
                    }
                } else {
                    println!(
                        "{} {} - {}",
                        "✗".red(),
                        metadata.plugin_name,
                        result.apply_error.as_deref().unwrap_or("Unknown error")
                    );
                }
            }
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&results).unwrap());
        }
    }
}

pub fn plugin_list(format: &OutputFormat, plugins: &[PluginMetadata]) {
    match format {
        OutputFormat::Text => {
            println!("{}", "Available Plugins".bold());
            println!("{}", "─".repeat(60));
            for plugin in plugins {
                println!(
                    "{:20} {} {}",
                    plugin.plugin_id.as_str().cyan(),
                    plugin.plugin_name,
                    format!("v{}", plugin.plugin_version).dimmed()
                );
                println!("  {}", plugin.plugin_description.dimmed());
            }
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&plugins).unwrap());
        }
    }
}

pub fn checkpoint_list(format: &OutputFormat, checkpoints: &[Checkpoint]) {
    match format {
        OutputFormat::Text => {
            if checkpoints.is_empty() {
                println!("No checkpoints found.");
                return;
            }

            println!("{}", "Checkpoints".bold());
            println!("{}", "─".repeat(80));
            for cp in checkpoints {
                println!(
                    "{} {} ({})",
                    cp.checkpoint_id.as_str().cyan(),
                    cp.checkpoint_name,
                    format_timestamp(cp.checkpoint_timestamp).dimmed()
                );
            }
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&checkpoints).unwrap());
        }
    }
}

pub fn checkpoint_created(format: &OutputFormat, id: &hardener_state::CheckpointId) {
    match format {
        OutputFormat::Text => {
            println!("{} Checkpoint created: {}", "✓".green(), id.as_str().cyan());
        }
        OutputFormat::Json => {
            println!("{}", serde_json::json!({ "checkpoint_id": id.as_str() }));
        }
    }
}

pub fn checkpoint_details(format: &OutputFormat, checkpoint: &Checkpoint, files: &[FileState]) {
    match format {
        OutputFormat::Text => {
            println!("{}", "Checkpoint Details".bold());
            println!("{}", "─".repeat(60));
            println!("ID:        {}", checkpoint.checkpoint_id.as_str().cyan());
            println!("Name:      {}", checkpoint.checkpoint_name);
            println!(
                "Created:   {}",
                format_timestamp(checkpoint.checkpoint_timestamp)
            );
            println!("User:      {}", checkpoint.checkpoint_username);
            println!("Files:     {}", files.len());

            if !files.is_empty() {
                println!("\n{}", "Captured Files:".bold());
                for file in files {
                    println!("  {}", file.file_path);
                }
            }
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::json!({
                    "checkpoint": checkpoint,
                    "files": files
                })
            );
        }
    }
}

pub fn validation_report(
    format: &OutputFormat,
    metadata: &PluginMetadata,
    report: &ValidationReport,
) {
    match format {
        OutputFormat::Text => {
            println!(
                "{} {} - {} item(s) to apply",
                "○".blue(),
                metadata.plugin_name,
                report.validation_report_estimated_changes.len()
            );
            for item in &report.validation_report_estimated_changes {
                println!("  {} {}", "•".dimmed(), item);
            }
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
    }
}

fn format_severity(severity: &Severity) -> colored::ColoredString {
    match severity {
        Severity::Critical => "CRIT".red().bold(),
        Severity::High => "HIGH".red(),
        Severity::Medium => "MED ".yellow(),
        Severity::Low => "LOW ".blue(),
        Severity::Info => "INFO".dimmed(),
    }
}

fn format_timestamp(timestamp: i64) -> String {
    use chrono::{DateTime, Local, TimeZone, Utc};

    let datetime: DateTime<Utc> = Utc
        .timestamp_opt(timestamp, 0)
        .single()
        .unwrap_or_else(Utc::now);

    // Convert to local time and format
    let local: DateTime<Local> = datetime.into();
    local.format("%Y-%m-%d %H:%M:%S").to_string()
}
