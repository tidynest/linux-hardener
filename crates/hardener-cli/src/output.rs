//! CLI output formatting: multiplexes between JSON and coloured terminal output.

use colored::Colorize;
use hardener_common::types::Severity;
use hardener_core::{
    ApplyResult, Finding, PluginMetadata, ValidationReport, plugin::UncheckedCheck,
};
use hardener_state::{Checkpoint, FileState, RollbackResult};

use crate::cli::{OutputFormat, ScanMode};

pub fn status(format: &OutputFormat, message: &str) {
    match format {
        OutputFormat::Json => {}
        _ => eprintln!("{} {}", "→".blue(), message),
    }
}

pub fn info(format: &OutputFormat, message: &str) {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::json!({ "info": message }));
        }
        _ => println!("{} {}", "i".cyan(), message),
    }
}

pub fn error(format: &OutputFormat, message: &str) {
    match format {
        OutputFormat::Json => {
            eprintln!("{}", serde_json::json!({ "error": message }));
        }
        _ => eprintln!("{} {}", "x".red(), message),
    }
}

pub fn warning(format: &OutputFormat, message: &str) {
    match format {
        OutputFormat::Json => {
            eprintln!("{}", serde_json::json!({ "warning": message }));
        }
        _ => eprintln!("{} {}", "W".yellow(), message),
    }
}

pub fn scan_results(
    format: &OutputFormat,
    results: &[(PluginMetadata, Vec<Finding>, Vec<UncheckedCheck>)],
    _mode: ScanMode,
) {
    match format {
        OutputFormat::Json => {
            let json_results: Vec<_> = results
                .iter()
                .map(|(m, f, u)| {
                    serde_json::json!({
                        "plugin_id": m.plugin_id.as_str(),
                        "plugin_name": m.plugin_name,
                        "findings": f,
                        "unchecked": u,
                    })
                })
                .collect();
            match serde_json::to_string_pretty(&json_results) {
                Ok(json) => println!("{json}"),
                Err(e) => eprintln!("{{\"error\": \"serialisation failed: {e}\"}}"),
            }
        }
        _ => {
            println!("\n{}", "═══ Scan Results ═══".bold());

            let mut total_findings = 0;
            for (metadata, findings, unchecked) in results {
                if findings.is_empty() && unchecked.is_empty() {
                    println!(
                        "{} {} - {}",
                        "✓".green(),
                        metadata.plugin_name,
                        "No issues found".dimmed()
                    );
                } else if !findings.is_empty() {
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

                if !unchecked.is_empty() {
                    println!(
                        "  {} {}",
                        "?".dimmed(),
                        format!(
                            "{} check(s) could not be verified without root",
                            unchecked.len()
                        )
                        .dimmed()
                    );
                    for entry in unchecked {
                        println!(
                            "    {} {} - {}",
                            "·".dimmed(),
                            entry.unchecked_title.dimmed(),
                            entry.unchecked_reason.dimmed()
                        );
                    }
                }
            }

            println!("\n{}", "═══════════════════".dimmed());
            println!(
                "Total: {} finding(s) across {} plugin(s)",
                total_findings,
                results.len()
            );

            let total_unchecked: usize = results.iter().map(|(_, _, u)| u.len()).sum();
            if total_unchecked > 0 {
                println!(
                    "{}",
                    format!(
                        "{} check(s) require root; run with sudo for a full scan",
                        total_unchecked
                    )
                    .dimmed()
                );
            }
        }
    }
}

/// Prints a per-plugin timing table, sorted slowest first.
///
/// Written to stderr so `--format json` stdout stays machine-parseable.
/// Plugins run concurrently, so the summed plugin time exceeds wall clock.
pub fn scan_timings(timings: &[(String, u64)], wall: std::time::Duration) {
    let mut rows: Vec<_> = timings.to_vec();
    rows.sort_by_key(|(_, us)| std::cmp::Reverse(*us));

    let width = rows
        .iter()
        .map(|(name, _)| name.len())
        .chain([19])
        .max()
        .unwrap_or(19);
    let ms = |us: f64| format!("{:>10.1} ms", us / 1000.0);

    eprintln!("\n{}", "═══ Plugin Timings ═══".bold());
    for (name, us) in &rows {
        eprintln!("{name:<width$} {}", ms(*us as f64));
    }
    let total: u64 = rows.iter().map(|(_, us)| us).sum();
    eprintln!("{}", "─".repeat(width + 14).dimmed());
    eprintln!("{:<width$} {}", "Total (plugin time)", ms(total as f64));
    eprintln!(
        "{:<width$} {}",
        "Wall clock",
        ms(wall.as_secs_f64() * 1_000_000.0)
    );
}

pub fn apply_results(format: &OutputFormat, results: &[(PluginMetadata, ApplyResult)]) {
    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(&results) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("{{\"error\": \"serialisation failed: {e}\"}}"),
        },
        _ => {
            println!("\n{}", "═══ Apply Results ═══".bold());

            for (metadata, result) in results {
                let icon = if result.apply_success {
                    "✓".green()
                } else {
                    "✗".red()
                };

                if let Some(err) = &result.apply_error {
                    println!("{} {} - {}", icon, metadata.plugin_name, err);
                } else {
                    let applied = result.applied_change_count();
                    let skipped = result.apply_changes.len() - applied;
                    let skipped_suffix = if skipped > 0 {
                        format!(", {skipped} skipped")
                    } else {
                        String::new()
                    };
                    println!(
                        "{} {} - {} change(s) applied{}",
                        icon, metadata.plugin_name, applied, skipped_suffix
                    );
                }

                for change in &result.apply_changes {
                    let status = if change.is_skipped() {
                        "○".dimmed()
                    } else if change.change_success {
                        "✓".green()
                    } else {
                        "✗".red()
                    };
                    println!("  {} {}", status, change.change_description);

                    if !change.change_success
                        && let Some(err) = &change.change_error
                    {
                        println!("{}", format_change_error(err));
                    }
                }
            }
        }
    }
}

/// Formats the indented, dimmed detail line printed under a failed change so
/// a terminal user sees why it failed, not just that it did.
fn format_change_error(error: &str) -> String {
    format!("    {}", error.dimmed())
}

pub fn plugin_list(format: &OutputFormat, plugins: &[PluginMetadata]) {
    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(&plugins) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("{{\"error\": \"serialisation failed: {e}\"}}"),
        },
        _ => {
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
    }
}

pub fn checkpoint_list(format: &OutputFormat, checkpoints: &[Checkpoint]) {
    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(&checkpoints) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("{{\"error\": \"serialisation failed: {e}\"}}"),
        },
        _ => {
            if checkpoints.is_empty() {
                println!("No checkpoints found.");
                return;
            }

            println!("{}", "Checkpoints".bold());
            println!("{}", "─".repeat(90));
            println!(
                "{:<36}  {:<24}  {:<12}  {}",
                "ID".bold(),
                "NAME".bold(),
                "HOST".bold(),
                "CREATED".bold()
            );
            println!("{}", "─".repeat(90));
            for cp in checkpoints {
                println!(
                    "{:<36}  {:<24}  {:<12}  {}",
                    cp.checkpoint_id.as_str().cyan(),
                    cp.checkpoint_name,
                    cp.host_key.dimmed(),
                    format_timestamp(cp.checkpoint_timestamp).dimmed()
                );
            }
        }
    }
}

pub fn checkpoint_created(format: &OutputFormat, id: &hardener_state::CheckpointId) {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::json!({ "checkpoint_id": id.as_str() }));
        }
        _ => {
            println!("{} Checkpoint created: {}", "✓".green(), id.as_str().cyan());
        }
    }
}

pub fn checkpoint_details(format: &OutputFormat, checkpoint: &Checkpoint, files: &[FileState]) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::json!({
                    "checkpoint": checkpoint,
                    "files": files
                })
            );
        }
        _ => {
            println!("{}", "Checkpoint Details".bold());
            println!("{}", "─".repeat(60));
            println!("ID:        {}", checkpoint.checkpoint_id.as_str().cyan());
            println!("Name:      {}", checkpoint.checkpoint_name);
            println!("Host:      {}", checkpoint.host_key);
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
    }
}

pub fn rollback_result(format: &OutputFormat, result: &RollbackResult) {
    use hardener_state::FileRestoreAction;

    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(&result) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("{{\"error\": \"serialisation failed: {e}\"}}"),
        },
        _ => {
            let icon = if result.rollback_success {
                "✓".green()
            } else {
                "✗".red()
            };
            println!(
                "\n{icon} Rolled back to: {} ({})",
                result.rollback_checkpoint_name.bold(),
                result.rollback_checkpoint_id.dimmed()
            );

            for file in &result.rollback_files {
                let status = if file.restore_success {
                    "✓".green()
                } else {
                    "✗".red()
                };
                let action = match file.restore_action {
                    FileRestoreAction::Restored => "restored",
                    FileRestoreAction::Removed => "removed",
                    FileRestoreAction::PermissionsRestored => "permissions",
                    FileRestoreAction::Skipped => "skipped",
                };
                println!("  {status} [{action}] {}", file.restore_path);
                if let Some(err) = &file.restore_error {
                    println!("    {}", err.as_str().red());
                }
            }

            let restored = result
                .rollback_files
                .iter()
                .filter(|f| f.restore_success)
                .count();
            println!(
                "\n{} file(s) processed, {restored} restored successfully.",
                result.rollback_files.len()
            );
        }
    }
}

pub fn validation_reports(format: &OutputFormat, reports: &[ValidationReport]) {
    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(&reports) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("{{\"error\": \"serialisation failed: {e}\"}}"),
        },
        _ => {
            for report in reports {
                println!(
                    "{} {} - {} item(s) to apply",
                    "○".blue(),
                    report.validation_report_plugin_id.as_str(),
                    report.validation_report_estimated_changes.len(),
                );
                for item in &report.validation_report_estimated_changes {
                    println!("  {} {}", "•".dimmed(), item);
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_severity_critical() {
        let formatted = format_severity(&Severity::Critical);
        assert!(formatted.to_string().contains("CRIT"));
    }

    #[test]
    fn test_format_severity_high() {
        let formatted = format_severity(&Severity::High);
        assert!(formatted.to_string().contains("HIGH"));
    }

    #[test]
    fn test_format_severity_medium() {
        let formatted = format_severity(&Severity::Medium);
        assert!(formatted.to_string().contains("MED"));
    }

    #[test]
    fn test_format_severity_low() {
        let formatted = format_severity(&Severity::Low);
        assert!(formatted.to_string().contains("LOW"));
    }

    #[test]
    fn test_format_severity_info() {
        let formatted = format_severity(&Severity::Info);
        assert!(formatted.to_string().contains("INFO"));
    }

    #[test]
    fn format_change_error_indents_and_carries_the_message() {
        let line = format_change_error("permission denied writing /etc/sysctl.d/99-hardening.conf");
        assert!(line.starts_with("    "));
        assert!(line.contains("permission denied writing /etc/sysctl.d/99-hardening.conf"));
    }
}
