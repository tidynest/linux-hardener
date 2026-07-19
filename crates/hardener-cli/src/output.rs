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
                for line in scan_plugin_lines(metadata, findings, unchecked) {
                    println!("{line}");
                }
                total_findings += findings.len();
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

/// Builds the terminal lines for one plugin's scan section, returned as
/// strings so tests can assert attribution without capturing stdout.
///
/// The plugin-name header prints whenever the plugin has findings OR
/// unchecked entries; an unchecked-only plugin therefore never renders an
/// anonymous block that visually attaches to the previous plugin's header.
/// Unchecked entries are deduplicated by `unchecked_check_id` (the audit
/// plugin emits one entry per underlying rule and several rules share an
/// id), mirroring the GUI's findings-tab dedupe; headers keep the honest
/// raw count and collapsed lines carry an `(xN)` multiplier so no check
/// appears to have vanished.
fn scan_plugin_lines(
    metadata: &PluginMetadata,
    findings: &[Finding],
    unchecked: &[UncheckedCheck],
) -> Vec<String> {
    if findings.is_empty() && unchecked.is_empty() {
        return vec![format!(
            "{} {} - {}",
            "✓".green(),
            metadata.plugin_name,
            "No issues found".dimmed()
        )];
    }

    let mut lines = Vec::new();
    let unchecked_note = format!(
        "{} check(s) could not be verified without root",
        unchecked.len()
    );

    // Unchecked entries nest one level deeper when they sit under a
    // findings sub-header rather than directly under the plugin header.
    let mut unchecked_indent = "  ";
    if findings.is_empty() {
        lines.push(format!(
            "\n{} {} - {}",
            "?".dimmed(),
            metadata.plugin_name.bold(),
            unchecked_note.dimmed()
        ));
    } else {
        lines.push(format!(
            "\n{} {} - {} finding(s)",
            "!".yellow(),
            metadata.plugin_name.bold(),
            findings.len()
        ));
        for finding in findings {
            let severity_str = format_severity(&finding.finding_severity);
            lines.push(format!(
                "  {} [{}] {}",
                "•".dimmed(),
                severity_str,
                finding.finding_title
            ));
            if !finding.finding_description.is_empty() {
                lines.push(format!("    {}", finding.finding_description.dimmed()));
            }
        }
        if !unchecked.is_empty() {
            lines.push(format!("  {} {}", "?".dimmed(), unchecked_note.dimmed()));
            unchecked_indent = "    ";
        }
    }

    for (entry, occurrences) in dedupe_unchecked(unchecked) {
        let multiplier = if occurrences > 1 {
            format!(" (x{occurrences})")
        } else {
            String::new()
        };
        lines.push(format!(
            "{unchecked_indent}{} {}{} - {}",
            "·".dimmed(),
            entry.unchecked_title.dimmed(),
            multiplier.dimmed(),
            entry.unchecked_reason.dimmed()
        ));
    }
    lines
}

/// Deduplicates unchecked entries by `unchecked_check_id`, preserving first
/// appearance order and counting occurrences so renderers can keep the raw
/// total honest.
fn dedupe_unchecked(unchecked: &[UncheckedCheck]) -> Vec<(&UncheckedCheck, usize)> {
    let mut deduped: Vec<(&UncheckedCheck, usize)> = Vec::new();
    let mut index: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for entry in unchecked {
        match index.get(entry.unchecked_check_id.as_str()) {
            Some(&at) => deduped[at].1 += 1,
            None => {
                index.insert(entry.unchecked_check_id.as_str(), deduped.len());
                deduped.push((entry, 1));
            }
        }
    }
    deduped
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
                    println!(
                        "{} {} - {}",
                        icon,
                        metadata.plugin_name,
                        apply_summary(result)
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

/// Builds the per-plugin summary phrase for apply output. When any change
/// failed the phrase says so numerically ("1 of 5 change(s) applied,
/// 4 failed") so the number next to "applied" only ever counts successes;
/// with no failures the plain "N change(s) applied[, M skipped]" wording is
/// kept.
fn apply_summary(result: &ApplyResult) -> String {
    let applied = result.applied_change_count();
    let failed = result.failed_change_count();
    let skipped = result.skipped_change_count();
    let skip_suffix = if skipped > 0 {
        format!(", {skipped} skipped")
    } else {
        String::new()
    };
    if failed > 0 {
        let attempted = applied + failed;
        format!("{applied} of {attempted} change(s) applied, {failed} failed{skip_suffix}")
    } else {
        format!("{applied} change(s) applied{skip_suffix}")
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

/// Applies the shared severity colour scheme to an arbitrary label so other
/// renderers (the batch per-host sections) colour severity words identically
/// to the single-host output without duplicating the palette.
pub(crate) fn severity_label(text: &str, severity: &Severity) -> colored::ColoredString {
    match severity {
        Severity::Critical => text.red().bold(),
        Severity::High => text.red(),
        Severity::Medium => text.yellow(),
        Severity::Low => text.blue(),
        Severity::Info => text.dimmed(),
    }
}

fn format_severity(severity: &Severity) -> colored::ColoredString {
    let label = match severity {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED ",
        Severity::Low => "LOW ",
        Severity::Info => "INFO",
    };
    severity_label(label, severity)
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

    use hardener_core::plugin::{Change, ChangeType, FindingCategory, PluginId};

    fn change(change_type: ChangeType, success: bool) -> Change {
        Change {
            change_description: "test change".to_string(),
            change_type,
            change_success: success,
            change_error: (!success).then(|| "nft: command failed".to_string()),
        }
    }

    fn apply_result(changes: Vec<Change>) -> ApplyResult {
        ApplyResult {
            apply_plugin_id: PluginId::new("firewall-hardening"),
            apply_success: false,
            apply_changes: changes,
            apply_checkpoint_id: None,
            apply_error: None,
        }
    }

    #[test]
    fn apply_summary_reports_failures_numerically() {
        let result = apply_result(vec![
            change(ChangeType::FirewallRule, true),
            change(ChangeType::FirewallRule, false),
            change(ChangeType::FirewallRule, false),
            change(ChangeType::FirewallRule, false),
            change(ChangeType::FirewallRule, false),
            change(ChangeType::Skipped, true),
        ]);
        assert_eq!(
            apply_summary(&result),
            "1 of 5 change(s) applied, 4 failed, 1 skipped"
        );
    }

    #[test]
    fn apply_summary_keeps_plain_wording_when_nothing_failed() {
        let all_good = apply_result(vec![
            change(ChangeType::KernelParameter, true),
            change(ChangeType::KernelParameter, true),
        ]);
        assert_eq!(apply_summary(&all_good), "2 change(s) applied");

        let with_skip = apply_result(vec![
            change(ChangeType::KernelParameter, true),
            change(ChangeType::Skipped, true),
        ]);
        assert_eq!(apply_summary(&with_skip), "1 change(s) applied, 1 skipped");
    }

    fn metadata(name: &str) -> PluginMetadata {
        PluginMetadata {
            plugin_category: FindingCategory::Audit,
            plugin_description: "test".to_string(),
            plugin_id: PluginId::new("audit-hardening"),
            plugin_name: name.to_string(),
            plugin_version: "0.1.0".to_string(),
        }
    }

    fn unchecked(id: &str, title: &str) -> UncheckedCheck {
        UncheckedCheck {
            unchecked_check_id: id.to_string(),
            unchecked_title: title.to_string(),
            unchecked_category: FindingCategory::Audit,
            unchecked_reason: "listing loaded audit rules (auditctl -l) requires root".to_string(),
            unchecked_compliance: vec![],
        }
    }

    fn finding(title: &str) -> Finding {
        Finding {
            finding_category: FindingCategory::Audit,
            finding_current_value: "off".to_string(),
            finding_description: "test description".to_string(),
            finding_explanation: String::new(),
            finding_id: "audit-001".to_string(),
            finding_impact: String::new(),
            finding_recommended_value: "on".to_string(),
            finding_remediation_steps: vec![],
            finding_severity: Severity::Medium,
            finding_title: title.to_string(),
            finding_compliance: vec![],
            finding_policy_exception: None,
        }
    }

    #[test]
    fn unchecked_only_plugin_gets_a_named_header_and_deduped_lines() {
        let entries = vec![
            unchecked("audit-time-change", "Audit rule: time-change"),
            unchecked("audit-time-change", "Audit rule: time-change"),
            unchecked("audit-time-change", "Audit rule: time-change"),
            unchecked("audit-time-change", "Audit rule: time-change"),
            unchecked("audit-identity", "Audit rule: identity"),
        ];
        let lines = scan_plugin_lines(&metadata("Audit Rules Hardening"), &[], &entries);

        let header = &lines[0];
        assert!(
            header.contains("Audit Rules Hardening"),
            "header must name the plugin: {header}"
        );
        assert!(
            header.contains("5 check(s) could not be verified without root"),
            "header must keep the honest raw count: {header}"
        );

        let time_change: Vec<_> = lines
            .iter()
            .filter(|l| l.contains("Audit rule: time-change"))
            .collect();
        assert_eq!(time_change.len(), 1, "duplicates must collapse: {lines:?}");
        assert!(
            time_change[0].contains("(x4)"),
            "collapsed line must carry its multiplier: {}",
            time_change[0]
        );
        assert!(
            lines.iter().any(|l| l.contains("Audit rule: identity")),
            "unique entries must survive dedupe: {lines:?}"
        );
    }

    #[test]
    fn mixed_plugin_nests_findings_and_unchecked_under_one_header() {
        let lines = scan_plugin_lines(
            &metadata("PAM Hardening"),
            &[finding("Password history not enforced")],
            &[unchecked("pam-minlen", "PAM setting: minlen")],
        );

        let named: Vec<_> = lines
            .iter()
            .filter(|l| l.contains("PAM Hardening"))
            .collect();
        assert_eq!(named.len(), 1, "exactly one plugin header: {lines:?}");
        assert!(
            lines[0].contains("PAM Hardening"),
            "header first: {lines:?}"
        );
        assert!(lines[0].contains("1 finding(s)"));
        assert!(
            lines
                .iter()
                .any(|l| l.contains("1 check(s) could not be verified without root")),
            "unchecked sub-header nests under the same plugin: {lines:?}"
        );
        assert!(lines.iter().any(|l| l.contains("PAM setting: minlen")));
    }

    #[test]
    fn clean_plugin_line_is_unchanged() {
        let lines = scan_plugin_lines(&metadata("SSH Hardening"), &[], &[]);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("SSH Hardening"));
        assert!(lines[0].contains("No issues found"));
    }
}
