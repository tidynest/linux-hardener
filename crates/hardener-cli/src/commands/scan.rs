//! Scan command: runs security plugins with filtering and persists results to history.

use crate::cli::{OutputFormat, ScanMode, SeverityFilter};
use crate::commands::daemon::load_scheduler_config;
use crate::commands::report::finding_to_scan_finding;
use crate::output;
use anyhow::Result;
use hardener_common::types::Severity;
use hardener_core::{
    ConfigLoader, Context, HardenerConfig, PluginMetadata,
    executor::SystemExecutor,
    plugin::{Finding, UncheckedCheck},
};
use hardener_scheduler::ScanHistoryManager;
use hardener_scheduler::db::ScanFinding;
use std::{path::PathBuf, sync::Arc};

pub struct ScanOptions<'a> {
    pub plugin_filter: &'a [String],
    pub severity_filter: SeverityFilter,
    pub format: OutputFormat,
    pub quiet: bool,
    pub config_path: Option<&'a PathBuf>,
    pub audit: bool,
    pub compliance: bool,
    pub exit_code: bool,
    pub timings: bool,
    pub executor: Arc<dyn SystemExecutor>,
}

pub async fn run(opts: ScanOptions<'_>) -> Result<()> {
    // Determine scan mode
    let mode = if opts.audit {
        ScanMode::Audit
    } else if opts.compliance {
        ScanMode::Compliance
    } else {
        ScanMode::Default
    };

    // Load config (ignored in audit mode)
    let _config = load_config(opts.config_path, mode)?;
    let registry = hardener_plugins::create_plugin_registry();
    let ctx = Context::with_executor(opts.executor.clone());

    let plugins = registry.list()?;
    validate_plugin_filter(opts.plugin_filter, &plugins)?;
    let min_severity = severity_filter_to_severity(&opts.severity_filter);

    // Resolve the selected plugin handles up front (registry hands out Arcs).
    let selected: Vec<_> = plugins
        .iter()
        .filter(|metadata| {
            opts.plugin_filter.is_empty()
                || opts
                    .plugin_filter
                    .iter()
                    .any(|p| is_valid_plugin_name(p, &[metadata.plugin_id.as_str()]))
        })
        .filter_map(|metadata| {
            registry
                .get(&metadata.plugin_id)
                .ok()
                .flatten()
                .map(|plugin| (metadata.clone(), plugin))
        })
        .collect();

    if !opts.quiet {
        for (metadata, _) in &selected {
            output::status(&opts.format, &format!("Scanning: {}", metadata.plugin_name));
        }
    }

    // Plugins are independent, so scan them concurrently. join_all yields
    // results in input order, which keeps the rendered output deterministic.
    let wall = std::time::Instant::now();
    let scans =
        futures::future::join_all(selected.iter().map(|(_, plugin)| plugin.scan(&ctx))).await;
    let wall_elapsed = wall.elapsed();

    let mut all_results = Vec::new();
    let mut plugin_timings = Vec::new();

    for ((metadata, _), scan) in selected.iter().zip(scans) {
        match scan {
            Ok(results) => {
                plugin_timings.push((metadata.plugin_name.clone(), results.scan_duration_us));
                // Filter findings by severity
                let filtered_findings: Vec<_> = results
                    .scan_findings
                    .iter()
                    .filter(|f| f.finding_severity >= min_severity)
                    .cloned()
                    .collect();
                all_results.push((
                    metadata.clone(),
                    filtered_findings,
                    results.scan_unchecked.clone(),
                ));
            }
            Err(e) => {
                output::error(
                    &opts.format,
                    &format!("Failed to scan {}: {e}", metadata.plugin_name),
                );
            }
        }
    }

    output::scan_results(&opts.format, &all_results, mode);

    if opts.timings {
        output::scan_timings(&plugin_timings, wall_elapsed);
    }

    // Persist scan session to history database
    persist_scan_session(&all_results).await;

    // Handle exit code flag
    if opts.exit_code {
        let has_findings = all_results
            .iter()
            .any(|(_, findings, _)| !findings.is_empty());
        if has_findings {
            std::process::exit(1);
        }
    }

    Ok(())
}

fn load_config(config_path: Option<&PathBuf>, mode: ScanMode) -> Result<HardenerConfig> {
    // In audit mode, ignore all config and use defaults
    if mode == ScanMode::Audit {
        return Ok(HardenerConfig::default());
    }

    let mut loader = ConfigLoader::new();
    if let Some(path) = config_path {
        loader = loader.with_cli_config(path.clone());
    }
    loader
        .load()
        .map_err(|e| anyhow::anyhow!("Config error: {}", e))
}

fn severity_filter_to_severity(filter: &SeverityFilter) -> Severity {
    match filter {
        SeverityFilter::Info => Severity::Info,
        SeverityFilter::Low => Severity::Low,
        SeverityFilter::Medium => Severity::Medium,
        SeverityFilter::High => Severity::High,
        SeverityFilter::Critical => Severity::Critical,
    }
}

/// Validates plugin filter entries and returns error if any are invalid.
/// Accepts both full IDs (e.g., "kernel-hardening") and short names (e.g., "kernel").
fn validate_plugin_filter(
    filter: &[String],
    valid_plugins: &[hardener_core::PluginMetadata],
) -> Result<()> {
    if filter.is_empty() {
        return Ok(());
    }

    let valid_ids: Vec<&str> = valid_plugins.iter().map(|p| p.plugin_id.as_str()).collect();

    let invalid: Vec<&str> = filter
        .iter()
        .filter(|f| !is_valid_plugin_name(f, &valid_ids))
        .map(|s| s.as_str())
        .collect();

    if invalid.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(
            "Unknown plugin(s): {}. Valid plugins: {}",
            invalid.join(", "),
            valid_ids.join(", ")
        )
    }
}

/// Checks if a filter entry matches a valid plugin (full ID or short name).
fn is_valid_plugin_name(name: &str, valid_ids: &[&str]) -> bool {
    valid_ids
        .iter()
        .any(|id| *id == name || id.starts_with(&format!("{}-", name)))
}

/// Persists scan results to the history database.
///
/// Failures are logged but do not propagate; scan output is already displayed,
/// so history persistence is best-effort.
async fn persist_scan_session(results: &[(PluginMetadata, Vec<Finding>, Vec<UncheckedCheck>)]) {
    let db = match open_history_db().await {
        Ok(db) => db,
        Err(_) => return,
    };

    let plugins: Vec<String> = results
        .iter()
        .map(|(m, _, _)| m.plugin_id.to_string())
        .collect();
    let hostname = std::fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|_| "localhost".to_string());

    let session_id = match db.create_session("cli", &hostname, &plugins).await {
        Ok(id) => id,
        Err(_) => return,
    };

    let findings: Vec<ScanFinding> = results
        .iter()
        .flat_map(|(meta, findings, _)| {
            findings
                .iter()
                .map(move |f| finding_to_scan_finding(meta, f))
        })
        .collect();

    let _ = db
        .complete_session(&session_id, &findings, None, None)
        .await;
}

/// Opens the scan history database using scheduler config paths.
async fn open_history_db() -> Result<ScanHistoryManager> {
    let config = load_scheduler_config()?;
    ScanHistoryManager::new(&config.storage.database_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open history database: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_IDS: &[&str] = &[
        "ssh-hardening",
        "kernel-hardening",
        "firewall-hardening",
        "pam-hardening",
        "audit-hardening",
        "mac-hardening",
        "permissions-hardening",
        "service-minimisation",
    ];

    #[test]
    fn test_valid_full_id() {
        assert!(is_valid_plugin_name("kernel-hardening", ALL_IDS));
    }

    #[test]
    fn test_valid_short_name() {
        assert!(is_valid_plugin_name("kernel", ALL_IDS));
    }

    #[test]
    fn test_valid_service_short() {
        assert!(is_valid_plugin_name("service", ALL_IDS));
    }

    #[test]
    fn test_invalid_name() {
        assert!(!is_valid_plugin_name("nonexistent", ALL_IDS));
    }

    #[test]
    fn scan_json_entry_carries_unchecked_key() {
        // The renderer contract Task 10's desktop parser depends on.
        let value = serde_json::json!({
            "plugin_id": "pam-hardening",
            "plugin_name": "PAM Hardening",
            "findings": [],
            "unchecked": [{
                "unchecked_check_id": "pam-minlen",
                "unchecked_title": "PAM setting: minlen",
                "unchecked_category": "Authentication",
                "unchecked_reason": "reading /etc/security/pwquality.conf requires root",
                "unchecked_compliance": []
            }],
        });
        let unchecked: Vec<hardener_core::plugin::UncheckedCheck> =
            serde_json::from_value(value["unchecked"].clone()).unwrap();
        assert_eq!(unchecked[0].unchecked_check_id, "pam-minlen");
    }
}
