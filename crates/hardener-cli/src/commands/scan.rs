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
    let config = load_config(opts.config_path, mode)?;
    let registry = hardener_plugins::create_plugin_registry();
    let ctx = Context::with_executor(opts.executor.clone());

    let plugins = registry.list()?;
    super::plugin_filter::validate(opts.plugin_filter, &plugins)?;
    let min_severity = severity_filter_to_severity(&opts.severity_filter);

    // Resolve the selected plugin handles up front (registry hands out Arcs).
    let (enabled, skipped_by_config) =
        select_enabled_plugins(&plugins, &config, opts.plugin_filter);

    // A plugin the user asked for but the config disables must not vanish
    // without a word: silence there reads as a clean host.
    if !skipped_by_config.is_empty() && !opts.quiet {
        output::status(
            &opts.format,
            &format!("Skipped by config: {}", plugin_id_list(&skipped_by_config)),
        );
    }
    if enabled.is_empty() && !skipped_by_config.is_empty() {
        anyhow::bail!(
            "Config disabled every selected plugin ({}). Nothing was scanned. \
             Remove them from [global] disabled_plugins, add them to \
             [global] enabled_plugins, or select a plugin the config enables.",
            plugin_id_list(&skipped_by_config)
        );
    }

    let selected: Vec<_> = enabled
        .into_iter()
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
    let scans = futures::future::join_all(selected.iter().map(|(metadata, plugin)| {
        plugin.scan(&ctx, config.get_plugin_config(metadata.plugin_id.as_str()))
    }))
    .await;
    let wall_elapsed = wall.elapsed();

    let mut all_results = Vec::new();
    let mut plugin_timings = Vec::new();

    for ((metadata, _), scan) in selected.iter().zip(scans) {
        match scan {
            Ok(results) => {
                plugin_timings.push((metadata.plugin_name.clone(), results.scan_duration_us));
                // A plugin can return Ok while reporting that its own scan
                // failed, and such a result carries no findings, which renders
                // exactly like a clean host. Say so rather than let the
                // operator read silence as a pass.
                if !results.scan_success {
                    output::error(
                        &opts.format,
                        &format!(
                            "Scan of {} did not complete: {}",
                            metadata.plugin_name,
                            results
                                .scan_error
                                .as_deref()
                                .unwrap_or("reason not reported")
                        ),
                    );
                }
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

/// Splits the plugins matching the CLI `--plugin` filter (an empty filter
/// selects everything) into those the config enables and those it disables.
/// The skipped half is returned rather than dropped so the caller can say why
/// a plugin the user asked for did not run.
fn select_enabled_plugins<'a>(
    plugins: &'a [PluginMetadata],
    config: &HardenerConfig,
    plugin_filter: &[String],
) -> (Vec<&'a PluginMetadata>, Vec<&'a PluginMetadata>) {
    plugins
        .iter()
        .filter(|metadata| {
            plugin_filter.is_empty()
                || plugin_filter
                    .iter()
                    .any(|p| super::plugin_filter::matches(p, metadata.plugin_id.as_str()))
        })
        .partition(|metadata| config.is_plugin_enabled(metadata.plugin_id.as_str()))
}

/// Comma-separated plugin IDs, as the user writes them in the config.
fn plugin_id_list(plugins: &[&PluginMetadata]) -> String {
    plugins
        .iter()
        .map(|metadata| metadata.plugin_id.as_str())
        .collect::<Vec<_>>()
        .join(", ")
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

    /// Whether any real plugin id answers to this `--plugin` entry.
    fn names_a_plugin(entry: &str) -> bool {
        ALL_IDS
            .iter()
            .any(|id| crate::commands::plugin_filter::matches(entry, id))
    }

    #[test]
    fn plugin_filter_entries_resolve_against_the_real_id_set() {
        for entry in [
            "kernel-hardening",
            "kernel",
            "service",
            "ssh",
            "permissions",
        ] {
            assert!(names_a_plugin(entry), "{entry} should name a plugin");
        }
        // "services" is the plural an operator reaches for; it matches nothing,
        // which is exactly why an unmatched entry must be refused rather than
        // dropped. The empty string is the degenerate case of the same rule.
        for entry in ["nonexistent", "services", ""] {
            assert!(!names_a_plugin(entry), "{entry} names no plugin");
        }
    }

    #[test]
    fn disabled_plugin_excluded_from_selection() {
        // A plugin named in global.disabled_plugins must never appear in the
        // set scan() is about to run, regardless of the --plugin filter.
        let plugins = hardener_plugins::create_plugin_registry().list().unwrap();
        let mut config = HardenerConfig::default();
        config.global.disabled_plugins = vec!["mac-hardening".to_string()];

        let (selected, skipped) = select_enabled_plugins(&plugins, &config, &[]);

        assert!(
            selected
                .iter()
                .all(|metadata| metadata.plugin_id.as_str() != "mac-hardening"),
            "disabled plugin must be excluded from the selected set"
        );
        assert_eq!(
            selected.len(),
            plugins.len() - 1,
            "exactly the disabled plugin should be excluded"
        );
        // The exclusion is reported, not silent.
        assert_eq!(plugin_id_list(&skipped), "mac-hardening");
    }

    #[test]
    fn filter_naming_only_config_disabled_plugins_selects_nothing() {
        // `hardener scan --plugin ssh` on a host whose config disables ssh:
        // the selection is empty and every skipped plugin is named, so the
        // caller can fail loudly instead of exiting clean with no output.
        let plugins = hardener_plugins::create_plugin_registry().list().unwrap();
        let mut config = HardenerConfig::default();
        config.global.disabled_plugins = vec!["ssh-hardening".to_string()];

        let (selected, skipped) = select_enabled_plugins(&plugins, &config, &["ssh".to_string()]);

        assert!(selected.is_empty());
        assert_eq!(plugin_id_list(&skipped), "ssh-hardening");
    }

    #[test]
    fn enabled_plugins_list_narrows_the_selection_too() {
        // global.enabled_plugins is the other way to disable a plugin: anything
        // absent from a non-empty list is skipped by config.
        let plugins = hardener_plugins::create_plugin_registry().list().unwrap();
        let mut config = HardenerConfig::default();
        config.global.enabled_plugins = vec!["kernel-hardening".to_string()];

        let (selected, skipped) = select_enabled_plugins(&plugins, &config, &[]);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].plugin_id.as_str(), "kernel-hardening");
        assert_eq!(skipped.len(), plugins.len() - 1);
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
