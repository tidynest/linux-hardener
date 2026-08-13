//! Scan command: runs security plugins with filtering and persists results to history.

use crate::cli::{OutputFormat, ScanMode, SeverityFilter};
use crate::commands::daemon::load_scheduler_config;
use crate::commands::report::finding_to_scan_finding;
use crate::output;
use anyhow::Result;
use hardener_common::types::Severity;
use hardener_core::{
    Context, HardenerConfig, PluginMetadata, ScanResult,
    executor::{SystemExecutor, session_host_key},
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
    pub exit_code: bool,
    pub timings: bool,
    pub executor: Arc<dyn SystemExecutor>,
}

pub async fn run(opts: ScanOptions<'_>) -> Result<()> {
    // Determine scan mode
    let mode = if opts.audit {
        ScanMode::Audit
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
    // A second clock, because the two answer different questions. `wall` is
    // monotonic and measures elapsed time; the history row needs an instant it
    // can store, and `Instant` cannot be converted to one. Taken here rather
    // than at persistence, which happens after every plugin has finished and so
    // recorded the completion time under the name `started_at` (#168).
    let scan_started_at = chrono::Utc::now().timestamp();
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
                // Filter findings by severity, keeping the rest of the result
                // intact so scan_success and scan_error survive to the
                // renderer instead of dying at the tuple boundary.
                let filtered_findings: Vec<_> = results
                    .scan_findings
                    .iter()
                    .filter(|f| f.finding_severity >= min_severity)
                    .cloned()
                    .collect();
                all_results.push((
                    metadata.clone(),
                    ScanResult {
                        scan_findings: filtered_findings,
                        ..results
                    },
                ));
            }
            Err(e) => {
                output::error(
                    &opts.format,
                    &format!("Failed to scan {}: {e}", metadata.plugin_name),
                );
                // Recorded rather than dropped: a plugin missing from the
                // results renders as one that was never selected, and the
                // JSON consumer cannot tell it apart from a clean scan.
                all_results.push((
                    metadata.clone(),
                    ScanResult {
                        scan_plugin_id: metadata.plugin_id.clone(),
                        scan_success: false,
                        scan_findings: Vec::new(),
                        scan_unchecked: Vec::new(),
                        scan_duration_us: 0,
                        scan_error: Some(e.to_string()),
                    },
                ));
            }
        }
    }

    output::scan_results(&opts.format, &all_results);

    if opts.timings {
        output::scan_timings(&plugin_timings, wall_elapsed);
    }

    // Persist scan session to history database
    persist_scan_session(
        &all_results,
        opts.executor.as_ref(),
        opts.config_path,
        scan_started_at,
    )
    .await;

    // Handle exit code flag. An incomplete scan exits non-zero too: a clean
    // exit is a positive claim about the host, and a plugin that never ran
    // has not earned it.
    if opts.exit_code {
        let has_findings = all_results
            .iter()
            .any(|(_, result)| !result.scan_findings.is_empty());
        let incomplete = all_results.iter().any(|(_, result)| !result.scan_success);
        if has_findings || incomplete {
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

    super::config_loader(config_path)
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
async fn persist_scan_session(
    results: &[(PluginMetadata, ScanResult)],
    executor: &dyn SystemExecutor,
    config_path: Option<&PathBuf>,
    started_at: i64,
) {
    let db = match open_history_db(config_path).await {
        Ok(db) => db,
        Err(_) => return,
    };

    let plugins: Vec<String> = results
        .iter()
        .map(|(m, _)| m.plugin_id.to_string())
        .collect();
    let hostname = session_host_key(executor).await;

    let session_id = match db
        .create_session_started_at("cli", &hostname, &plugins, started_at)
        .await
    {
        Ok(id) => id,
        Err(_) => return,
    };

    let findings: Vec<ScanFinding> = results
        .iter()
        .flat_map(|(meta, result)| {
            result
                .scan_findings
                .iter()
                .map(move |f| finding_to_scan_finding(meta, f))
        })
        .collect();

    let _ = db
        .complete_session(&session_id, &findings, None, None)
        .await;
}

/// Opens the scan history database using scheduler config paths.
async fn open_history_db(config_path: Option<&PathBuf>) -> Result<ScanHistoryManager> {
    let config = load_scheduler_config(config_path)?;
    ScanHistoryManager::new(&config.storage.database_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open history database: {}", e))
}

#[cfg(test)]
mod tests;
