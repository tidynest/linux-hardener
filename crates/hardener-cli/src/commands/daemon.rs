//! Daemon command implementation.
//!
//! Provides CLI interface to the scheduled scanning daemon.

use crate::cli::OutputFormat;
use crate::output;
use anyhow::{Result, anyhow};
use hardener_core::{ConfigLoader, Context, PluginManager};
use hardener_scheduler::{
    Daemon, JsonStore, ScanHistoryManager, SchedulerConfig, TriggerType, db::SessionFilter,
};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;

/// Starts the daemon and blocks until shutdown signal.
pub async fn start(format: OutputFormat, quiet: bool, config_path: Option<&PathBuf>) -> Result<()> {
    let config = load_scheduler_config(config_path)?;

    if !config.enabled {
        return Err(anyhow!(
            "Scheduler is disabled. Set 'enabled = true' in [scheduler] config section."
        ));
    }

    if !quiet {
        output::status(
            &format,
            &format!("Starting daemon with schedule '{}'", config.schedule),
        );
    }

    // Initialise storage
    let db = Arc::new(
        ScanHistoryManager::new(&config.storage.database_path)
            .await
            .map_err(|e| anyhow!("Failed to initialise database: {}", e))?,
    );
    let json_store = Arc::new(
        JsonStore::new(&config.storage.json_output_dir)
            .await
            .map_err(|e| anyhow!("Failed to initialise json store: {}", e))?,
    );

    // Create daemon
    let mut daemon = Daemon::new(config, db, json_store);

    // Set up plugin manager
    let registry = hardener_plugins::create_plugin_registry();
    let mut pm = PluginManager::new(registry);
    pm.resolve_dependencies()?;

    let ctx = Context::new();

    if !quiet {
        output::status(&format, "Daemon running. Press Ctrl-C to stop.");
    }

    // Start blocks until shutdown
    daemon
        .start(Arc::new(pm), Arc::new(ctx))
        .await
        .map_err(|e| anyhow!("Daemon error: {}", e))?;

    if !quiet {
        output::status(&format, "Daemon stopped.");
    }

    Ok(())
}

/// Runs a single scan immediately.
pub async fn run_once(
    format: OutputFormat,
    quiet: bool,
    config_path: Option<&PathBuf>,
) -> Result<()> {
    let config = load_scheduler_config(config_path)?;

    if !quiet {
        output::status(&format, "Running single scan...");
    }

    // Initialise storage
    let db = Arc::new(
        ScanHistoryManager::new(&config.storage.database_path)
            .await
            .map_err(|e| anyhow!("Failed to initialise database: {}", e))?,
    );
    let json_store = Arc::new(
        JsonStore::new(&config.storage.json_output_dir)
            .await
            .map_err(|e| anyhow!("Failed to initialise JSON store: {}", e))?,
    );

    // Create daemon (doesn't need to be enabled for run_once)
    let daemon = Daemon::new(config, db, json_store);

    // Set up plugin manager
    let registry = hardener_plugins::create_plugin_registry();
    let mut pm = PluginManager::new(registry);
    pm.resolve_dependencies()?;

    let ctx = Context::new();

    let summary = daemon
        .run_once(&pm, &ctx, TriggerType::Manual)
        .await
        .map_err(|e| anyhow!("Scan failed: {}", e))?;

    // Output results
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        _ => {
            println!("\nScan Complete");
            println!("  Session:  {}", summary.session_id);
            println!("  Host:  {}", summary.host);
            println!("  Findings:  {}", summary.total_findings);
            println!(
                "    Critical: {}, High: {}, Medium: {}, Low: {}",
                summary.critical_count, summary.high_count, summary.medium_count, summary.low_count
            );
            if let Some(path) = &summary.json_path {
                println!("  Export:   {}", path);
            }
        }
    }

    Ok(())
}

/// Shows daemon status and recent scan history.
pub async fn status(
    format: OutputFormat,
    quiet: bool,
    limit: u32,
    config_path: Option<&PathBuf>,
) -> Result<()> {
    let config = load_scheduler_config(config_path)?;

    // Try to connect to database
    let db = ScanHistoryManager::new(&config.storage.database_path)
        .await
        .map_err(|e| anyhow!("Failed to initialise database: {}", e))?;

    let filter = SessionFilter {
        limit: Some(limit),
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
            if !quiet {
                println!("Scheduler Configuration:");
                println!("  Enabled:  {}", config.enabled);
                println!("  Schedule: {}", config.schedule);
                println!("  Database: {}", config.storage.database_path.display());
                println!();
            }

            if sessions.is_empty() {
                println!("No scan history found.");
            } else {
                println!("Scan History ({}):", sessions.len());
                println!(
                    "{:<36} {:<10} {:<8} {:>5} {:>5} {:>5}",
                    "Session ID", "Status", "Trigger", "Crit", "High", "Med"
                );
                println!("{}", "-".repeat(75));

                for session in &sessions {
                    println!(
                        "{:<36} {:<10} {:<8} {:>5} {:>5} {:>5}",
                        &session.id[..36.min(session.id.len())],
                        session.status,
                        session.trigger_type,
                        session.critical_count,
                        session.high_count,
                        session.medium_count,
                    );
                }
            }
        }
    }

    Ok(())
}

/// Configuration file structure for parsing scheduler section.
///
/// `Option`, not a defaulted `SchedulerConfig`: a file that says nothing about
/// the scheduler is not that file configuring the scheduler, and the two were
/// indistinguishable while the section defaulted. That mattered most where the
/// section is read from the first file found rather than merged, because
/// "found" then meant "the first file that exists" rather than "the first file
/// that configures this", so a config mentioning only `[global]` silenced the
/// one that had the settings.
#[derive(Deserialize)]
struct ConfigFile {
    #[serde(default)]
    scheduler: Option<SchedulerConfig>,
}

/// Loads scheduler configuration: the path `--config` named, if it named one
/// and that file configures the scheduler, else the standard locations.
///
/// This took no path at all, so `-C` reached the hardening policy and not the
/// `[scheduler]` section beside it: one file carrying both was half honoured,
/// and `scan` read its policy from the named file and then wrote its history to
/// whatever database the default search found.
///
/// The named path is searched **first**, not **instead**. A file that says
/// nothing about the scheduler is not that file configuring the scheduler, so
/// the search goes on. Replacing the search outright looked equivalent and was
/// not: `systemd generate`/`install` embed the `--config` path in the unit they
/// write, so a timer installed against a policy file got a scheduled scan on
/// the compiled-in defaults, which is disabled, on another schedule, writing to
/// another database, while the operator's own config said otherwise and nothing
/// reported it.
///
/// The section still does not merge. The first file that configures it wins
/// whole, which is what `configuration.md` describes; the named path only joins
/// the front of that order. A named path that is missing, unreadable or
/// unparseable is an error, because the flag exists to decide the run.
///
/// Uses the same paths as `ConfigLoader` to avoid duplication.
pub fn load_scheduler_config(config_path: Option<&PathBuf>) -> Result<SchedulerConfig> {
    if let Some(named) = config_path {
        if !named.exists() {
            return Err(anyhow!("Config file not found: {}", named.display()));
        }
        if let Some(scheduler) = read_scheduler_section(named)? {
            return Ok(scheduler);
        }
    }

    // Then the default locations, user config before system config.
    // (ConfigLoader checks in reverse order for merging, but only the first
    // found is needed.)
    for path in [
        ConfigLoader::user_config_path(),
        ConfigLoader::system_config_path(),
    ]
    .into_iter()
    .flatten()
    {
        if path.exists()
            && let Some(scheduler) = read_scheduler_section(&path)?
        {
            return Ok(scheduler);
        }
    }

    // Nothing configures the scheduler, so the defaults are the honest answer.
    Ok(SchedulerConfig::default())
}

/// The `[scheduler]` section of one file, or `None` when the file has none.
fn read_scheduler_section(path: &std::path::Path) -> Result<Option<SchedulerConfig>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("Failed to read config file {}: {}", path.display(), e))?;
    let config: ConfigFile = toml::from_str(&content)
        .map_err(|e| anyhow!("Failed to parse config file {}: {}", path.display(), e))?;
    Ok(config.scheduler)
}
