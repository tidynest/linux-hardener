//! Daemon command implementation.
//!
//! Provides CLI interface to the scheduled scanning daemon.

use crate::cli::OutputFormat;
use crate::output;
use anyhow::{anyhow, Result};
use hardener_core::{ConfigLoader, Context, PluginManager};
use hardener_scheduler::{
    db::SessionFilter, Daemon, JsonStore, ScanHistoryManager, SchedulerConfig, TriggerType,
};
use serde::Deserialize;
use std::sync::Arc;

/// Starts the daemon and blocks until shutdown signal.
pub async fn start(format: OutputFormat, quiet: bool) -> Result<()> {
    let config = load_scheduler_config()?;

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
pub async fn run_once(format: OutputFormat, quiet: bool) -> Result<()> {
    let config = load_scheduler_config()?;

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
                summary.critical_count,
                summary.high_count,
                summary.medium_count,
                summary.low_count
            );
            if let Some(path) = &summary.json_path {
                println!("  Export:   {}", path);
            }
        }
    }

    Ok(())
}

/// Shows daemon status and recent scan history.
pub async fn status(format: OutputFormat, quiet: bool, limit: u32) -> Result<()> {
    let config = load_scheduler_config()?;

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
#[derive(Deserialize)]
struct ConfigFile {
    #[serde(default)]
    scheduler: SchedulerConfig,
}

/// Loads scheduler configuration from standard config file locations.
///
/// Uses the same paths as `ConfigLoader` to avoid duplication.
fn load_scheduler_config() -> Result<SchedulerConfig> {
    // Check locations in order: user config, then system config
    // (ConfigLoader checks in reverse order for merging, but only the first found is needed)
    let paths = [
        ConfigLoader::user_config_path(),
        ConfigLoader::system_config_path(),
    ];

    for path in paths.into_iter().flatten() {
        if path.exists() {
            let content = std::fs::read_to_string(&path).map_err(|e| {
                anyhow!("Failed to read config file {}: {}", path.display(), e)
            })?;

            let config: ConfigFile = toml::from_str(&content).map_err(|e| {
                anyhow!("Failed to parse config file {}: {}", path.display(), e)
            })?;

            return Ok(config.scheduler);
        }
    }

    // No config file found, use defaults
    Ok(SchedulerConfig::default())
}
