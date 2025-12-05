use crate::cli::OutputFormat;
use crate::output;
use anyhow::{bail, Result};
use hardener_common::types::PluginId;
use hardener_core::{Config, Context, SystemExecutor};
use hardener_plugins::create_plugin_registry;
use hardener_state::{init_db, CheckpointManager, CheckpointSigner};
use std::path::PathBuf;
use std::sync::Arc;

async fn get_checkpoint_manager() -> Result<CheckpointManager> {
    let data_dir = dirs::data_local_dir()
        .map(|p| p.join("linux-hardener"))
        .unwrap_or_else(|| PathBuf::from(".linux-hardener"));

    std::fs::create_dir_all(&data_dir)?;

    let db_path = data_dir.join("checkpoints.db");
    let key_path = data_dir.join("signing.key");

    let pool = init_db(Some(db_path.as_path())).await?;
    let signer = CheckpointSigner::new_with_path(&key_path)?;
    Ok(CheckpointManager::new_with_signer(pool, signer)?)
}

pub async fn run(
    plugin_filter: &[String],
    all: bool,
    dry_run: bool,
    format: OutputFormat,
    quiet: bool,
    executor: Arc<dyn SystemExecutor>,
) -> Result<()> {
    // Must be root to apply changes
    if !nix::unistd::geteuid().is_root() && !dry_run {
        bail!("Root privileges required to apply hardening changes. Use sudo or --dry-run.");
    }

    if plugin_filter.is_empty() && !all {
        bail!("Specify plugins with --plugin or use --all to apply all plugins.");
    }

    let registry = create_plugin_registry();

    // Create context with checkpoint manager for automatic rollback support
    let mut ctx = Context::with_executor(executor);
    if !dry_run {
        let manager = get_checkpoint_manager().await?;
        Context::with_checkpoint_manager(manager)
    } else {
        Context::new()
    };

    let config = Config;

    let plugins = registry.list()?;
    let plugin_ids: Vec<PluginId> = if all {
        plugins.iter().map(|m| m.plugin_id.clone()).collect()
    } else {
        plugin_filter.iter().map(PluginId::new).collect()
    };

    if dry_run {
        output::info(&format, "Dry run - no changes will be made");
    }

    let mut results = Vec::new();

    for plugin_id in &plugin_ids {
        if let Ok(Some(plugin)) = registry.get(plugin_id) {
            let metadata = plugin.metadata();

            if !quiet {
                output::status(&format, &format!("Applying: {}", metadata.plugin_name));
            }

            if dry_run {
                // Just validate without applying
                match plugin.validate(&ctx, &config).await {
                    Ok(report) => {
                        output::validation_report(&format, &metadata, &report);
                    }
                    Err(e) => {
                        output::error(
                            &format,
                            &format!("Validation failed for {}: {}", metadata.plugin_name, e),
                        );
                    }
                }
            } else {
                match plugin.apply(&mut ctx, &config).await {
                    Ok(result) => {
                        results.push((metadata, result));
                    }
                    Err(e) => {
                        output::error(
                            &format,
                            &format!("Failed to apply {}: {e}", metadata.plugin_name),
                        );
                    }
                }
            }
        } else {
            output::error(
                &format,
                &format!("Plugin not found: {}", plugin_id.as_str()),
            );
        }
    }

    if !dry_run {
        output::apply_results(&format, &results);
    }

    Ok(())
}
