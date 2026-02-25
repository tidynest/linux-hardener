//! Apply command — applies hardening changes with dry-run and checkpoint support.

use crate::cli::OutputFormat;
use crate::output;
use anyhow::{Result, bail};
use hardener_common::types::PluginId;
use hardener_core::{ConfigLoader, Context, HardenerConfig, SystemExecutor};
use hardener_plugins::create_plugin_registry;
use hardener_state::{ActionResult, ActionType};
use std::sync::Arc;

use super::state::{get_audit_logger, get_checkpoint_manager};

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
    let mut ctx = if !dry_run {
        let manager = get_checkpoint_manager().await?;
        Context::with_executor_and_checkpoint(executor, manager)
    } else {
        Context::with_executor(executor)
    };
    if let Some(logger) = get_audit_logger().await {
        ctx.set_audit_logger(logger);
    }

    let hardener_config = ConfigLoader::new()
        .load()
        .unwrap_or_else(|_| HardenerConfig::default());

    let plugins = registry.list()?;
    let plugin_ids: Vec<PluginId> = if all {
        plugins.iter().map(|m| m.plugin_id.clone()).collect()
    } else {
        // Expand short names to full plugin IDs (e.g., "kernel" -> "kernel-hardening")
        plugin_filter
            .iter()
            .filter_map(|filter| {
                plugins
                    .iter()
                    .find(|p| {
                        p.plugin_id.as_str() == filter
                            || p.plugin_id.as_str().starts_with(&format!("{}-", filter))
                    })
                    .map(|p| p.plugin_id.clone())
            })
            .collect()
    };

    if dry_run {
        output::info(&format, "Dry run - no changes will be made");
    }

    let mut results = Vec::new();
    let mut validation_reports = Vec::new();
    let mut had_failure = false;

    for plugin_id in &plugin_ids {
        if let Ok(Some(plugin)) = registry.get(plugin_id) {
            // Skip disabled plugins
            let id_str = plugin_id.as_str();
            if !hardener_config.global.disabled_plugins.is_empty()
                && hardener_config
                    .global
                    .disabled_plugins
                    .iter()
                    .any(|d| d == id_str)
            {
                if !quiet {
                    output::status(&format, &format!("Skipping (disabled): {}", id_str));
                }
                continue;
            }
            let plugin_config = hardener_config.get_plugin_config(id_str);
            let metadata = plugin.metadata();

            if !quiet {
                output::status(&format, &format!("Applying: {}", metadata.plugin_name));
            }

            if dry_run {
                // Just validate without applying
                match plugin.validate(&ctx, plugin_config).await {
                    Ok(report) => {
                        validation_reports.push(report);
                    }
                    Err(e) => {
                        had_failure = true;
                        output::error(
                            &format,
                            &format!("Validation failed for {}: {}", metadata.plugin_name, e),
                        );
                    }
                }
            } else {
                match plugin.apply(&mut ctx, plugin_config).await {
                    Ok(result) => {
                        results.push((metadata, result));
                    }
                    Err(e) => {
                        had_failure = true;
                        output::error(
                            &format,
                            &format!("Failed to apply {}: {e}", metadata.plugin_name),
                        );
                    }
                }
            }
        } else {
            had_failure = true;
            output::error(
                &format,
                &format!("Plugin not found: {}", plugin_id.as_str()),
            );
        }
    }

    if results.iter().any(|(_, r)| !r.apply_success) {
        had_failure = true;
    }

    // Persistent audit log
    if let Some(logger) = ctx.audit_logger() {
        let user = super::state::effective_user();
        for (metadata, result) in &results {
            let action_result = if result.apply_success {
                ActionResult::Success
            } else {
                ActionResult::Failure
            };
            let _ = logger
                .log_action(
                    ActionType::Apply,
                    user.clone(),
                    metadata.plugin_name.clone(),
                    action_result,
                )
                .await;
        }
    }

    if dry_run {
        output::validation_reports(&format, &validation_reports);
    } else {
        output::apply_results(&format, &results);
    }

    if had_failure {
        bail!("One or more plugins failed to apply");
    }

    Ok(())
}
