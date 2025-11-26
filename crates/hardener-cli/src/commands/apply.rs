use anyhow::{bail, Result};
use hardener_common::types::PluginId;
use hardener_core::{Config, Context, PluginRegistry};

use crate::cli::OutputFormat;
use crate::output;

pub async fn run(
    plugin_filter: &[String],
    all: bool,
    dry_run: bool,
    format: OutputFormat,
    quiet: bool,
) -> Result<()> {
    // Must be root to apply changes
    if !nix::unistd::geteuid().is_root() && !dry_run {
        bail!("Root privileges required to apply hardening changes. Use sudo or --dry-run.");
    }

    if plugin_filter.is_empty() && !all {
        bail!("Specify plugins with --plugin or use --all to apply all plugins.");
    }

    let registry = create_plugin_registry();
    let mut ctx = Context::new();
    let config = Config::default();

    let plugins = registry.list()?;
    let plugin_ids: Vec<PluginId> = if all {
        plugins.iter().map(|m| m.plugin_id.clone()).collect()
    } else {
        plugin_filter.iter().map(|s| PluginId::new(s)).collect()
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
                match plugin.validate(&config) {
                    Ok(report) => {
                        output::validation_report(&format, &metadata, &report);
                    }
                    Err(e) => {
                        output::error(
                            &format,
                            &format!("Validation failed for {}: {}", metadata.plugin_name, e
                            ));
                    }
                }
            } else {
                match plugin.apply(&mut ctx, &config) {
                    Ok(result) => {
                        results.push((metadata, result));
                    }
                    Err(e) => {
                        output::error(
                            &format,
                            &format!("Failed to apply {}: {e}", metadata.plugin_name
                            ));
                    }
                }
            }
        } else {
            output::error(&format, &format!("Plugin not found: {}", plugin_id.as_str()));
        }
    }

    if !dry_run {
        output::apply_results(&format, &results);
    }

    Ok(())
}

fn create_plugin_registry() -> PluginRegistry {
    use hardener_plugins::*;

    let registry = PluginRegistry::new();
    let _ = registry.register(Box::new(AuditHardeningPlugin::new()));
    let _ = registry.register(Box::new(FirewallHardeningPlugin::new()));
    let _ = registry.register(Box::new(KernelHardeningPlugin::new()));
    let _ = registry.register(Box::new(MacHardeningPlugin::new()));
    let _ = registry.register(Box::new(PamHardeningPlugin::new()));
    let _ = registry.register(Box::new(PermissionsHardeningPlugin::new()));
    let _ = registry.register(Box::new(ServicesHardeningPlugin::new()));
    let _ = registry.register(Box::new(SshHardeningPlugin::new()));
    registry
}
