use anyhow::Result;
use hardener_core::PluginRegistry;

use crate::cli::OutputFormat;
use crate::output;

pub async fn run(format: OutputFormat, _quiet: bool) -> Result<()> {
    let registry = create_plugin_registry();
    let plugins = registry.list()?;

    output::plugin_list(&format, &plugins);
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
