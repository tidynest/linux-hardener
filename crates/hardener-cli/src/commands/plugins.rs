//! Plugins command: lists all registered hardening plugins.

use anyhow::Result;
use hardener_plugins::create_plugin_registry;

use crate::cli::OutputFormat;
use crate::output;

pub async fn run(format: OutputFormat, _quiet: bool) -> Result<()> {
    let registry = create_plugin_registry();
    let plugins = registry.list()?;

    output::plugin_list(&format, &plugins);
    Ok(())
}
