//! Shared host-inventory persistence.
//!
//! The list of saved remote hosts lives in `~/.config/linux-hardener/hosts.toml`.
//! Both the CLI (`batch`) and the Tauri GUI read and write it through this module
//! so there is a single source of truth for its location and format.

use hardener_common::error::{HardeningError, Result};
use hardener_types::remote::HostsConfig;
use std::path::{Path, PathBuf};

/// Returns the inventory file path, creating the parent directory if needed.
pub fn default_path() -> Result<PathBuf> {
    let dir = dirs::config_dir()
        .ok_or_else(|| HardeningError::Config("cannot determine config directory".into()))?
        .join("linux-hardener");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("hosts.toml"))
}

/// Loads the inventory from the default path. A missing file is an empty inventory.
pub fn load() -> Result<HostsConfig> {
    load_from(&default_path()?)
}

/// Saves the inventory to the default path.
pub fn save(config: &HostsConfig) -> Result<()> {
    save_to(&default_path()?, config)
}

fn load_from(path: &Path) -> Result<HostsConfig> {
    if !path.exists() {
        return Ok(HostsConfig::default());
    }
    let content = std::fs::read_to_string(path)?;
    toml::from_str(&content)
        .map_err(|e| HardeningError::Config(format!("failed to parse hosts config: {e}")))
}

fn save_to(path: &Path, config: &HostsConfig) -> Result<()> {
    let content = toml::to_string_pretty(config)
        .map_err(|e| HardeningError::Config(format!("failed to serialise hosts config: {e}")))?;
    std::fs::write(path, content)?;
    Ok(())
}

#[cfg(test)]
mod tests;
