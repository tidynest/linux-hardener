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

/// Saves the inventory to the default path, recording the change.
///
/// Every caller is a desktop command that adds or removes a host, and a host
/// leaving this file stops being scanned without anything else reporting it.
/// The audit descriptor is therefore mandatory rather than optional, on the
/// same reasoning as [`crate::config_write::write_atomically`], which this
/// delegates to and which is also what makes the write atomic.
///
/// Behind `system` because the audit log and the effective user are, and a
/// `default-features = false` build has neither. That build reads the inventory
/// and does not write it.
#[cfg(feature = "system")]
pub async fn save_audited(
    config: &HostsConfig,
    audit: crate::config_write::WriteAudit<'_>,
) -> Result<()> {
    let content = serialise(config)?;
    crate::config_write::write_atomically(&default_path()?, &content, audit)
        .await
        .map_err(|e| HardeningError::Config(format!("{e:#}")))
}

/// The inventory as TOML, or the serialisation error naming what failed.
///
/// Separate from the write so both the audited path and the round-trip test can
/// use it, and so a serialisation failure is distinguishable from a write
/// failure: the first never touches the file, the second may leave a temporary
/// one behind.
fn serialise(config: &HostsConfig) -> Result<String> {
    toml::to_string_pretty(config)
        .map_err(|e| HardeningError::Config(format!("failed to serialise hosts config: {e}")))
}

fn load_from(path: &Path) -> Result<HostsConfig> {
    if !path.exists() {
        return Ok(HostsConfig::default());
    }
    let content = std::fs::read_to_string(path)?;
    toml::from_str(&content)
        .map_err(|e| HardeningError::Config(format!("failed to parse hosts config: {e}")))
}

// `save_to` used to sit here, writing an arbitrary path with `std::fs::write`.
// It went when `save_audited` started delegating to
// `crate::config_write::write_atomically`, which does the writing and files the
// entry. Nothing but the round-trip test below called it, and that asserts what
// it was really for: that `serialise` and `load_from` agree.

#[cfg(test)]
mod tests;
