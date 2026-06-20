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
mod tests {
    use super::*;
    use hardener_types::remote::RemoteHostProfile;

    fn sample() -> HostsConfig {
        HostsConfig {
            hosts: vec![RemoteHostProfile {
                name: "web-01".into(),
                hostname: "web-01.example.com".into(),
                user: Some("admin".into()),
                port: 22,
                key_file: None,
                host_key_checking: true,
            }],
        }
    }

    #[test]
    fn missing_file_is_empty_inventory() {
        let path = std::env::temp_dir().join("hardener-test-missing-hosts.toml");
        let _ = std::fs::remove_file(&path);
        let config = load_from(&path).expect("load missing");
        assert!(config.hosts.is_empty());
    }

    #[test]
    fn save_then_load_round_trips() {
        let path = std::env::temp_dir().join("hardener-test-roundtrip-hosts.toml");
        save_to(&path, &sample()).expect("save");
        let loaded = load_from(&path).expect("load");
        let _ = std::fs::remove_file(&path);
        assert_eq!(loaded.hosts.len(), 1);
        assert_eq!(loaded.hosts[0].name, "web-01");
        assert_eq!(loaded.hosts[0].user.as_deref(), Some("admin"));
    }
}
