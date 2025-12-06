//! Configuration loader for Linux System Hardener.
//!
//! Loads configuration from multiple sources with the following precedence
//! (later sources override earlier ones):
//! 1. Built-in defaults
//! 2. System config (`/etc/linux-hardener/config.toml`)
//! 3. User config (`~/.config/linux-hardener/config.toml`)
//! 4. CLI-specified config (`--config` flag)
//! 5. Environment variables (`HARDENER_*` prefix)

use crate::config::{GlobalConfig, HardenerConfig, PluginConfig};
use hardener_common::error::{HardeningError, Result};
use std::path::{Path, PathBuf};

/// Configuration loader with support for multiple sources.
#[derive(Debug, Default)]
pub struct ConfigLoader {
    /// Optional CLI-specified config path.
    cli_config_path: Option<PathBuf>,
    /// Skip loading from default locations (for testing).
    skip_default_locations: bool,
}

impl ConfigLoader {
    /// Create a new ConfigLoader.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a CLI-specified config file path.
    #[must_use]
    pub fn with_cli_config(mut self, path: PathBuf) -> Self {
        self.cli_config_path = Some(path);
        self
    }

    /// Skip loading from default locations (useful for testing).
    #[must_use]
    pub fn skip_defaults(mut self) -> Self {
        self.skip_default_locations = true;
        self
    }

    /// Load configuration from all sources.
    ///
    /// Returns the merged configuration with later sources overriding earlier ones.
    pub fn load(&self) -> Result<HardenerConfig> {
        // Start with defaults
        let mut config = HardenerConfig::default();

        if !self.skip_default_locations {
            // Load system config if it exists
            if let Some(system_path) = Self::system_config_path()
                && system_path.exists()
            {
                let system_config = Self::load_from_file(&system_path)?;
                config = Self::merge_configs(config, system_config);
            }

            // Load user config if it exists
            if let Some(user_path) = Self::user_config_path()
                && user_path.exists()
            {
                let user_config = Self::load_from_file(&user_path)?;
                config = Self::merge_configs(config, user_config);
            }
        }

        // Load CLI-specified config (required if specified)
        if let Some(cli_path) = &self.cli_config_path {
            if !cli_path.exists() {
                return Err(HardeningError::Config(format!(
                    "Config file not found: {}",
                    cli_path.display()
                )));
            }
            let cli_config = Self::load_from_file(cli_path)?;
            config = Self::merge_configs(config, cli_config);
        }

        // Apply environment variable overrides
        config = Self::apply_env_overrides(config);

        Ok(config)
    }

    /// Get the system config path.
    pub fn system_config_path() -> Option<PathBuf> {
        Some(PathBuf::from("/etc/linux-hardener/config.toml"))
    }

    /// Get the user config path.
    pub fn user_config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|p| p.join("linux-hardener").join("config.toml"))
    }

    /// Load configuration from a TOML file.
    fn load_from_file(path: &Path) -> Result<HardenerConfig> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            HardeningError::Config(format!(
                "Failed to read config file {}: {}",
                path.display(),
                e
            ))
        })?;

        toml::from_str(&content).map_err(|e| {
            HardeningError::Config(format!(
                "Failed to parse config file {}: {}",
                path.display(),
                e
            ))
        })
    }

    /// Merge two configs, with `overlay` taking precedence.
    fn merge_configs(base: HardenerConfig, overlay: HardenerConfig) -> HardenerConfig {
        HardenerConfig {
            global: Self::merge_global(base.global, overlay.global),
            ssh: Self::merge_plugin(base.ssh, overlay.ssh),
            kernel: Self::merge_plugin(base.kernel, overlay.kernel),
            firewall: Self::merge_plugin(base.firewall, overlay.firewall),
            pam: Self::merge_plugin(base.pam, overlay.pam),
            audit: Self::merge_plugin(base.audit, overlay.audit),
            mac: Self::merge_plugin(base.mac, overlay.mac),
            permissions: Self::merge_plugin(base.permissions, overlay.permissions),
            services: Self::merge_plugin(base.services, overlay.services),
        }
    }

    /// Merge global configs.
    fn merge_global(base: GlobalConfig, overlay: GlobalConfig) -> GlobalConfig {
        GlobalConfig {
            // For lists, overlay replaces base if non-empty
            enabled_plugins: if overlay.enabled_plugins.is_empty() {
                base.enabled_plugins
            } else {
                overlay.enabled_plugins
            },
            disabled_plugins: if overlay.disabled_plugins.is_empty() {
                base.disabled_plugins
            } else {
                overlay.disabled_plugins
            },
        }
    }

    /// Merge plugin configs.
    fn merge_plugin(base: PluginConfig, overlay: PluginConfig) -> PluginConfig {
        let mut directives = base.directives;
        directives.extend(overlay.directives);

        let mut custom_directives = base.custom_directives;
        custom_directives.extend(overlay.custom_directives);

        let mut exceptions = base.exceptions;
        exceptions.extend(overlay.exceptions);

        PluginConfig {
            enabled: overlay.enabled,
            directives,
            custom_directives,
            exceptions,
        }
    }

    /// Apply environment variable overrides.
    fn apply_env_overrides(mut config: HardenerConfig) -> HardenerConfig {
        // HARDENER_DISABLED_PLUGINS=ssh-hardening,kernel-hardening
        if let Ok(disabled) = std::env::var("HARDENER_DISABLED_PLUGINS") {
            config.global.disabled_plugins = disabled
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        // HARDENER_ENABLED_PLUGINS=ssh-hardening
        if let Ok(enabled) = std::env::var("HARDENER_ENABLED_PLUGINS") {
            config.global.enabled_plugins = enabled
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let loader = ConfigLoader::new().skip_defaults();
        let config = loader.load().unwrap();
        assert!(config.global.enabled_plugins.is_empty());
        assert!(config.ssh.enabled);
    }

    #[test]
    fn test_load_from_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
  [global]
  disabled_plugins = ["mac-hardening"]

  [ssh]
  enabled = true
  "#
        )
        .unwrap();

        let loader = ConfigLoader::new()
            .skip_defaults()
            .with_cli_config(file.path().to_path_buf());

        let config = loader.load().unwrap();
        assert_eq!(
            config.global.disabled_plugins,
            vec!["mac-hardening".to_string()]
        );
        assert!(config.ssh.enabled);
    }

    #[test]
    fn test_missing_cli_config_error() {
        let loader = ConfigLoader::new()
            .skip_defaults()
            .with_cli_config(PathBuf::from("/nonexistent/config.toml"));

        let result = loader.load();
        assert!(result.is_err());
    }

    #[test]
    fn test_merge_configs() {
        let base = HardenerConfig::default();
        let mut overlay = HardenerConfig::default();
        overlay.global.disabled_plugins = vec!["ssh-hardening".to_string()];
        overlay.ssh.enabled = false;

        let merged = ConfigLoader::merge_configs(base, overlay);
        assert_eq!(
            merged.global.disabled_plugins,
            vec!["ssh-hardening".to_string()]
        );
        assert!(!merged.ssh.enabled);
    }

    #[test]
    fn test_merge_directives() {
        let mut base = HardenerConfig::default();
        base.ssh
            .directives
            .insert("MaxAuthTries".to_string(), "3".to_string());

        let mut overlay = HardenerConfig::default();
        overlay
            .ssh
            .directives
            .insert("PermitRootLogin".to_string(), "no".to_string());

        let merged = ConfigLoader::merge_configs(base, overlay);
        assert_eq!(merged.ssh.directives.get("MaxAuthTries").unwrap(), "3");
        assert_eq!(merged.ssh.directives.get("PermitRootLogin").unwrap(), "no");
    }

    #[test]
    fn test_user_config_path() {
        let path = ConfigLoader::user_config_path();
        assert!(path.is_some());
        let path = path.unwrap();
        assert!(path.to_string_lossy().contains("linux-hardener"));
    }

    #[test]
    fn test_system_config_path() {
        let path = ConfigLoader::system_config_path();
        assert!(path.is_some());
        assert_eq!(
            path.unwrap(),
            PathBuf::from("/etc/linux-hardener/config.toml")
        );
    }
}
