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
    skip_defaults: bool,
}

impl ConfigLoader {
    const SYSTEM_CONFIG_PATH: &'static str = "/etc/linux-hardener/config.toml";
    const ENV_DISABLED_PLUGINS: &'static str = "HARDENER_DISABLED_PLUGINS";
    const ENV_ENABLED_PLUGINS: &'static str = "HARDENER_ENABLED_PLUGINS";

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
        self.skip_defaults = true;
        self
    }

    /// Load configuration from all sources.
    ///
    /// Returns the merged configuration with later sources overriding earlier ones.
    pub fn load(&self) -> Result<HardenerConfig> {
        // 1. Start with defaults
        let mut config = HardenerConfig::default();

        if !self.skip_defaults {
            // 2. Load system config if it exists
            if let Some(path) = Self::system_config_path() {
                config = Self::merge_source(config, &path, false)?;
            }
            // 3. Load user config if it exists
            if let Some(path) = Self::user_config_path() {
                config = Self::merge_source(config, &path, false)?;
            }
        }

        // 4. Load CLI-specified config (required if specified)
        if let Some(path) = &self.cli_config_path {
            config = Self::merge_source(config, path, true)?;
        }

        // 5. Apply environment variable overrides
        let config = Self::apply_env_overrides(config);

        // 6. Validate all directive values before returning
        crate::config_validation::validate_config(&config)?;

        Ok(config)
    }

    /// Helper to merge a configuration source if it exists.
    ///
    /// If `required` is true, returns an error if the file is missing.
    fn merge_source(base: HardenerConfig, path: &Path, required: bool) -> Result<HardenerConfig> {
        if !path.exists() {
            if required {
                return Err(HardeningError::Config(format!(
                    "Config file not found: {}",
                    path.display()
                )));
            }
            return Ok(base);
        }

        let overlay = Self::load_from_file(path)?;
        Ok(Self::merge_configs(base, overlay))
    }

    /// Get the system config path.
    pub fn system_config_path() -> Option<PathBuf> {
        Some(PathBuf::from(Self::SYSTEM_CONFIG_PATH))
    }

    /// Get the user config path.
    pub fn user_config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|p| p.join("linux-hardener").join("config.toml"))
    }

    /// Maximum config file size (1 MiB). Prevents OOM from oversized files.
    const MAX_CONFIG_SIZE: u64 = 1_048_576;

    /// Load configuration from a TOML file.
    fn load_from_file(path: &Path) -> Result<HardenerConfig> {
        let metadata = std::fs::metadata(path).map_err(|e| {
            HardeningError::Config(format!(
                "Failed to stat config file {}: {}",
                path.display(),
                e
            ))
        })?;
        if metadata.len() > Self::MAX_CONFIG_SIZE {
            return Err(HardeningError::Config(format!(
                "Config file {} exceeds 1 MiB size limit ({} bytes)",
                path.display(),
                metadata.len()
            )));
        }

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
        if let Ok(disabled) = std::env::var(Self::ENV_DISABLED_PLUGINS) {
            config.global.disabled_plugins = Self::parse_env_list(&disabled);
        }
        if let Ok(enabled) = std::env::var(Self::ENV_ENABLED_PLUGINS) {
            config.global.enabled_plugins = Self::parse_env_list(&enabled);
        }
        config
    }

    fn parse_env_list(input: &str) -> Vec<String> {
        input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
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

    #[test]
    fn test_config_routing_end_to_end() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[services.exceptions.cups]
value = "running"
allowed = true
reason = "Print server required"
"#
        )
        .unwrap();

        let config = ConfigLoader::new()
            .skip_defaults()
            .with_cli_config(file.path().to_path_buf())
            .load()
            .unwrap();

        let plugin = config.get_plugin_config("service-minimisation");
        assert!(
            plugin.has_valid_exception("cups").is_some(),
            "Exception added under [services] must be reachable via service-minimisation ID"
        );
    }
}
