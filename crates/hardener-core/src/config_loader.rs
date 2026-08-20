//! Configuration loader for Linux Hardener.
//!
//! Loads configuration from multiple sources with the following precedence
//! (later sources override earlier ones):
//! 1. Built-in defaults
//! 2. System config (`/etc/linux-hardener/config.toml`)
//! 3. User config (`~/.config/linux-hardener/config.toml`)
//! 4. CLI-specified config (`--config` flag)
//! 5. Environment variables (`HARDENER_*` prefix)

use crate::config::scope::ComplianceConfig;
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
    /// Base directory the user config is looked up under.
    ///
    /// `None`, which is what every shipping caller leaves it as, resolves
    /// through [`dirs::config_dir`]. It exists because `dirs::config_dir`
    /// reads the environment and nothing else here can: without a seam, the
    /// two branches deciding whether user config is read at all had no
    /// observable difference on a test runner, since neither default location
    /// exists there. See [`Self::with_config_dir`].
    config_dir: Option<PathBuf>,
    /// Where the system config is read from.
    ///
    /// `None`, which every shipping caller leaves it as, resolves to
    /// [`Self::SYSTEM_CONFIG_PATH`]. It exists because that path is absolute
    /// and outside any directory a test may write: without a seam, `load`
    /// reads it in every test that does not call `skip_defaults`, but nothing
    /// observes what it read, since `/etc/linux-hardener/config.toml` does not
    /// exist on a developer machine or in CI. See [`Self::with_system_config`].
    system_config_path: Option<PathBuf>,
    /// Whether this process counts as root for the user-config rule.
    ///
    /// `None`, which every shipping caller leaves it as, asks the real
    /// effective UID. It exists because the suite runs unprivileged, so the
    /// real check answers `false` for every test and only the *reading* half
    /// of the rule could be asserted. The refusing half, the one that stops an
    /// unprivileged `~/.config` steering root hardening under `pkexec`, was
    /// inferred from the reading half rather than asked. See
    /// [`Self::with_running_as_root`].
    running_as_root: Option<bool>,
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

    /// Look the user config up under `dir` instead of [`dirs::config_dir`].
    ///
    /// The seam exists so the precedence rules can be asked at all. `load`
    /// decides twice whether to read user config, once on `skip_defaults` and
    /// once on whether the process is root, and both decisions were
    /// unobservable on a test runner: `~/.config/linux-hardener/config.toml`
    /// is absent there, so taking the branch and skipping it produced the same
    /// configuration. Pointing the lookup at a directory a test controls is
    /// what makes the difference visible, and it is the same shape of fix #155
    /// took for `stat`: pin the input rather than teach the parser about the
    /// environment.
    #[must_use]
    pub fn with_config_dir(mut self, dir: PathBuf) -> Self {
        self.config_dir = Some(dir);
        self
    }

    /// Read the system config from `path` rather than from
    /// [`Self::SYSTEM_CONFIG_PATH`].
    ///
    /// Test seam, in the manner of [`Self::with_config_dir`] and
    /// [`Self::with_running_as_root`]: every shipping caller leaves it unset.
    #[must_use]
    pub fn with_system_config(mut self, path: PathBuf) -> Self {
        self.system_config_path = Some(path);
        self
    }

    /// Answer the root check with `is_root` rather than the effective UID.
    ///
    /// The same shape of seam as [`Self::with_config_dir`], for the same
    /// reason: pin the input rather than teach the rule about its environment.
    /// A test runner is never root, so without this the rule could only ever
    /// be asked the question it already answers.
    ///
    /// This does not make `is_running_as_root` mutation-killable, and is not
    /// meant to. Replacing that function with `false` stays **provably
    /// equivalent** under an unprivileged runner, because the real one returns
    /// `false` there too. What this pins is the rule the function feeds, which
    /// is the part with security consequences.
    #[must_use]
    pub fn with_running_as_root(mut self, is_root: bool) -> Self {
        self.running_as_root = Some(is_root);
        self
    }

    /// The root answer this load should use: the override, or the real UID.
    fn running_as_root(&self) -> bool {
        self.running_as_root
            .unwrap_or_else(Self::is_running_as_root)
    }

    /// Load configuration from all sources.
    ///
    /// Returns the merged configuration with later sources overriding earlier ones.
    pub fn load(&self) -> Result<HardenerConfig> {
        // 1. Start with defaults
        let mut config = HardenerConfig::default();

        if !self.skip_defaults {
            // 2. Load system config if it exists
            if let Some(path) = self.system_config_path_for() {
                config = Self::merge_source(config, &path, false)?;
            }
            // 3. Load user config if it exists, skip when running as root
            //    (via pkexec) to prevent unprivileged user config from
            //    influencing root-level hardening operations.
            if !self.running_as_root()
                && let Some(path) = self.user_config_path_for()
            {
                config = Self::merge_source(config, &path, false)?;
            }
        }

        // 4. Load CLI-specified config (required if specified)
        if let Some(path) = &self.cli_config_path {
            config = Self::merge_source(config, path, true)?;
        }

        // 5. Apply environment variable overrides
        let config = Self::apply_env_overrides(config)?;

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
        Self::merge_configs(base, overlay)
    }

    /// Returns true when the process is running with effective UID 0.
    ///
    /// When `true`, user-level config (`~/.config/...`) is skipped to prevent
    /// unprivileged config from influencing root hardening operations via pkexec.
    fn is_running_as_root() -> bool {
        #[cfg(feature = "system")]
        {
            nix::unistd::geteuid().is_root()
        }
        #[cfg(not(feature = "system"))]
        {
            false
        }
    }

    /// Get the system config path.
    pub fn system_config_path() -> Option<PathBuf> {
        Some(PathBuf::from(Self::SYSTEM_CONFIG_PATH))
    }

    /// Get the user config path.
    pub fn user_config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|p| p.join("linux-hardener").join("config.toml"))
    }

    /// The user config path this loader reads, honouring
    /// [`with_config_dir`](Self::with_config_dir).
    fn user_config_path_for(&self) -> Option<PathBuf> {
        match &self.config_dir {
            Some(dir) => Some(dir.join("linux-hardener").join("config.toml")),
            None => Self::user_config_path(),
        }
    }

    /// The system config path this load should use: the override, or the real
    /// one.
    fn system_config_path_for(&self) -> Option<PathBuf> {
        self.system_config_path
            .clone()
            .or_else(Self::system_config_path)
    }

    /// Maximum config file size (1 MiB). Prevents OOM from oversized files.
    const MAX_CONFIG_SIZE: u64 = 1_048_576;

    /// Maximum directives per plugin section. Prevents DoS via config bloat.
    const MAX_DIRECTIVES_PER_PLUGIN: usize = 500;
    /// Maximum exceptions per plugin section.
    const MAX_EXCEPTIONS_PER_PLUGIN: usize = 200;
    /// Maximum exclusions per framework in `[compliance.not_applicable]`.
    ///
    /// The same guard `MAX_DIRECTIVES_PER_PLUGIN` gives a plugin section, and
    /// the same figure, because the sections are the same shape: an operator
    /// map merged across every source. Comfortably above the largest catalogue
    /// this tool renders, so it bounds config bloat without bounding any real
    /// declaration.
    const MAX_EXCLUSIONS_PER_FRAMEWORK: usize = 500;

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
    fn merge_configs(base: HardenerConfig, overlay: HardenerConfig) -> Result<HardenerConfig> {
        Ok(HardenerConfig {
            global: Self::merge_global(base.global, overlay.global),
            ssh: Self::merge_plugin(base.ssh, overlay.ssh)?,
            kernel: Self::merge_plugin(base.kernel, overlay.kernel)?,
            firewall: Self::merge_plugin(base.firewall, overlay.firewall)?,
            pam: Self::merge_plugin(base.pam, overlay.pam)?,
            audit: Self::merge_plugin(base.audit, overlay.audit)?,
            mac: Self::merge_plugin(base.mac, overlay.mac)?,
            permissions: Self::merge_plugin(base.permissions, overlay.permissions)?,
            services: Self::merge_plugin(base.services, overlay.services)?,
            compliance: Self::merge_compliance(base.compliance, overlay.compliance)?,
        })
    }

    /// Merge compliance configs, per control rather than per framework.
    ///
    /// A plain `extend` of the outer map would let a later source that excludes
    /// one control of a framework discard every other exclusion the earlier
    /// source declared for that same framework, silently returning those
    /// controls to the score.
    ///
    /// Size-limited like [`Self::merge_plugin`], and after the merge rather
    /// than per source, because the merge is where two sources within the cap
    /// can add up to one map beyond it.
    fn merge_compliance(
        base: ComplianceConfig,
        overlay: ComplianceConfig,
    ) -> Result<ComplianceConfig> {
        let mut not_applicable = base.not_applicable;
        for (framework, controls) in overlay.not_applicable {
            not_applicable
                .entry(framework)
                .or_default()
                .extend(controls);
        }

        for (framework, controls) in &not_applicable {
            if controls.len() > Self::MAX_EXCLUSIONS_PER_FRAMEWORK {
                return Err(HardeningError::Config(format!(
                    "Compliance config exceeds exclusion limit for '{}' ({} > {})",
                    framework,
                    controls.len(),
                    Self::MAX_EXCLUSIONS_PER_FRAMEWORK
                )));
            }
        }

        Ok(ComplianceConfig { not_applicable })
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

    /// Merge plugin configs, enforcing size limits.
    fn merge_plugin(base: PluginConfig, overlay: PluginConfig) -> Result<PluginConfig> {
        let mut directives = base.directives;
        directives.extend(overlay.directives);
        let mut exceptions = base.exceptions;
        exceptions.extend(overlay.exceptions);

        if directives.len() > Self::MAX_DIRECTIVES_PER_PLUGIN {
            return Err(HardeningError::Config(format!(
                "Plugin config exceeds directive limit ({} > {})",
                directives.len(),
                Self::MAX_DIRECTIVES_PER_PLUGIN
            )));
        }
        if exceptions.len() > Self::MAX_EXCEPTIONS_PER_PLUGIN {
            return Err(HardeningError::Config(format!(
                "Plugin config exceeds exception limit ({} > {})",
                exceptions.len(),
                Self::MAX_EXCEPTIONS_PER_PLUGIN,
            )));
        }

        Ok(PluginConfig {
            // `or`, not the overlay outright: a source that did not mention
            // the key has not decided it, so the earlier decision stands.
            enabled: overlay.enabled.or(base.enabled),
            directives,
            exceptions,
        })
    }

    /// Apply environment variable overrides.
    fn apply_env_overrides(mut config: HardenerConfig) -> Result<HardenerConfig> {
        if let Ok(disabled) = std::env::var(Self::ENV_DISABLED_PLUGINS) {
            config.global.disabled_plugins =
                Self::parse_and_validate_env_list(&disabled, Self::ENV_DISABLED_PLUGINS)?;
        }
        if let Ok(enabled) = std::env::var(Self::ENV_ENABLED_PLUGINS) {
            config.global.enabled_plugins =
                Self::parse_and_validate_env_list(&enabled, Self::ENV_ENABLED_PLUGINS)?;
        }
        Ok(config)
    }

    const KNOWN_PLUGIN_IDS: &'static [&'static str] = &[
        "audit-hardening",
        "firewall-hardening",
        "kernel-hardening",
        "mac-hardening",
        "pam-hardening",
        "permissions-hardening",
        "service-minimisation",
        "ssh-hardening",
    ];

    fn parse_and_validate_env_list(input: &str, var_name: &str) -> Result<Vec<String>> {
        let ids: Vec<String> = input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        for id in &ids {
            if !Self::KNOWN_PLUGIN_IDS.contains(&id.as_str()) {
                return Err(HardeningError::Config(format!(
                    "Unknown plugin ID '{id}' in {var_name}"
                )));
            }
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests;
