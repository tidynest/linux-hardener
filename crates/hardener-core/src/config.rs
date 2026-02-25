//! Configuration system for Linux System Hardener
//!
//! This module provides the configuration structures that control plugin behaviour
//! and policy exceptions. Configuration annotates findings; it never hides them.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::LazyLock;
use tracing::warn;

/// Root configuration structure for Linux System Hardener.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct HardenerConfig {
    /// Global settings affecting all plugins.
    pub global: GlobalConfig,
    /// SSH hardening plugin configuration.
    pub ssh: PluginConfig,
    /// Kernel hardening plugin configuration.
    pub kernel: PluginConfig,
    /// Firewall hardening plugin configuration.
    pub firewall: PluginConfig,
    /// PAM hardening plugin configuration.
    pub pam: PluginConfig,
    /// Audit hardening plugin configuration.
    pub audit: PluginConfig,
    /// MAC (SELinux/AppArmor) hardening plugin configuration.
    pub mac: PluginConfig,
    /// Permissions hardening plugin configuration.
    pub permissions: PluginConfig,
    /// Services hardening plugin configuration.
    pub services: PluginConfig,
}

/// Global configuration settings.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct GlobalConfig {
    /// Plugins to enable (empty means all enabled).
    pub enabled_plugins: Vec<String>,
    /// Plugins to explicitly disable (takes precedence over enabled_plugins).
    pub disabled_plugins: Vec<String>,
}

/// Configuration for an individual plugin.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct PluginConfig {
    /// Whether this plugin is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Stricter directive values (beyond baseline).
    pub directives: HashMap<String, String>,
    /// Additional custom directives to check.
    pub custom_directives: HashMap<String, String>,
    /// Policy exceptions for specific checks.
    pub exceptions: HashMap<String, PolicyException>,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            directives: HashMap::new(),
            custom_directives: HashMap::new(),
            exceptions: HashMap::new(),
        }
    }
}

impl PluginConfig {
    /// Returns a valid, non-expired exception for the given key, if one exists.
    pub fn has_valid_exception(&self, key: &str) -> Option<&PolicyException> {
        self.exceptions.get(key).filter(|e| e.is_valid())
    }
}

/// A policy exception that allows a value deviating from secure baseline.
///
/// Policy exceptions provide an audit trail for intentional deviations
/// from security best practices.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PolicyException {
    /// The value being allowed (must match current system value).
    pub value: String,
    /// Explicit acknowledgment (must be true for exception to be valid).
    pub allowed: bool,
    /// Human-readable justification for the exception.
    pub reason: String,
    /// Who approved this exception.
    pub approved_by: Option<String>,
    /// When this exception was approved (ISO 8601 date).
    pub approved_date: Option<String>,
    /// Reference to approval ticket/issue.
    pub ticket: Option<String>,
    /// When this exception expires (ISO 8601 date).
    pub expires: Option<String>,
}

fn default_true() -> bool {
    true
}

impl HardenerConfig {
    /// Check if a plugin is enabled based on global and plugin-specific settings
    pub fn is_plugin_enabled(&self, plugin_id: &str) -> bool {
        if self
            .global
            .disabled_plugins
            .contains(&plugin_id.to_string())
        {
            return false;
        }

        // If enabled_plugin is empty, all plugins are enabled by default
        if self.global.enabled_plugins.is_empty() {
            return true;
        }

        // Otherwise, check if plugin is in enabled list.
        self.global.enabled_plugins.contains(&plugin_id.to_string())
    }

    /// Get plugin-specific configuration by plugin ID.
    pub fn get_plugin_config(&self, plugin_id: &str) -> &PluginConfig {
        static EMPTY: LazyLock<PluginConfig> = LazyLock::new(PluginConfig::default);

        match plugin_id {
            "ssh-hardening" => &self.ssh,
            "kernel-hardening" => &self.kernel,
            "firewall-hardening" => &self.firewall,
            "pam-hardening" => &self.pam,
            "audit-hardening" => &self.audit,
            "mac-hardening" => &self.mac,
            "permissions-hardening" => &self.permissions,
            "service-minimisation" => &self.services,
            _ => {
                warn!("Unknown plugin ID '{plugin_id}', returning empty config");
                &EMPTY
            }
        }
    }
}

impl PolicyException {
    /// Check if this exception has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = &self.expires
            && let Ok(expiry_date) = chrono::NaiveDate::parse_from_str(expires, "%Y-%m-%d")
        {
            let today = chrono::Local::now().date_naive();
            return today > expiry_date;
        }
        false
    }

    /// Check if this exception is valid (allowed=true and not expired).
    pub fn is_valid(&self) -> bool {
        self.allowed && !self.is_expired()
    }
}
