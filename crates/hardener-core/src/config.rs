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
    /// Policy exceptions for specific checks.
    pub exceptions: HashMap<String, PolicyException>,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            directives: HashMap::new(),
            exceptions: HashMap::new(),
        }
    }
}

impl PluginConfig {
    /// The target value for `key`: the operator's directive override if the
    /// config sets one, otherwise the plugin's built-in `baseline`.
    ///
    /// Scan, apply and dry-run each resolve every directive this way, so the
    /// three must agree on what the target is; nine hand-written copies of the
    /// same expression is an invitation for one of them to drift. Plain
    /// resolution only: pam's threshold directives additionally clamp so an
    /// override can tighten but never loosen, and that rule is deliberately not
    /// folded in here, because applying it to the string directives would
    /// silently change what an override means.
    pub fn resolve_str<'a>(&'a self, key: &str, baseline: &'a str) -> &'a str {
        self.directives
            .get(key)
            .map(|value| value.as_str())
            .unwrap_or(baseline)
    }

    /// The integer directive override for `key`, if the config sets a parseable
    /// one.
    ///
    /// Separate from [`resolve_str`](Self::resolve_str) because its callers do
    /// not fall back to a baseline here: they hand the `Option` to a clamp that
    /// decides whether the override may move the target at all. An unparseable
    /// value reads as no override, which leaves the plugin's own secure value
    /// standing rather than letting a typo relax a threshold.
    pub fn resolve_i64(&self, key: &str) -> Option<i64> {
        self.directives.get(key).and_then(|v| v.parse::<i64>().ok())
    }

    /// Returns a valid, non-expired exception for the given key, if one exists.
    pub fn has_valid_exception(&self, key: &str) -> Option<&PolicyException> {
        self.exceptions.get(key).filter(|e| e.is_valid())
    }

    /// Returns a valid, non-expired exception for `key` only when its documented
    /// `value` matches the value actually present on the system. An exception
    /// that does not describe the real deviation is not an exception.
    pub fn matching_exception(&self, key: &str, actual_value: &str) -> Option<&PolicyException> {
        self.has_valid_exception(key)
            .filter(|e| e.value == actual_value)
    }

    /// Octal-mode variant of [`matching_exception`](Self::matching_exception)
    /// for permission paths. A mode may be spelled with or without the leading
    /// zero ("644" and "0644" name the same mode), so both sides are compared
    /// numerically rather than as text. A value that is not a valid octal mode
    /// never matches.
    pub fn matching_mode_exception(&self, key: &str, actual_mode: u32) -> Option<&PolicyException> {
        self.has_valid_exception(key)
            .filter(|e| u32::from_str_radix(&e.value, 8).is_ok_and(|mode| mode == actual_mode))
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
    /// Whether a plugin should run, given the `[global]` lists and its own
    /// section's `enabled` key.
    ///
    /// Disabled anywhere is final. A plugin runs only when its own section
    /// leaves it enabled, the global deny list does not name it, and either the
    /// global allow list is empty or names it. `enabled` defaults to `true`, so
    /// it can only ever turn a plugin off: reading it as an override would let a
    /// config that never mentions the plugin defeat `disabled_plugins`.
    pub fn is_plugin_enabled(&self, plugin_id: &str) -> bool {
        if !self.get_plugin_config(plugin_id).enabled {
            return false;
        }

        if self.global.disabled_plugins.iter().any(|p| p == plugin_id) {
            return false;
        }

        // An empty allow list enables everything the two checks above left.
        self.global.enabled_plugins.is_empty()
            || self.global.enabled_plugins.iter().any(|p| p == plugin_id)
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

impl PolicyException {
    /// Builds the finding-facing exception record from this policy exception.
    /// Only valid (allowed, unexpired) exceptions are ever annotated onto a
    /// finding, so `exception_is_expired` is computed but expected to be false.
    pub fn to_finding_exception(&self) -> hardener_types::FindingPolicyException {
        hardener_types::FindingPolicyException {
            exception_allowed_value: self.value.clone(),
            exception_reason: self.reason.clone(),
            exception_approved_by: self.approved_by.clone(),
            exception_approved_date: self.approved_date.clone(),
            exception_ticket: self.ticket.clone(),
            exception_expires: self.expires.clone(),
            exception_is_expired: self.is_expired(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_exception_maps_to_finding_exception() {
        let ex = PolicyException {
            value: "yes".into(),
            allowed: true,
            reason: "legacy jump host".into(),
            approved_by: Some("Security Team".into()),
            approved_date: Some("2026-01-15".into()),
            ticket: Some("SEC-1234".into()),
            expires: None,
        };
        let fe = ex.to_finding_exception();
        assert_eq!(fe.exception_allowed_value, "yes");
        assert_eq!(fe.exception_reason, "legacy jump host");
        assert_eq!(fe.exception_ticket.as_deref(), Some("SEC-1234"));
        assert!(!fe.exception_is_expired); // no expiry -> not expired
    }

    /// Builds a valid exception allowing `value` for testing.
    fn exception(value: &str, expires: Option<&str>) -> PolicyException {
        PolicyException {
            value: value.into(),
            allowed: true,
            reason: "documented deviation".into(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: expires.map(str::to_string),
        }
    }

    fn plugin_with(key: &str, exception: PolicyException) -> PluginConfig {
        let mut plugin = PluginConfig::default();
        plugin.exceptions.insert(key.to_string(), exception);
        plugin
    }

    #[test]
    fn matching_exception_honours_only_the_documented_value() {
        let plugin = plugin_with("PermitRootLogin", exception("yes", None));

        // The exception describes the real deviation: honoured.
        assert!(
            plugin
                .matching_exception("PermitRootLogin", "yes")
                .is_some()
        );
        // The system deviates differently from what was approved: ignored.
        assert!(
            plugin
                .matching_exception("PermitRootLogin", "prohibit-password")
                .is_none()
        );
        // Unknown key: nothing to honour.
        assert!(plugin.matching_exception("X11Forwarding", "yes").is_none());
    }

    #[test]
    fn matching_exception_rejects_an_expired_exception() {
        let plugin = plugin_with("PermitRootLogin", exception("yes", Some("2020-01-01")));

        assert!(
            plugin
                .matching_exception("PermitRootLogin", "yes")
                .is_none()
        );
    }

    #[test]
    fn matching_mode_exception_normalises_octal_spelling() {
        let plugin = plugin_with("/etc/passwd", exception("644", None));

        // Written without the leading zero, but the same mode.
        assert!(
            plugin
                .matching_mode_exception("/etc/passwd", 0o644)
                .is_some()
        );
        // A different mode is not the approved deviation.
        assert!(
            plugin
                .matching_mode_exception("/etc/passwd", 0o600)
                .is_none()
        );

        // The four-digit spelling of the same mode also matches.
        let padded = plugin_with("/etc/passwd", exception("0644", None));
        assert!(
            padded
                .matching_mode_exception("/etc/passwd", 0o644)
                .is_some()
        );
        // A non-octal value can never describe a mode.
        let bogus = plugin_with("/etc/passwd", exception("rw-r--r--", None));
        assert!(
            bogus
                .matching_mode_exception("/etc/passwd", 0o644)
                .is_none()
        );
    }
}
