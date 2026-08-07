//! Configuration system for Linux Hardener
//!
//! This module provides the configuration structures that control plugin behaviour
//! and policy exceptions. Configuration annotates findings; it never hides them.

use hardener_types::{DeclineReason, ExceptionOutcome, FindingExceptionDeclined};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::LazyLock;
use tracing::warn;

/// Root configuration structure for Linux Hardener.
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
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct PluginConfig {
    /// Whether this plugin is enabled, when the source said so.
    ///
    /// `None` means the file did not mention it, which is not the same as
    /// mentioning it as `true`. While this was a `bool` defaulting to `true`,
    /// the two were indistinguishable, so a later source that named a section
    /// for any reason at all supplied `enabled = true` for it and revived a
    /// plugin an earlier source had turned off. Read it through
    /// [`is_enabled`](Self::is_enabled) rather than directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Stricter directive values (beyond baseline).
    pub directives: HashMap<String, String>,
    /// Policy exceptions for specific checks.
    pub exceptions: HashMap<String, PolicyException>,
}

impl PluginConfig {
    /// Whether this plugin runs, as far as this section alone decides.
    ///
    /// A section that said nothing about it runs, which is the behaviour that
    /// shipped and the reason the key defaults the way it does. The `[global]`
    /// lists are consulted separately, by
    /// [`HardenerConfig::is_plugin_enabled`], and can still refuse a plugin
    /// this answers `true` for.
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
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

    /// What the configuration has to say about `key`, given the value actually
    /// read from the host.
    ///
    /// The single place that decides what a scan reports. The apply path keeps
    /// its own three lookups, and they are deliberately not expressed in terms
    /// of this one: `has_valid_exception` and its two callers hand back
    /// `Option<&PolicyException>`, a borrow into the config, while this returns
    /// an owned outcome carrying a converted `FindingPolicyException`. The
    /// borrow cannot be recovered from the owned value, so unifying them would
    /// mean changing the apply path's public signatures, which this slice does
    /// not do.
    ///
    /// What that leaves is one real duplication, recorded here rather than left
    /// to be discovered: `PolicyException::is_valid` is `allowed && !expired`,
    /// and this method takes those two apart, because they need opposite
    /// answers. `allowed = false` is an operator declining to except something
    /// and reports nothing; an expiry is an exception that used to work and
    /// silently stopped, which is the whole reason this method exists. Anyone
    /// changing what "valid" means must change both.
    pub fn exception_outcome(&self, key: &str, observed: &str) -> ExceptionOutcome {
        self.exception_outcome_with(key, Some(observed))
    }

    /// What the configuration has to say about `key` for a check that is
    /// present or absent, with no host value to compare.
    ///
    /// Can never return [`DeclineReason::ValueMismatch`]. For `[services]`,
    /// `[mac]`, `[audit]` and `[firewall]` the exception key already names the
    /// deviating item and the exception's own `value` is advisory, which
    /// [`EXCEPTION_OBSERVED_UNCHANGED`] documents from the other side. Only
    /// expiry can decline one of these.
    pub fn exception_outcome_for_presence(&self, key: &str) -> ExceptionOutcome {
        self.exception_outcome_with(key, None)
    }

    /// Shared body. `observed` is `None` for a presence check, which is the
    /// only thing that can suppress a value mismatch.
    ///
    /// The `Option` lives here and not on the public surface deliberately: a
    /// caller passing `None` to a method named `exception_outcome` would be
    /// switching off one of three outcomes through a parameter, which is the
    /// same one-value-several-meanings problem this whole type exists to
    /// remove. Two named public methods say which question is being asked.
    ///
    /// Expiry is checked before the value, so an exception that is both
    /// expired and mismatched reports the expiry. That ordering is deliberate:
    /// the expiry is the reason it stopped applying, and correcting the value
    /// would not bring it back.
    fn exception_outcome_with(&self, key: &str, observed: Option<&str>) -> ExceptionOutcome {
        let Some(exception) = self.exceptions.get(key) else {
            return ExceptionOutcome::NotConfigured;
        };
        if !exception.allowed {
            return ExceptionOutcome::NotConfigured;
        }
        let declined = |reason| {
            ExceptionOutcome::Declined(FindingExceptionDeclined {
                exception_declined_reason: reason,
                exception_reason: exception.reason.clone(),
            })
        };
        if exception.is_expired() {
            return declined(DeclineReason::Expired {
                expired_on: exception.expires.clone().unwrap_or_default(),
            });
        }
        if let Some(observed) = observed
            && exception.value != observed
        {
            return declined(DeclineReason::ValueMismatch {
                documented: exception.value.clone(),
                observed: observed.to_string(),
            });
        }
        ExceptionOutcome::Applied(exception.to_finding_exception())
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
        if !self.get_plugin_config(plugin_id).is_enabled() {
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

    /// The `config.toml` section a plugin's directives and exceptions live
    /// under, which is not its plugin id: the services plugin declares
    /// `service-minimisation` and is configured under `[services]`.
    ///
    /// A plugin cannot answer this about itself, because `scan` and `apply`
    /// receive a bare [`PluginConfig`] with nothing on it naming the section
    /// it was taken from. Anything telling an operator where to write an
    /// exception has to ask here.
    ///
    /// `None` for an unrecognised id, matching
    /// [`get_plugin_config`](Self::get_plugin_config), which has no section to
    /// return one either. A caller then says nothing rather than naming a
    /// table that nothing reads.
    pub fn config_section(plugin_id: &str) -> Option<&'static str> {
        match plugin_id {
            "ssh-hardening" => Some("ssh"),
            "kernel-hardening" => Some("kernel"),
            "firewall-hardening" => Some("firewall"),
            "pam-hardening" => Some("pam"),
            "audit-hardening" => Some("audit"),
            "mac-hardening" => Some("mac"),
            "permissions-hardening" => Some("permissions"),
            "service-minimisation" => Some("services"),
            _ => None,
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
mod tests;
