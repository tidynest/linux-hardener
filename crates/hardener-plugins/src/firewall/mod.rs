//! Firewall hardening plugin supporting multiple firewall backends.
//!
//! This plugin provides unified firewall management across different Linux
//! firewall systems including nftables, firewalld, and ufw.
//!
//! The plugin automatically detects which firewall backend is available on
//! the system and uses the appropriate implementation.

mod ufw;

use hardener_common::{
    error::Result,
    types::{
        FindingCategory,
        PluginId,
        Severity,
    },
};
use hardener_core::{
    context::Context,
    plugin::{
        Finding,
        HardeningPlugin,
        PluginMetadata,
        ScanResult,
    },
    ApplyResult,
    Change,
    ChangeType,
    Checkpoint,
    Config,
    ValidationIssue,
    ValidationReport,
};
use std::time::Instant;

/// Represents a single firewall rule in a backend-agnostic format.
#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    /// Rule description for logging and display.
    pub rule_description: String,
    /// Protocol (tcp, udp, icmp, all).
    pub rule_protocol: String,
    /// Port or port range (e.g., "22", "80:443", "any").
    pub rule_port: String,
    /// Source address (CIDR notation or "any").
    pub rule_source: String,
    /// Action to take (accept, drop, reject).
    pub rule_action: String,
}

/// Trait for firewall backend implementations.
///
/// Each firewall system (nftables, firewalld, ufw) implements this trait
/// to provide unified firewall management.
pub trait FirewallBackend: Send + Sync {
    /// Returns the name of this backend (e.g., "nftables", "firewalld", "ufw").
    fn backend_name(&self) -> &str;

    /// Detects if this backend is available on the system.
    ///
    /// This typically checks if the backend's command-line tool exists and is executable.
    fn detect(&self) -> Result<bool>;

    /// Checks if the firewall is currently enabled and running.
    fn is_enabled(&self) -> Result<()>;

    /// Enables and starts the firewall service.
    fn enable(&self) -> Result<()>;

    /// Lists current firewall rules in a backend-agnostic format.
    ///
    /// This converts the backend's rule format into the unified Rule structure.
    fn list_rules(&self) -> Result<Vec<Rule>>;

    /// Applies a set of firewall rules.
    ///
    /// # Arguments
    /// * `rules` - The rules to apply in a backend-agnostic format.
    ///
    /// # Returns
    /// A list of changes made, or an error if application fails.
    fn apply_rules(
        &self,
        rules: &[Rule]
    ) -> Result<Vec<Change>>;

    /// Returns the recommended baseline firewall rules.
    ///
    /// These are sensible defaults that work across most systems:
    /// - Allow established/related connections
    /// - Allow loopback
    /// - Allow SSH (port 22)
    /// - Drop all other inbound by default.
    fn get_default_rules(&self) -> Vec<Rule>;
}

/// Returns sensible default firewall rules for hardening.
///
/// These rules provide a secure baseline:
/// - Allow loopback traffic (localhost communication)
/// - Allow established and related connections (don't break existing sessions)
/// - Allow SSH (port 22) to prevent lockout
/// - Drop all other inbound traffic by default.
pub fn get_baseline_rules() -> Vec<Rule> {
    vec![
        Rule {
            rule_description: "Allow loopback traffic".to_string(),
            rule_protocol:    "all".to_string(),
            rule_port:        "any".to_string(),
            rule_source:      "127.0.0.1/8".to_string(),
            rule_action:      "accept".to_string(),
        },
        Rule {
            rule_description: "Allow established and related connections".to_string(),
            rule_protocol:    "all".to_string(),
            rule_port:        "any".to_string(),
            rule_source:      "any".to_string(),
            rule_action:      "accept".to_string(),
        },
        Rule {
            rule_description: "Allow SSH to prevent lockout".to_string(),
            rule_protocol:    "tcp".to_string(),
            rule_port:        "22".to_string(),
            rule_source:      "any".to_string(),
            rule_action:      "accept".to_string(),
        },
        Rule {
            rule_description: "Drop all other inbound traffic by default".to_string(),
            rule_protocol:    "all".to_string(),
            rule_port:        "any".to_string(),
            rule_source:      "any".to_string(),
            rule_action:      "drop".to_string(),
        },
    ]
}

/// Main firewall hardening plugin
///
/// This plugin automatically detects and uses the appropriate firewall
/// backend for the system (nftables, firewalld, or ufw).
pub struct FirewallPlugin {
    backend: Option<Box<dyn FirewallBackend>>,
}

impl FirewallPlugin {
    /// Create a new firewall plugin instance.
    ///
    /// The backend is detected lazily during the first operation.
    pub fn new() -> FirewallPlugin {
        FirewallPlugin { backend: None }
    }

    /// Detects and returns the appropriate firewall backend for this system.
    ///
    /// Detection order:
    /// 1. firewalld (RHEL/Fedora/CentOS)
    /// 2. ufw (Ubuntu/Debian)
    /// 3. nftables (modern systems, direct control)
    ///
    /// # Returns
    /// A boxed backend implementation, or an error if no backend is available.
    fn detect_backend(&self) -> Result<Box<dyn FirewallBackend>> {
        Err(hardener_common::error::HardeningError::Plugin(
            "Firewall backend detection not yet implemented".to_string(),
        ))
    }

    /// Gets or detects the firewall backend.
    fn get_backend(&mut self) -> Result<&dyn FirewallBackend> {
        if self.backend.is_none() {
            self.backend = Some(self.detect_backend()?);
        }
        Ok(self.backend.as_ref().unwrap().as_ref())
    }
}

impl HardeningPlugin for FirewallPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            id:          PluginId::new("firewall-hardening"),
            name:        "Firewall Hardening".to_string(),
            version:     "0.1.0".to_string(),
            description: "Manages firewall configuration across nftables, firewalld, and ufw".to_string(),
            category:    FindingCategory::Network,
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        // Firewall hardening has no dependencies
        vec![]
    }

    fn scan(
        &self,
        _ctx: &Context
    ) -> Result<ScanResult> {
        let start_time = Instant::now();
        let plugin_id  = PluginId::new("firewall-hardening");

        // Stub implementation
        tracing::warn!("Firewall scan() method has not yet been implemented");

        let duration_us = start_time.elapsed().as_micros() as u64;
        Ok(ScanResult {
            plugin_id,
            success:   true,
            findings:  vec![],
            duration_us,
            error:     None,
        })
    }

    fn apply(
        &self,
        _ctx: &mut Context,
        _config: &Config
    ) -> Result<ApplyResult> {
        let plugin_id  = PluginId::new("firewall-hardening");

        // Stub implementation
        tracing::warn!("Firewall apply() method has not yet been implemented");

        Ok(ApplyResult {
            plugin_id,
            success:       false,
            changes:       vec![],
            checkpoint_id: None,
            error:         Some("Not yet implemented".to_string()),
        })
    }

    fn rollback(
        &self,
        _ctx: &mut Context,
        _checkpoint: &Checkpoint
    ) -> Result<()> {
        // Stub implementation - will be completed during checkpoint integration
        tracing::warn!("Firewall rollback() method not yet fully implemented");
        Ok(())
    }

    fn validate(
        &self,
        _config: &Config
    ) -> Result<ValidationReport> {
        let plugin_id = PluginId::new("firewall-hardening");

        // Stub implementation - will be completed after backends are implemented
        tracing::warn!("Firewall validate() method not yet fully implemented");

        Ok(ValidationReport {
            plugin_id,
            valid: true,
            issues: vec![],
            estimated_changes: vec![],
        })
    }
}
