//! Firewall hardening plugin supporting multiple firewall backends.
//!
//! This plugin provides unified firewall management across different Linux
//! firewall systems including nftables, firewalld, and ufw.
//!
//! The plugin automatically detects which firewall backend is available on
//! the system and uses the appropriate implementation.

pub mod firewalld;
pub mod nftables;
pub mod ufw;

use async_trait::async_trait;
use hardener_common::{
    error::Result,
    types::{ComplianceFramework, ComplianceMapping, FindingCategory, PluginId, Severity},
};
use hardener_core::{
    ApplyResult, Change, ChangeType, Checkpoint, Config, ValidationReport,
    context::Context,
    plugin::{Finding, HardeningPlugin, PluginMetadata, ScanResult},
};
use std::time::Instant;
use tracing::{info, warn};

/// Represents a single firewall rule in a backend-agnostic format.
#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    /// Rule finding_description for logging and display.
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
#[async_trait]
pub trait FirewallBackend: Send + Sync {
    /// Returns the name of this backend (e.g., "nftables", "firewalld", "ufw").
    fn backend_name(&self) -> &str;

    /// Detects if this backend is available on the system.
    ///
    /// This typically checks if the backend's command-line tool exists and is executable.
    async fn detect(&self, ctx: &Context) -> Result<bool>;

    /// Checks if the firewall is currently enabled and running.
    async fn is_enabled(&self, ctx: &Context) -> Result<()>;

    /// Enables and starts the firewall service.
    async fn enable(&self, ctx: &Context) -> Result<()>;

    /// Lists current firewall rules in a backend-agnostic format.
    ///
    /// This converts the backend's rule format into the unified Rule structure.
    async fn list_rules(&self, ctx: &Context) -> Result<Vec<Rule>>;

    /// Applies a set of firewall rules.
    ///
    /// # Arguments
    /// * `rules` - The rules to apply in a backend-agnostic format.
    ///
    /// # Returns
    /// A list of changes made, or an error if application fails.
    async fn apply_rules(&self, ctx: &Context, rules: &[Rule]) -> Result<Vec<Change>>;

    /// Returns the recommended baseline firewall rules.
    ///
    /// These are sensible defaults that work across most systems:
    /// - Allow established/related connections
    /// - Allow loopback
    /// - Allow SSH (port 22)
    /// - Drop all other inbound by default.
    fn get_default_rules(&self) -> Vec<Rule>;
}

/// Returns compliance mappings for firewall findings.
fn get_firewall_compliance_mappings() -> Vec<ComplianceMapping> {
    vec![ComplianceMapping {
        compliance_framework: ComplianceFramework::CIS,
        compliance_control_id: "3.4.1.2".to_string(),
        compliance_control_title: "Ensure firewall service is enabled and
  running"
            .to_string(),
        compliance_section: Some("Network Configuration".to_string()),
    }]
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
            rule_protocol: "all".to_string(),
            rule_port: "any".to_string(),
            rule_source: "127.0.0.1/8".to_string(),
            rule_action: "accept".to_string(),
        },
        Rule {
            rule_description: "Allow established and related connections".to_string(),
            rule_protocol: "all".to_string(),
            rule_port: "any".to_string(),
            rule_source: "any".to_string(),
            rule_action: "accept".to_string(),
        },
        Rule {
            rule_description: "Allow SSH to prevent lockout".to_string(),
            rule_protocol: "tcp".to_string(),
            rule_port: "22".to_string(),
            rule_source: "any".to_string(),
            rule_action: "accept".to_string(),
        },
        Rule {
            rule_description: "Drop all other inbound traffic by default".to_string(),
            rule_protocol: "all".to_string(),
            rule_port: "any".to_string(),
            rule_source: "any".to_string(),
            rule_action: "drop".to_string(),
        },
    ]
}

/// Main firewall hardening plugin
///
/// This plugin automatically detects and uses the appropriate firewall
/// backend for the system (nftables, firewalld, or ufw).
pub struct FirewallHardeningPlugin {}

impl Default for FirewallHardeningPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallHardeningPlugin {
    /// Create a new firewall plugin instance.
    ///
    /// The backend is detected lazily during the first operation.
    pub fn new() -> FirewallHardeningPlugin {
        FirewallHardeningPlugin {}
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
    async fn detect_backend(&self, ctx: &Context) -> Result<Box<dyn FirewallBackend>> {
        // Try firewalld first (RHEL/Fedora/CentOS).
        let firewalld = firewalld::FirewalldBackend::new();
        if firewalld.detect(ctx).await? {
            info!("Detected firewalld firewall backend");
            return Ok(Box::new(firewalld));
        }

        // Try UFW second (Ubuntu/Debian).
        let ufw = ufw::UfwBackend::new();
        if ufw.detect(ctx).await? {
            info!("Detected UFW firewall backend");
            return Ok(Box::new(ufw));
        }

        // Try nftables third (modern systems, Arch, Debian 10+, Ubuntu 20.04+).
        let nftables = nftables::NftablesBackend::new();
        if nftables.detect(ctx).await? {
            info!("Detected nftables firewall backend");
            return Ok(Box::new(nftables));
        }

        // No backend found.
        Err(hardener_common::error::HardeningError::Plugin(
            "No supported firewall backend found (checked: ufw, nftables)".to_string(),
        ))
    }
}

#[async_trait]
impl HardeningPlugin for FirewallHardeningPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_category: FindingCategory::Network,
            plugin_description:
                "Manages firewall configuration across nftables, firewalld, and ufw".to_string(),
            plugin_id: PluginId::new("firewall-hardening"),
            plugin_name: "Firewall Hardening".to_string(),
            plugin_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        // Firewall hardening has no dependencies
        vec![]
    }

    async fn scan(&self, ctx: &Context) -> Result<ScanResult> {
        let start_time = Instant::now();
        let plugin_id = PluginId::new("firewall-hardening");

        let mut findings = Vec::new();

        // Detect backend.
        let backend = match self.detect_backend(ctx).await {
            Ok(backend) => backend,
            Err(e) => {
                return Ok(ScanResult {
                    scan_plugin_id: plugin_id,
                    scan_success: false,
                    scan_findings: vec![],
                    scan_duration_us: start_time.elapsed().as_micros() as u64,
                    scan_error: Some(format!("No firewall backend: {}", e)),
                });
            }
        };

        // Check if firewall is enabled.
        if let Err(e) = backend.is_enabled(ctx).await {
            let error_msg = e.to_string();

            // Distinguish between "disabled" and "permission denied".
            // Only report "disabled" if we're certain it's actually disabled.
            if error_msg.contains("permission denied") || error_msg.contains("Permission denied") {
                // Cannot determine status - log warning but don't create false finding.
                warn!(
                    "Cannot verify {} firewall status: {}",
                    backend.backend_name(),
                    error_msg
                );
            } else {
                // Firewall is genuinely disabled.
                findings.push(Finding {
                    finding_category: FindingCategory::Network,
                    finding_current_value: "disabled".to_string(),
                    finding_description: format!(
                        "{} firewall is not enabled",
                        backend.backend_name()
                    ),
                    finding_explanation: "A firewall provides essential network protection"
                        .to_string(),
                    finding_id: format!("{}-disabled", backend.backend_name()),
                    finding_impact: "System exposed to network attacks".to_string(),
                    finding_recommended_value: "enabled".to_string(),
                    finding_remediation_steps: vec![format!(
                        "Enable {} firewall",
                        backend.backend_name()
                    )],
                    finding_severity: Severity::High,
                    finding_title: "Firewall disabled".to_string(),
                    finding_compliance: get_firewall_compliance_mappings(),
                    finding_policy_exception: None,
                });
            }
        }

        let duration_us = start_time.elapsed().as_micros() as u64;
        Ok(ScanResult {
            scan_plugin_id: plugin_id,
            scan_success: true,
            scan_findings: findings,
            scan_duration_us: duration_us,
            scan_error: None,
        })
    }

    async fn apply(&self, ctx: &mut Context, _config: &Config) -> Result<ApplyResult> {
        use std::path::Path;

        let apply_plugin_id = PluginId::new("firewall-hardening");

        // Create checkpoint for firewall config files
        let firewall_paths: Vec<&Path> = vec![
            Path::new("/etc/nftables.conf"),
            Path::new("/etc/firewalld"),
            Path::new("/etc/ufw"),
        ];
        let checkpoint_id = crate::create_checkpoint_for_apply(
            ctx,
            "firewall-hardening-pre-apply",
            &firewall_paths,
        )
        .await?;

        // Detect backend.
        let backend = match self.detect_backend(ctx).await {
            Ok(b) => b,
            Err(e) => {
                return Ok(ApplyResult {
                    apply_plugin_id,
                    apply_success: false,
                    apply_changes: vec![],
                    apply_checkpoint_id: checkpoint_id,
                    apply_error: Some(format!("No firewall backend: {}", e)),
                });
            }
        };

        // Enable firewall if not already enabled.
        if backend.is_enabled(ctx).await.is_err() {
            backend.enable(ctx).await?;
        }

        // Apply default rules.
        let rules = backend.get_default_rules();
        let mut apply_changes = backend.apply_rules(ctx, &rules).await?;

        if checkpoint_id.is_some() {
            apply_changes.insert(
                0,
                Change {
                    change_description: "Created checkpoint for rollback".to_string(),
                    change_type: ChangeType::FirewallRule,
                    change_success: true,
                    change_error: None,
                },
            );
        }

        Ok(ApplyResult {
            apply_plugin_id,
            apply_success: true,
            apply_changes,
            apply_checkpoint_id: checkpoint_id,
            apply_error: None,
        })
    }

    async fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()> {
        info!(
            "Rolling back firewall configuration to checkpoint: {}",
            checkpoint.checkpoint_id.as_str()
        );

        // Restore configuration files from checkpoint
        crate::rollback_files_from_checkpoint(ctx, checkpoint)?;

        info!("Firewall configuration files restored from checkpoint");

        // Re-enable firewall to reload rules based on detected backend
        match self.detect_backend(ctx).await {
            Ok(backend) => match backend.enable(ctx).await {
                Ok(_) => info!("Firewall re-enabled successfully"),
                Err(e) => warn!("Failed to re-enable firewall: {}", e),
            },
            Err(e) => {
                warn!("Could not detect firewall backend for reload: {}", e);
            }
        }

        Ok(())
    }

    async fn validate(&self, ctx: &Context, _config: &Config) -> Result<ValidationReport> {
        let validation_plugin_id = PluginId::new("firewall-hardening");
        let mut issues = Vec::new();
        let mut estimated_changes = Vec::new();

        // Detect backend.
        match self.detect_backend(ctx).await {
            Ok(backend) => {
                // Check if firewall is enabled.
                if let Err(e) = backend.is_enabled(ctx).await {
                    let error_msg = e.to_string();
                    if error_msg.contains("permission denied")
                        || error_msg.contains("Permission denied")
                    {
                        issues.push(hardener_core::ValidationIssue {
                            validation_issue_severity: Severity::Medium,
                            validation_issue_message:
                                "Cannot verify firewall status (permission denied)".to_string(),
                            validation_issue_config_key: None,
                        });
                    } else {
                        // Firewall is disabled - will be enabled.
                        estimated_changes
                            .push(format!("Enable {} firewall", backend.backend_name()));
                    }
                }

                // Get default rules that would be applied.
                let rules = backend.get_default_rules();
                if !rules.is_empty() {
                    estimated_changes.push(format!("Apply {} baseline firewall rules", rules.len()));
                }
            }
            Err(e) => {
                issues.push(hardener_core::ValidationIssue {
                    validation_issue_severity: Severity::Critical,
                    validation_issue_message: format!("No firewall backend available: {}", e),
                    validation_issue_config_key: None,
                });
            }
        }

        Ok(ValidationReport {
            validation_report_plugin_id: validation_plugin_id,
            validation_report_is_valid: issues
                .iter()
                .all(|i| i.validation_issue_severity != Severity::Critical),
            validation_report_issues: issues,
            validation_report_estimated_changes: estimated_changes,
        })
    }
}
