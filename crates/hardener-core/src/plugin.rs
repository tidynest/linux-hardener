//! Core plugin trait and related types.
//!
//! Defines the HardeningPlugin trait that all security plugins must implement.

use hardener_common::{
    error::Result,
    types::{ComplianceMapping, FindingCategory, PluginId},
};
use serde::{Deserialize, Serialize};
use std::fmt;

// Context is only available with the system feature
#[cfg(feature = "system")]
pub(crate) use crate::context::Context;

/// Placeholder types - will be implemented in other modules
#[cfg(feature = "system")]
pub struct Checkpoint;

#[cfg(feature = "system")]
pub struct Config;

/// Metadata describing a hardening plugin.
///
/// Contains identifying information and categorisation for each plugin.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PluginMetadata {
    /// Category of security controls this plugin implements.
    pub plugin_category: FindingCategory,
    /// Brief finding_description of what this plugin hardens.
    pub plugin_description: String,
    /// Unique identifier for the plugin.
    pub plugin_id: PluginId,
    /// Human-readable name of the plugin.
    pub plugin_name: String,
    /// Semantic version of the plugin (e.g., "0.1.0").
    pub plugin_version: String,
}

/// Result of a scan operation.
///
/// Contains all security findings discovered by a plugin during scanning.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanResult {
    /// Plugin that generated this result.
    pub scan_plugin_id: PluginId,
    /// Whether the scan completed successfully.
    pub scan_success: bool,
    /// List of security findings discovered.
    pub scan_findings: Vec<Finding>,
    /// Duration of the scan in microseconds.
    pub scan_duration_us: u64,
    /// Optional error message if scan failed.
    pub scan_error: Option<String>,
}

/// A single security finding from a scan.
///
/// Represents a specific security issue or configuration problem.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Finding {
    /// Category of the finding.
    pub finding_category: FindingCategory,
    /// Current (insecure) value or configuration.
    pub finding_current_value: String,
    /// Detailed finding_description of the security issue.
    pub finding_description: String,
    /// Explanation of why this is a security issue.
    pub finding_explanation: String,
    /// Unique identifier for this finding.
    pub finding_id: String,
    /// Impact of applying the recommended change.
    pub finding_impact: String,
    /// Recommended secure value or configuration.
    pub finding_recommended_value: String,
    /// Steps to remediate this finding.
    pub finding_remediation_steps: Vec<String>,
    /// Severity level of the finding.
    pub finding_severity: hardener_common::types::Severity,
    /// Short title describing the issue.
    pub finding_title: String,
    /// Compliance framework mappings for this finding.
    pub finding_compliance: Vec<ComplianceMapping>,
}

/// Result of applying hardening changes.
///
/// Contains information about what changes were made and whether they succeeded.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApplyResult {
    /// Plugin that generated this result.
    pub apply_plugin_id: PluginId,
    /// Whether all changes were applied successfully.
    pub apply_success: bool,
    /// List of changes that were applied.
    pub apply_changes: Vec<Change>,
    /// ID of the checkpoint created before changes (for rollback).
    pub apply_checkpoint_id: Option<String>,
    /// Optional error message if apply failed.
    pub apply_error: Option<String>,
}

/// Represents a single change made during hardening.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Change {
    /// Description of what was changed.
    pub change_description: String,
    /// Type of change (file, sysctl, service, etc.).
    pub change_type: ChangeType,
    /// Whether this change was successful.
    pub change_success: bool,
    /// Optional error if change failed.
    pub change_error: Option<String>,
}

/// Type of system change.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ChangeType {
    /// Configuration file modification.
    ConfigFile,
    /// Firewall rule change.
    FirewallRule,
    /// Kernel parameter (sysctl) modification.
    KernelParameter,
    /// Package installation or removal.
    Package,
    /// File or directory permissions change.
    Permissions,
    /// Service state change (enable/disable/mask).
    Service,
}

impl fmt::Display for ChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChangeType::ConfigFile => write!(f, "Config File"),
            ChangeType::FirewallRule => write!(f, "Firewall Rule"),
            ChangeType::KernelParameter => write!(f, "Kernel Parameter"),
            ChangeType::Package => write!(f, "Package"),
            ChangeType::Permissions => write!(f, "Permissions"),
            ChangeType::Service => write!(f, "Service"),
        }
    }
}

/// Validation report for configuration.
///
/// Contains the results of validating a configuration without applying it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidationReport {
    /// Plugin that generated this report.
    pub validation_report_plugin_id: PluginId,
    /// Whether the configuration is valid.
    pub validation_report_is_valid: bool,
    /// List of validation issues found.
    pub validation_report_issues: Vec<ValidationIssue>,
    /// Estimated changes if this configuration were applied.
    pub validation_report_estimated_changes: Vec<String>,
}

/// A single validation issue.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidationIssue {
    /// Severity of the validation issue.
    pub validation_issue_severity: hardener_common::types::Severity,
    /// Description of the validation issue.
    pub validation_issue_message: String,
    /// Configuration of the validation issue.
    pub validation_issue_config_key: Option<String>,
}

/// Core trait that all hardening plugins must implement.
///
/// This trait defines the contract for security hardening plugins.
/// Each plugin is responsible for:
/// - Scanning the system for security issues in its domain
/// - Applying hardening changes based on configuration
/// - Rolling back changes if needed
/// - Validating configurations before applying
///
/// # Plugin Lifecycle
///
/// 1. **Registration**: Plugin is registered with the PluginRegistry
/// 2. **Dependency Resolution**: Dependencies are checked and ordered
/// 3. **Scanning**: `scan()` is called to detect current security state
/// 4. **Validation**: `validate()` checks configuration before changes
/// 5. **Application**: `apply()` makes changes to harden the system
/// 5. **Rollback**: `rollback()` restores previous state if needed
///
/// # Thread Safety
///
/// Plugins must be `Send + Sync` as they may be called from async contexts
/// and share across threads.
///
/// This trait is only available with the `system` feature enabled.
#[cfg(feature = "system")]
pub trait HardeningPlugin: Send + Sync {
    /// Returns metadata describing this plugin.
    fn metadata(&self) -> PluginMetadata;

    /// Returns a list of plugin IDs that this plugin depends on.
    ///
    /// Dependencies will be processed before this plugin during operations.
    fn dependencies(&self) -> Vec<PluginId>;

    /// Scans the system for security issues in this plugin's domain.
    ///
    /// This method should not modify the system (read-only operation).
    fn scan(&self, ctx: &Context) -> Result<ScanResult>;

    /// Applies hardening changes based on the provided configuration.
    ///
    /// Should create a checkpoint before making changes.
    fn apply(&self, ctx: &mut Context, config: &Config) -> Result<ApplyResult>;

    /// Rolls back changes to a previous checkpoint
    fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()>;

    /// Validates configuration without applying changes (dry-run).
    fn validate(&self, config: &Config) -> Result<ValidationReport>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_change_type_display() {
        assert_eq!(ChangeType::ConfigFile.to_string(), "Config File");
        assert_eq!(ChangeType::FirewallRule.to_string(), "Firewall Rule");
        assert_eq!(ChangeType::KernelParameter.to_string(), "Kernel Parameter");
    }
}
