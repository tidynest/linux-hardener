//! Shared type definitions for Linux System Hardener.
//!
//! This crate contains all types that need to be shared between the native
//! backend (Tauri) and WASM frontend (Leptos). It has minimal dependencies
//! to ensure WASM compatibility.

use serde::{Deserialize, Serialize};
use std::fmt;

// Re-export chrono types used in reports
pub use chrono::{DateTime, Utc};

pub mod remote;
pub use remote::*;

// ============================================================================
// Plugin Types (from hardener-common)
// ============================================================================

/// Unique identifier for a hardening plugin.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct PluginId(String);

impl PluginId {
    /// Creates a new PluginId from a string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Returns the string representation of the plugin ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PluginId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for PluginId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for PluginId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Severity level for security findings.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum Severity {
    /// Informational finding, no immediate action required.
    Info,
    /// Low severity, should be addressed eventually.
    Low,
    /// Medium severity, should be addressed soon.
    Medium,
    /// High severity, should be addressed promptly.
    High,
    /// Critical severity, requires immediate action.
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Category of security finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingCategory {
    /// Audit logging and monitoring.
    Audit,
    /// Authentication and access control (PAM, SSH, etc.).
    Authentication,
    /// Cryptographic settings and algorithms.
    Cryptography,
    /// File system permissions and access controls.
    FileSystem,
    /// Kernel-level security settings.
    Kernel,
    /// Mandatory Access Control (SELinux, AppArmor).
    MandatoryAccessControl,
    /// Network and firewall configuration.
    Network,
    /// Service configuration and minimisation.
    Services,
}

impl fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindingCategory::Audit => write!(f, "Audit"),
            FindingCategory::Authentication => write!(f, "Authentication"),
            FindingCategory::Cryptography => write!(f, "Cryptography"),
            FindingCategory::FileSystem => write!(f, "File System"),
            FindingCategory::Kernel => write!(f, "Kernel"),
            FindingCategory::MandatoryAccessControl => write!(f, "MAC"),
            FindingCategory::Network => write!(f, "Network"),
            FindingCategory::Services => write!(f, "Services"),
        }
    }
}

/// Compliance framework identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComplianceFramework {
    /// Center for Internet Security Benchmarks.
    CIS,
    /// Health Insurance Portability and Accountability Act.
    HIPAA,
    /// International Organisation for Standardisation 27001.
    ISO27001,
    /// National Institute of Standards and Technology.
    NIST,
    /// Payment Card Industry Data Security Standard.
    PCIDSS,
    /// Security Technical Implementation Guides.
    STIG,
    /// General Data Protection Regulation (EU).
    GDPR,
}

impl fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComplianceFramework::CIS => write!(f, "CIS"),
            ComplianceFramework::HIPAA => write!(f, "HIPAA"),
            ComplianceFramework::ISO27001 => write!(f, "ISO27001"),
            ComplianceFramework::NIST => write!(f, "NIST"),
            ComplianceFramework::PCIDSS => write!(f, "PCIDSS"),
            ComplianceFramework::STIG => write!(f, "STIG"),
            ComplianceFramework::GDPR => write!(f, "GDPR"),
        }
    }
}

impl ComplianceFramework {
    /// Returns the full name of the compliance framework.
    pub fn full_name(&self) -> &'static str {
        match self {
            ComplianceFramework::CIS => "CIS Benchmark",
            ComplianceFramework::HIPAA => "HIPAA Security Rule",
            ComplianceFramework::ISO27001 => "ISO/IEC 27001",
            ComplianceFramework::NIST => "NIST 800-53",
            ComplianceFramework::PCIDSS => "PCI-DSS v4.0",
            ComplianceFramework::STIG => "DISA STIG",
            ComplianceFramework::GDPR => "GDPR Article 32",
        }
    }

    /// Returns a brief description of the compliance framework.
    pub fn description(&self) -> &'static str {
        match self {
            ComplianceFramework::CIS => "Center for Internet Security Benchmarks for Linux",
            ComplianceFramework::HIPAA => "Health Insurance Portability and Accountability Act",
            ComplianceFramework::ISO27001 => "International Organisation for Standardisation 27001",
            ComplianceFramework::NIST => {
                "National Institute of Standards and Technology Special Publication 800-53"
            }
            ComplianceFramework::PCIDSS => "Payment Card Industry Data Security Standard",
            ComplianceFramework::STIG => {
                "Defense Information Systems Agency Security Technical Implementation Guides"
            }
            ComplianceFramework::GDPR => "European Union General Data Protection Regulation",
        }
    }
}

/// Mapping of a finding to a specific compliance framework control.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComplianceMapping {
    /// The compliance framework this mapping belongs to.
    pub compliance_framework: ComplianceFramework,
    /// The control identifier (e.g., "1.5.1" for CIS, "V-230223" for STIG).
    pub compliance_control_id: String,
    /// Human-readable title of the control.
    pub compliance_control_title: String,
    /// Optional section/category within the framework.
    pub compliance_section: Option<String>,
}

/// Status of a compliance control check.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum ControlStatus {
    /// Control requirements are met.
    Pass,
    /// Control requirements are not met.
    Fail,
    /// Control is not applicable to this system.
    #[default]
    NotApplicable,
    /// Control requires manual review.
    ManualReview,
}

impl fmt::Display for ControlStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControlStatus::Pass => write!(f, "Pass"),
            ControlStatus::Fail => write!(f, "Fail"),
            ControlStatus::NotApplicable => write!(f, "N/A"),
            ControlStatus::ManualReview => write!(f, "MANUAL"),
        }
    }
}

/// Policy exception attached to a finding when config allows a deviation.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FindingPolicyException {
    /// The value that was allowed by policy.
    pub exception_allowed_value: String,
    /// Human-readable reason for the exception.
    pub exception_reason: String,
    /// Who approved this exception.
    pub exception_approved_by: Option<String>,
    /// When this exception was approved (ISO 8601 date).
    pub exception_approved_date: Option<String>,
    /// Reference to approval ticket/issue.
    pub exception_ticket: Option<String>,
    /// When this exception expires (ISO 8601 date).
    pub exception_expires: Option<String>,
    /// Whether the exception has expired.
    pub exception_is_expired: bool,
}

// ============================================================================
// Plugin Types (from hardener-core)
// ============================================================================

/// Metadata describing a hardening plugin.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PluginMetadata {
    /// Category of security controls this plugin implements.
    pub plugin_category: FindingCategory,
    /// Brief description of what this plugin hardens.
    pub plugin_description: String,
    /// Unique identifier for the plugin.
    pub plugin_id: PluginId,
    /// Human-readable name of the plugin.
    pub plugin_name: String,
    /// Semantic version of the plugin (e.g., "0.1.0").
    pub plugin_version: String,
}

/// Result of a scan operation.
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
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Finding {
    /// Category of the finding.
    pub finding_category: FindingCategory,
    /// Current (insecure) value or configuration.
    pub finding_current_value: String,
    /// Detailed description of the security issue.
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
    pub finding_severity: Severity,
    /// Short title describing the issue.
    pub finding_title: String,
    /// Compliance framework mappings for this finding.
    pub finding_compliance: Vec<ComplianceMapping>,
    /// Policy exception if this finding is covered by config.
    pub finding_policy_exception: Option<FindingPolicyException>,
}

/// Result of applying hardening changes.
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

// ============================================================================
// Rollback Types
// ============================================================================

/// The type of restore action performed on a file during rollback.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FileRestoreAction {
    /// File content and permissions were restored.
    Restored,
    /// File was removed (it didn't exist at checkpoint time).
    Removed,
    /// Directory permissions were restored (content unchanged).
    PermissionsRestored,
    /// File was skipped (no action needed).
    Skipped,
}

/// Outcome of a single file restore during rollback.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileRestoreResult {
    /// Path that was restored.
    pub restore_path: String,
    /// What action was taken.
    pub restore_action: FileRestoreAction,
    /// Whether the restore succeeded.
    pub restore_success: bool,
    /// Error message if the restore failed.
    pub restore_error: Option<String>,
}

/// Results of a full rollback operation.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RollbackResult {
    /// Checkpoint that was rolled back to.
    pub rollback_checkpoint_id: String,
    /// Name of the checkpoint.
    pub rollback_checkpoint_name: String,
    /// Whether all files were restored successfully.
    pub rollback_success: bool,
    /// Per-file restore results.
    pub rollback_files: Vec<FileRestoreResult>,
}

// ============================================================================
// Validation Types
// ============================================================================

/// Validation report for configuration.
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
    pub validation_issue_severity: Severity,
    /// Description of the validation issue.
    pub validation_issue_message: String,
    /// Configuration key related to the issue.
    pub validation_issue_config_key: Option<String>,
}

// ============================================================================
// Compliance Report Types (from hardener-compliance)
// ============================================================================

/// A complete compliance report for a single framework.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComplianceReport {
    /// The compliance framework this report covers.
    pub report_framework: ComplianceFramework,
    /// When this report was generated.
    pub report_generated_at: DateTime<Utc>,
    /// Individual control check results.
    pub report_controls: Vec<ControlResult>,
    /// Summary statistics for the report.
    pub report_summary: ComplianceSummary,
}

/// Result of checking a single compliance control.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ControlResult {
    /// The control identifier (e.g., "1.5.1" for CIS).
    pub control_id: String,
    /// Human-readable title of the control.
    pub control_title: String,
    /// Section/category within the framework.
    pub control_section: String,
    /// Whether the control passed or failed.
    pub control_status: ControlStatus,
    /// Findings that caused this control to fail (empty if passed).
    pub control_findings: Vec<Finding>,
}

/// Summary statistics for a compliance report.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComplianceSummary {
    /// Total number of controls checked.
    pub summary_total_controls: usize,
    /// Number of controls that passed.
    pub summary_passing: usize,
    /// Number of controls that failed.
    pub summary_failing: usize,
    /// Number of controls requiring manual review.
    pub summary_manual_review: usize,
    /// Number of controls not applicable to this system.
    pub summary_not_applicable: usize,
    /// Overall compliance score as a percentage.
    pub summary_score_percentage: f64,
}

impl ComplianceSummary {
    /// Creates a new summary by calculating statistics from control results.
    pub fn from_controls(controls: &[ControlResult]) -> ComplianceSummary {
        let total = controls.len();
        let passing = controls
            .iter()
            .filter(|c| c.control_status == ControlStatus::Pass)
            .count();
        let failing = controls
            .iter()
            .filter(|c| c.control_status == ControlStatus::Fail)
            .count();
        let not_applicable = controls
            .iter()
            .filter(|c| c.control_status == ControlStatus::NotApplicable)
            .count();
        let manual_review = controls
            .iter()
            .filter(|c| c.control_status == ControlStatus::ManualReview)
            .count();

        let applicable = total.saturating_sub(not_applicable);
        let score = if applicable > 0 {
            (passing as f64 / applicable as f64) * 100.0
        } else {
            100.0
        };

        Self {
            summary_total_controls: total,
            summary_passing: passing,
            summary_failing: failing,
            summary_manual_review: manual_review,
            summary_not_applicable: not_applicable,
            summary_score_percentage: score,
        }
    }
}
