//! Shared type definitions for Linux System Hardener.
//!
//! This crate contains all types that need to be shared between the native
//! backend (Tauri) and WASM frontend (Leptos). It has minimal dependencies
//! to ensure WASM compatibility.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

// Re-export chrono types used in reports
pub use chrono::{DateTime, Utc};

pub mod config_picker;
pub mod remote;
pub mod scheduler;
pub use config_picker::*;
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
    /// AICPA SOC 2 Trust Services Criteria.
    SOC2,
    /// NIST SP 800-171 protection of Controlled Unclassified Information.
    NIST800171,
    /// FedRAMP Moderate baseline (Rev 5) of NIST SP 800-53 controls.
    FedRAMP,
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
            ComplianceFramework::SOC2 => write!(f, "SOC 2"),
            ComplianceFramework::NIST800171 => write!(f, "NIST 800-171"),
            ComplianceFramework::FedRAMP => write!(f, "FedRAMP"),
        }
    }
}

impl ComplianceFramework {
    /// Every supported framework, in canonical display order. Single source
    /// for UI pickers and auto-report calls so new frameworks cannot be
    /// silently omitted from hardcoded lists.
    pub const ALL: [ComplianceFramework; 10] = [
        ComplianceFramework::CIS,
        ComplianceFramework::STIG,
        ComplianceFramework::NIST,
        ComplianceFramework::PCIDSS,
        ComplianceFramework::HIPAA,
        ComplianceFramework::GDPR,
        ComplianceFramework::ISO27001,
        ComplianceFramework::SOC2,
        ComplianceFramework::NIST800171,
        ComplianceFramework::FedRAMP,
    ];

    /// Canonical request identifier, as accepted by the CLI `--framework`
    /// flag and the desktop `parse_frameworks` command layer.
    pub fn id(&self) -> &'static str {
        match self {
            ComplianceFramework::CIS => "cis",
            ComplianceFramework::HIPAA => "hipaa",
            ComplianceFramework::ISO27001 => "iso27001",
            ComplianceFramework::NIST => "nist",
            ComplianceFramework::PCIDSS => "pci-dss",
            ComplianceFramework::STIG => "stig",
            ComplianceFramework::GDPR => "gdpr",
            ComplianceFramework::SOC2 => "soc2",
            ComplianceFramework::NIST800171 => "800-171",
            ComplianceFramework::FedRAMP => "fedramp",
        }
    }

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
            ComplianceFramework::SOC2 => "SOC 2 Trust Services Criteria",
            ComplianceFramework::NIST800171 => "NIST SP 800-171",
            ComplianceFramework::FedRAMP => "FedRAMP Moderate Baseline",
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
            ComplianceFramework::SOC2 => {
                "AICPA Trust Services Criteria (2017, with 2022 points of focus)"
            }
            ComplianceFramework::NIST800171 => {
                "NIST SP 800-171 Revision 3 protection of Controlled Unclassified Information"
            }
            ComplianceFramework::FedRAMP => {
                "FedRAMP Moderate baseline (Rev 5) of NIST SP 800-53 controls for federal cloud authorisation"
            }
        }
    }
}

/// OS-specific compliance profile selecting which control identifiers a report renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ComplianceProfile {
    /// Canonical plugin identifiers (RHEL 8 baseline for STIG).
    #[default]
    Generic,
    /// DISA RHEL 10 STIG V1R1 / CIS RHEL 10 identifiers.
    Rhel10,
}

impl fmt::Display for ComplianceProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComplianceProfile::Generic => write!(f, "generic"),
            ComplianceProfile::Rhel10 => write!(f, "rhel10"),
        }
    }
}

impl FromStr for ComplianceProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "generic" => Ok(ComplianceProfile::Generic),
            "rhel10" | "rhel-10" => Ok(ComplianceProfile::Rhel10),
            _ => Err(format!(
                "Unknown profile '{s}'. Valid options: generic, rhel10"
            )),
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
    /// No action was taken; nothing applicable on this host (e.g. no MAC
    /// system present, or the target excepted by policy). Distinct from a
    /// real change so renderers do not count it as one applied.
    Skipped,
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
            ChangeType::Skipped => write!(f, "Skipped"),
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
    /// The profile whose control identifiers this report renders.
    #[serde(default)]
    pub report_profile: ComplianceProfile,
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

// ============================================================================
// Fleet Scan Types
// ============================================================================

/// Per-severity finding counts for one host's scan.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct SeverityTallies {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

impl SeverityTallies {
    /// Counts findings by severity across all of a host's scan results.
    pub fn from_results(results: &[ScanResult]) -> Self {
        let mut tallies = Self::default();
        for finding in results.iter().flat_map(|r| &r.scan_findings) {
            match finding.finding_severity {
                Severity::Critical => tallies.critical += 1,
                Severity::High => tallies.high += 1,
                Severity::Medium => tallies.medium += 1,
                Severity::Low => tallies.low += 1,
                Severity::Info => tallies.info += 1,
            }
        }
        tallies
    }
}

/// Outcome of scanning one host in a fleet scan.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum FleetHostStatus {
    /// Host scanned successfully.
    Ok,
    /// Host could not be reached or scanned; carries the error message.
    Failed(String),
}

/// One framework's compliance posture for a fleet host: summary only (no
/// per-control detail, which already travels in `FleetHostScan::scan_results`).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FleetFrameworkPosture {
    /// The framework this posture is for.
    pub framework: ComplianceFramework,
    /// Pass/fail/manual/NA counts and the overall score.
    pub summary: ComplianceSummary,
}

/// One host's result row in a fleet scan.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FleetHostScan {
    /// Inventory profile name of the host.
    pub host_name: String,
    /// Whether the host scanned or failed.
    pub status: FleetHostStatus,
    /// Per-severity counts (zero when the host failed).
    pub tallies: SeverityTallies,
    /// Per-plugin scan results (as `run_remote_scan` returns); empty when failed.
    pub scan_results: Vec<ScanResult>,
    /// Per-framework compliance posture derived from `scan_results`; empty when
    /// the host failed to scan.
    pub compliance: Vec<FleetFrameworkPosture>,
}

// ============================================================================
// Fleet Mutation Types
// ============================================================================

/// One host's outcome from a fleet apply (or dry-run validation).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplyOutcome {
    pub name: String,
    pub target: String,
    pub status: ApplyStatus,
}

/// Result of applying (or validating) one host.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum ApplyStatus {
    /// Dry-run: `plugins` validated, `would_change` pending changes, `failed` validation errors.
    Validated {
        plugins: usize,
        would_change: usize,
        failed: usize,
    },
    /// Execute: `ok` plugins applied, `failed` did not.
    Applied { ok: usize, failed: usize },
    /// Host-level error (connect / not privileged / usage).
    Failed { error: String },
}

/// One host's outcome from a fleet rollback (or dry-run preview).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RollbackOutcome {
    pub name: String,
    pub target: String,
    pub status: RollbackStatus,
}

/// Result of rolling back (or previewing) one host.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum RollbackStatus {
    /// Dry-run: `checkpoints` checkpoints would be restored.
    Previewed { checkpoints: usize },
    /// Execute: `restored` fully restored, `failed` had a restore error.
    RolledBack { restored: usize, failed: usize },
    /// No matching checkpoint for the selected plugins on this host.
    NothingToDo,
    /// Host-level error (connect / not privileged / selection query / usage).
    Failed { error: String },
}

#[cfg(test)]
mod fleet_mutation_tests {
    use super::*;

    #[test]
    fn apply_status_deserialises_by_state_tag() {
        let validated: ApplyStatus = serde_json::from_str(
            r#"{"state":"validated","plugins":3,"would_change":5,"failed":0}"#,
        )
        .unwrap();
        assert!(matches!(
            validated,
            ApplyStatus::Validated {
                plugins: 3,
                would_change: 5,
                failed: 0
            }
        ));
        let applied: ApplyStatus =
            serde_json::from_str(r#"{"state":"applied","ok":2,"failed":1}"#).unwrap();
        assert!(matches!(applied, ApplyStatus::Applied { ok: 2, failed: 1 }));
    }

    #[test]
    fn rollback_status_deserialises_by_state_tag() {
        let previewed: RollbackStatus =
            serde_json::from_str(r#"{"state":"previewed","checkpoints":4}"#).unwrap();
        assert!(matches!(
            previewed,
            RollbackStatus::Previewed { checkpoints: 4 }
        ));
        let nothing: RollbackStatus = serde_json::from_str(r#"{"state":"nothingtodo"}"#).unwrap();
        assert!(matches!(nothing, RollbackStatus::NothingToDo));
    }
}

#[cfg(test)]
mod fleet_tests {
    use super::*;

    fn finding(severity: Severity) -> Finding {
        Finding {
            finding_category: FindingCategory::Kernel,
            finding_current_value: String::new(),
            finding_description: String::new(),
            finding_explanation: String::new(),
            finding_id: String::new(),
            finding_impact: String::new(),
            finding_recommended_value: String::new(),
            finding_remediation_steps: Vec::new(),
            finding_severity: severity,
            finding_title: String::new(),
            finding_compliance: Vec::new(),
            finding_policy_exception: None,
        }
    }

    fn result(findings: Vec<Finding>) -> ScanResult {
        ScanResult {
            scan_plugin_id: PluginId::new("test"),
            scan_success: true,
            scan_findings: findings,
            scan_duration_us: 0,
            scan_error: None,
        }
    }

    #[test]
    fn tallies_count_by_severity_across_results() {
        let results = vec![
            result(vec![finding(Severity::Critical), finding(Severity::High)]),
            result(vec![
                finding(Severity::High),
                finding(Severity::Low),
                finding(Severity::Info),
            ]),
        ];
        let t = SeverityTallies::from_results(&results);
        assert_eq!(t.critical, 1);
        assert_eq!(t.high, 2);
        assert_eq!(t.medium, 0);
        assert_eq!(t.low, 1);
        assert_eq!(t.info, 1);
    }
}

#[cfg(test)]
mod compliance_profile_tests {
    use super::*;

    #[test]
    fn profile_serde_round_trips_both_variants() {
        for (profile, json) in [
            (ComplianceProfile::Generic, "\"generic\""),
            (ComplianceProfile::Rhel10, "\"rhel10\""),
        ] {
            assert_eq!(serde_json::to_string(&profile).unwrap(), json);
            let back: ComplianceProfile = serde_json::from_str(json).unwrap();
            assert_eq!(back, profile);
        }
    }

    #[test]
    fn profile_defaults_to_generic() {
        assert_eq!(ComplianceProfile::default(), ComplianceProfile::Generic);
    }

    #[test]
    fn profile_displays_as_lowercase() {
        assert_eq!(ComplianceProfile::Generic.to_string(), "generic");
        assert_eq!(ComplianceProfile::Rhel10.to_string(), "rhel10");
    }

    #[test]
    fn profile_parses_case_insensitively_with_alias() {
        assert_eq!(
            "Generic".parse::<ComplianceProfile>().unwrap(),
            ComplianceProfile::Generic
        );
        assert_eq!(
            "rhel10".parse::<ComplianceProfile>().unwrap(),
            ComplianceProfile::Rhel10
        );
        assert_eq!(
            "RHEL-10".parse::<ComplianceProfile>().unwrap(),
            ComplianceProfile::Rhel10
        );
    }

    #[test]
    fn profile_parse_error_lists_valid_values() {
        let err = "centos".parse::<ComplianceProfile>().unwrap_err();
        assert!(err.contains("centos"));
        assert!(err.contains("generic"));
        assert!(err.contains("rhel10"));
    }
}
