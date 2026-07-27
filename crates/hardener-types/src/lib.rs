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

    /// Parses a framework request string into its enum value. Normalises
    /// case first, then checks the canonical `id()` table, then a small
    /// alias table for legacy spellings the CLI and desktop command layers
    /// used to hand-maintain separately. Single source of truth so a third
    /// parser cannot drift from either.
    pub fn from_id(s: &str) -> Option<Self> {
        let lower = s.to_lowercase();
        if let Some(framework) = ComplianceFramework::ALL.iter().find(|f| f.id() == lower) {
            return Some(*framework);
        }
        match lower.as_str() {
            "pcidss" | "pci" => Some(ComplianceFramework::PCIDSS),
            "iso" | "iso-27001" => Some(ComplianceFramework::ISO27001),
            "soc-2" => Some(ComplianceFramework::SOC2),
            "nist800171" | "nist-800-171" => Some(ComplianceFramework::NIST800171),
            "fed-ramp" => Some(ComplianceFramework::FedRAMP),
            _ => None,
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

#[cfg(test)]
mod compliance_framework_tests {
    use super::*;

    #[test]
    fn from_id_accepts_every_canonical_id() {
        for framework in ComplianceFramework::ALL {
            assert_eq!(
                ComplianceFramework::from_id(framework.id()),
                Some(framework),
                "canonical id '{}' must parse to its framework",
                framework.id()
            );
        }
    }

    #[test]
    fn from_id_is_case_insensitive() {
        assert_eq!(
            ComplianceFramework::from_id("CIS"),
            Some(ComplianceFramework::CIS)
        );
        assert_eq!(
            ComplianceFramework::from_id("Pci-Dss"),
            Some(ComplianceFramework::PCIDSS)
        );
    }

    #[test]
    fn from_id_accepts_legacy_aliases_from_both_parsers() {
        // Union of legacy alias spellings from both old parsers
        // (crates/hardener-cli/src/commands/report.rs and
        // src-tauri/src/commands.rs); of these, only "iso" was CLI-only.
        for alias in [
            "pcidss",
            "pci",
            "iso",
            "soc-2",
            "nist800171",
            "nist-800-171",
            "fed-ramp",
        ] {
            assert!(
                ComplianceFramework::from_id(alias).is_some(),
                "CLI alias '{alias}' must still parse"
            );
        }
        // Desktop-only spelling (src-tauri/src/commands.rs, matched
        // uppercase there but from_id normalises to lowercase).
        assert_eq!(
            ComplianceFramework::from_id("iso-27001"),
            Some(ComplianceFramework::ISO27001),
            "desktop alias 'iso-27001' must still parse"
        );
    }

    #[test]
    fn from_id_rejects_unknown() {
        assert_eq!(ComplianceFramework::from_id("nonsense"), None);
        assert_eq!(ComplianceFramework::from_id(""), None);
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

/// A check the scanner could not evaluate at its current privilege level.
///
/// Unchecked entries are not findings: they carry no severity, never enter
/// the security score, and map to `ManualReview` in compliance reports.
/// `unchecked_check_id` equals the `finding_id` the check would produce if it
/// failed, so consumers can correlate the two.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UncheckedCheck {
    /// Stable id, identical to the finding_id the check would produce.
    pub unchecked_check_id: String,
    /// Short human title of the check, e.g. "PAM setting: minlen".
    pub unchecked_title: String,
    /// Category, same domain as Finding.
    pub unchecked_category: FindingCategory,
    /// Why it could not be checked, e.g. "reading /etc/security/pwquality.conf requires root".
    pub unchecked_reason: String,
    /// Compliance mappings the check covers (drives ManualReview).
    pub unchecked_compliance: Vec<ComplianceMapping>,
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
    /// Checks that could not be evaluated at the current privilege level.
    #[serde(default)]
    pub scan_unchecked: Vec<UncheckedCheck>,
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

/// Label shown in place of a severity when the configuration documents a
/// finding as an accepted deviation.
///
/// A documented deviation is not a violation, so it is never rendered as one.
/// It is still rendered, so a result resting on an exception stays
/// distinguishable from a genuinely clean one. This lives here, in the crate
/// every front end already depends on, because a renderer that quietly drops
/// excepted findings reports a deviation as compliance.
pub const POLICY_EXCEPTION_LABEL: &str = "POLICY EXCEPTION";

/// One line for `validation_report_exceptions`, naming the setting, the value
/// the host keeps, and why.
///
/// Every plugin whose `validate` skips an excepted setting builds its line
/// here. Seven hand-written copies of the same sentence is how one of them ends
/// up worded differently, or omitted altogether, which is the defect this field
/// exists to close.
pub fn exception_preview_line(setting: &str, observed: &str, reason: &str) -> String {
    format!("{setting}: left at '{observed}' ({POLICY_EXCEPTION_LABEL}: {reason})")
}

impl Finding {
    /// Whether the configuration documents this finding as an accepted
    /// deviation rather than a live violation.
    pub fn is_policy_excepted(&self) -> bool {
        self.finding_policy_exception.is_some()
    }

    /// The label for this finding's evidence line: [`POLICY_EXCEPTION_LABEL`]
    /// for a documented deviation, otherwise the finding's severity.
    ///
    /// Renderers that style the two cases differently, rather than only
    /// labelling them, branch on [`Finding::is_policy_excepted`] and reach for
    /// the constant themselves.
    pub fn evidence_label(&self) -> String {
        if self.is_policy_excepted() {
            POLICY_EXCEPTION_LABEL.to_string()
        } else {
            self.finding_severity.to_string()
        }
    }
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

impl ApplyResult {
    /// Counts changes that were genuinely applied to the host: real work
    /// (not a [`ChangeType::Skipped`] no-op such as no MAC system present, and
    /// not the [`ChangeType::Checkpoint`] rollback-bookkeeping entry) that also
    /// succeeded. Renderers must use these count helpers, never
    /// `apply_changes.len()` arithmetic, so "N change(s) applied" can only
    /// ever mean N hardening successes.
    pub fn applied_change_count(&self) -> usize {
        self.apply_changes
            .iter()
            .filter(|c| !c.is_skipped() && !c.is_checkpoint() && c.change_success)
            .count()
    }

    /// Counts real (non-skipped, non-checkpoint) changes that were attempted
    /// and failed.
    pub fn failed_change_count(&self) -> usize {
        self.apply_changes
            .iter()
            .filter(|c| !c.is_skipped() && !c.is_checkpoint() && !c.change_success)
            .count()
    }

    /// Counts [`ChangeType::Skipped`] no-op entries. Renderers must use this
    /// for "M skipped", not `len - applied`, which would lump failures in.
    pub fn skipped_change_count(&self) -> usize {
        self.apply_changes.iter().filter(|c| c.is_skipped()).count()
    }
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

impl Change {
    /// Whether this entry is a [`ChangeType::Skipped`] no-op rather than a
    /// real change applied to the host.
    pub fn is_skipped(&self) -> bool {
        self.change_type == ChangeType::Skipped
    }

    /// Whether this entry records rollback-checkpoint creation rather than a
    /// hardening change. Excluded from both the applied and the failed counts.
    pub fn is_checkpoint(&self) -> bool {
        self.change_type == ChangeType::Checkpoint
    }
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
    /// A rollback checkpoint was captured before applying. Bookkeeping rather
    /// than a hardening change: renderers still show it (so the admin knows a
    /// rollback point exists), but the count helpers exclude it from both the
    /// applied and the failed totals, so a plugin whose only action was the
    /// checkpoint reads as having hardened nothing.
    Checkpoint,
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
            ChangeType::Checkpoint => write!(f, "Checkpoint"),
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

/// Paths a rollback must never delete, whatever a checkpoint records.
///
/// A checkpoint stores an absent path with `file_permissions: 0`, which restore
/// reads as "remove on rollback". Versions up to and including v1.4.0 could
/// record an existing file that way when its metadata could not be read, and
/// upgrading does not rewrite rows already in `checkpoints.db`, so such a row
/// is an untrustworthy record rather than an instruction to delete.
///
/// Membership rule: a path belongs here only when an apply can never create it,
/// which is what makes deleting it never a correct restore. A path some apply
/// can bring into existence must stay deletable, whether that is a file the
/// tool writes without first requiring it to be there, a drop-in of its own, or
/// a directory it creates with `mkdir`; protecting one of those would leave
/// behind the very file the operator asked to be rolled back. Where the source
/// cannot settle the question, the path stays deletable.
///
/// Exact matches only. `/etc/sudoers.d` the directory is protected; a drop-in
/// file inside it that an apply created stays removable.
pub const UNDELETABLE_ROLLBACK_PATHS: &[&str] = &[
    // Account, boot and auth paths hardened by the permissions plugin, which
    // only ever chmods/chowns what is already there.
    "/root",
    "/boot",
    "/etc/ssh",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/passwd",
    "/etc/group",
    "/etc/shadow",
    "/etc/gshadow",
    // Distribution-owned configuration the plugins edit in place after a read
    // that aborts on absence, or capture without ever writing.
    "/etc/ssh/sshd_config",
    "/etc/sysctl.conf",
    "/etc/audit/auditd.conf",
    "/etc/nftables.conf",
    "/etc/selinux/config",
    // Directories the plugins write files into, or capture and never touch.
    // Writes go through `write_file`, which cannot create a missing parent, and
    // no apply runs `mkdir` for any of these.
    "/etc/sysctl.d",
    "/etc/pam.d",
    "/etc/security",
    "/etc/apparmor",
    "/etc/apparmor.d",
];

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
    /// Estimated changes if this configuration were applied. Genuinely pending
    /// changes only; settings already at their target are not listed here (see
    /// `validation_report_compliant_count`), so the length is the real
    /// change count.
    pub validation_report_estimated_changes: Vec<String>,
    /// Number of settings the plugin checked that were already compliant (no
    /// change needed). Surfaced separately so renderers can report it without
    /// counting it among the pending `validation_report_estimated_changes`.
    /// Plugins with no compliant-count concept leave this 0.
    #[serde(default)]
    pub validation_report_compliant_count: usize,
    /// Settings this run will leave alone because a policy exception documents
    /// the value the host already has, one line per setting, carrying the
    /// reason.
    ///
    /// Surfaced separately for the same reason as
    /// `validation_report_compliant_count`: an excepted setting is not a
    /// pending change and must not inflate the count, but it is not nothing
    /// either. Dropping it is how a preview came to show "0 changes" and an
    /// empty panel on a host where a directive was deliberately exempt, which
    /// is the one thing a documented deviation must never look like.
    #[serde(default)]
    pub validation_report_exceptions: Vec<String>,
}

/// A single validation issue.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
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
    /// Findings mapped to this control. An excepted finding is kept as
    /// evidence, so a passing control may still be non-empty.
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
    /// Dry-run: `plugins` validated, `would_change` genuinely pending changes,
    /// `compliant` settings already at target (reported, never folded into
    /// `would_change`), `failed` validation errors.
    Validated {
        plugins: usize,
        would_change: usize,
        #[serde(default)]
        compliant: usize,
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
mod apply_change_tests {
    use super::*;

    fn change(change_type: ChangeType, description: &str) -> Change {
        Change {
            change_description: description.to_string(),
            change_type,
            change_success: true,
            change_error: None,
        }
    }

    fn failed_change(change_type: ChangeType, description: &str) -> Change {
        Change {
            change_success: false,
            change_error: Some("nft: command failed".to_string()),
            ..change(change_type, description)
        }
    }

    /// 1 success + 4 failures + 1 skip: the mixed shape the live tour hit.
    fn mixed_result() -> ApplyResult {
        apply_result(vec![
            change(ChangeType::FirewallRule, "set default drop policy"),
            failed_change(ChangeType::FirewallRule, "add ssh allow rule"),
            failed_change(ChangeType::FirewallRule, "add loopback rule"),
            failed_change(ChangeType::FirewallRule, "add established rule"),
            failed_change(ChangeType::FirewallRule, "add icmp rule"),
            change(ChangeType::Skipped, "stateful by default"),
        ])
    }

    fn apply_result(changes: Vec<Change>) -> ApplyResult {
        ApplyResult {
            apply_plugin_id: PluginId::new("test"),
            apply_success: true,
            apply_changes: changes,
            apply_checkpoint_id: None,
            apply_error: None,
        }
    }

    #[test]
    fn applied_change_count_excludes_skipped() {
        let result = apply_result(vec![
            change(ChangeType::ConfigFile, "wrote sshd_config"),
            change(ChangeType::Skipped, "no MAC system detected"),
        ]);
        assert_eq!(result.applied_change_count(), 1);
    }

    #[test]
    fn applied_change_count_all_applied() {
        let result = apply_result(vec![
            change(ChangeType::ConfigFile, "wrote sshd_config"),
            change(ChangeType::Service, "restarted sshd"),
        ]);
        assert_eq!(result.applied_change_count(), 2);
    }

    #[test]
    fn applied_change_count_all_skipped() {
        let result = apply_result(vec![change(ChangeType::Skipped, "no MAC system detected")]);
        assert_eq!(result.applied_change_count(), 0);
    }

    #[test]
    fn applied_change_count_excludes_failures() {
        assert_eq!(mixed_result().applied_change_count(), 1);
    }

    #[test]
    fn failed_change_count_excludes_skips_and_successes() {
        assert_eq!(mixed_result().failed_change_count(), 4);
    }

    #[test]
    fn skipped_change_count_counts_only_skips() {
        assert_eq!(mixed_result().skipped_change_count(), 1);
    }

    #[test]
    fn is_skipped_reflects_change_type() {
        assert!(change(ChangeType::Skipped, "skip").is_skipped());
        assert!(!change(ChangeType::ConfigFile, "real").is_skipped());
    }

    #[test]
    fn is_checkpoint_reflects_change_type() {
        let cp = change(ChangeType::Checkpoint, "Created checkpoint for rollback");
        assert!(cp.is_checkpoint());
        assert!(!cp.is_skipped());
        assert!(!change(ChangeType::ConfigFile, "real").is_checkpoint());
    }

    /// A checkpoint entry is bookkeeping: with 3 successes and 1 failure
    /// alongside it, applied is 3 and failed is 1, never 4 or 5.
    #[test]
    fn counts_exclude_checkpoint_bookkeeping() {
        let result = apply_result(vec![
            change(ChangeType::Checkpoint, "Created checkpoint for rollback"),
            change(ChangeType::KernelParameter, "set kptr_restrict"),
            change(ChangeType::KernelParameter, "set dmesg_restrict"),
            change(ChangeType::ConfigFile, "wrote 99-hardening.conf"),
            failed_change(ChangeType::KernelParameter, "set bpf_hardened"),
        ]);
        assert_eq!(result.applied_change_count(), 3);
        assert_eq!(result.failed_change_count(), 1);
        assert_eq!(result.skipped_change_count(), 0);
    }

    /// A plugin whose only recorded action was the checkpoint hardened nothing.
    #[test]
    fn checkpoint_only_result_counts_zero_applied() {
        let result = apply_result(vec![change(
            ChangeType::Checkpoint,
            "Created checkpoint for rollback",
        )]);
        assert_eq!(result.applied_change_count(), 0);
        assert_eq!(result.failed_change_count(), 0);
        assert_eq!(result.skipped_change_count(), 0);
    }
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
                compliant: 0,
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
            scan_unchecked: vec![],
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

#[cfg(test)]
mod serde_compatibility_tests {
    use super::*;

    #[test]
    fn scan_result_deserialises_without_unchecked_field() {
        let old_json = r#"{
            "scan_plugin_id": "kernel-hardening",
            "scan_success": true,
            "scan_findings": [],
            "scan_duration_us": 42,
            "scan_error": null
        }"#;
        let result: ScanResult = serde_json::from_str(old_json).expect("old JSON must parse");
        assert!(result.scan_unchecked.is_empty());
    }

    #[test]
    fn unchecked_check_round_trips() {
        let check = UncheckedCheck {
            unchecked_check_id: "pam-minlen".to_string(),
            unchecked_title: "PAM setting: minlen".to_string(),
            unchecked_category: FindingCategory::Authentication,
            unchecked_reason: "reading /etc/security/pwquality.conf requires root".to_string(),
            unchecked_compliance: vec![],
        };
        let json = serde_json::to_string(&check).unwrap();
        let back: UncheckedCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(back.unchecked_check_id, check.unchecked_check_id);
    }
}

#[cfg(test)]
mod policy_exception_tests {
    use super::*;

    fn finding(severity: Severity, excepted: bool) -> Finding {
        Finding {
            finding_category: FindingCategory::Network,
            finding_current_value: String::new(),
            finding_description: String::new(),
            finding_explanation: String::new(),
            finding_id: "test".to_string(),
            finding_impact: String::new(),
            finding_recommended_value: String::new(),
            finding_remediation_steps: Vec::new(),
            finding_severity: severity,
            finding_title: "Test".to_string(),
            finding_compliance: Vec::new(),
            finding_policy_exception: excepted.then(FindingPolicyException::default),
        }
    }

    /// The whole point of the label: a deviation the operator documented must
    /// not read as a violation, and must not vanish either.
    #[test]
    fn a_documented_deviation_is_not_labelled_as_a_violation() {
        let excepted = finding(Severity::Critical, true);
        assert!(excepted.is_policy_excepted());
        assert_eq!(excepted.evidence_label(), POLICY_EXCEPTION_LABEL);
    }

    #[test]
    fn a_live_violation_keeps_its_severity() {
        let live = finding(Severity::Critical, false);
        assert!(!live.is_policy_excepted());
        assert_eq!(live.evidence_label(), "CRITICAL");
    }
}
