//! Common types used across the hardening tool.
//!
//! Defines core types for plugins, findings, severity levels, and compliance frameworks.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for a hardening plugin.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct PluginId(String);

impl PluginId {
    /// Creates a new PluginId from a string.
    ///
    /// # Examples
    /// ```
    /// use hardener_common::types::PluginId;
    ///
    /// let id = PluginId::new("ssh_hardening");
    /// ```
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
///
/// This provides an audit trail for intentional deviations from security baselines.
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
