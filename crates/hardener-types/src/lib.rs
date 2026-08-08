//! Shared type definitions for Linux Hardener.
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

/// Why a configured policy exception did not apply to a finding.
///
/// Each variant carries the values that variant needs rather than sharing one
/// flat set of fields. The four plugins asking a presence question (services,
/// mac, audit, firewall) have no observed value to name, so a shared
/// `observed: Option<String>` would be `None` for every expiry and would mean
/// different things in different arms. See [`EXCEPTION_OBSERVED_UNCHANGED`],
/// which documents the same asymmetry from the other side.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "cause", rename_all = "lowercase")]
pub enum DeclineReason {
    /// The exception documents a value the host does not have.
    ValueMismatch {
        /// The value the exception says the host keeps.
        documented: String,
        /// The value actually read from the host.
        observed: String,
    },
    /// The exception passed its expiry date and stopped applying.
    Expired {
        /// The `expires` date the exception carried, ISO 8601.
        expired_on: String,
    },
}

/// A policy exception that was configured, was allowed, and did not apply.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FindingExceptionDeclined {
    /// Why it did not apply, with the values that reason needs.
    pub exception_declined_reason: DeclineReason,
    /// The operator's own `reason` text, so they can tell which exception of
    /// several this was without opening the config.
    pub exception_reason: String,
}

/// What the configuration had to say about a finding.
///
/// This replaced an `Option<FindingPolicyException>` that had to stand for two
/// situations needing opposite advice: no exception was configured, and an
/// exception was configured and did not apply. Only the first is true of most
/// findings carrying `None`, and an operator whose exception silently did
/// nothing was told nothing at all.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum ExceptionOutcome {
    /// No exception names this check, or one does and sets `allowed = false`,
    /// which is the operator saying not to treat it as an exception.
    #[default]
    NotConfigured,
    /// An exception applied. The finding is a documented deviation.
    Applied(FindingPolicyException),
    /// An exception was configured and did not apply. The finding is live.
    Declined(FindingExceptionDeclined),
}

/// One line saying an exception did not apply, and why.
///
/// Shared for the same reason [`exception_preview_line`] is shared: hand-written
/// copies of one sentence are how one ends up worded differently, or omitted.
pub fn exception_declined_line(declined: &FindingExceptionDeclined) -> String {
    let cause = match &declined.exception_declined_reason {
        DeclineReason::ValueMismatch {
            documented,
            observed,
        } => format!("documents '{documented}', host has '{observed}'"),
        DeclineReason::Expired { expired_on } => format!("expired {expired_on}"),
    };
    format!(
        "exception not applied: {cause} ({}: {})",
        POLICY_EXCEPTION_LABEL, declined.exception_reason
    )
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

/// What stopped a check from being evaluated, as far as the producer could
/// tell.
///
/// This replaced a boolean that had to stand for two situations needing
/// opposite advice: the process was not privileged and a privileged re-run
/// would reach the check, or the process was already privileged and something
/// else blocked it, so a privileged re-run would change nothing. There was
/// nowhere to record the second, and four producers asserted the first
/// unconditionally, so an operator was sent after a remedy that could not work.
///
/// The measurement that settled it: `systemd-nspawn` grants `CAP_NET_ADMIN`
/// only to a container with its own network namespace, so the firewall plugin
/// running as uid 0 reported "requires root" for a check whose real blocker was
/// a missing capability. `CapEff` reads `fdecbfff` with `--network-veth` and
/// `fdecafff` without, one bit apart, and `iptables -L` returns 4 either way to
/// a process that cannot see the tables.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum UncheckedBlocker {
    /// The session is not privileged, and a privileged re-run would reach this
    /// check. This is the only variant that makes a renderer offer sudo.
    Privilege,
    /// Privilege is not what is missing. A capability the process does not
    /// hold, a filesystem that cannot express the thing being asked about, a
    /// tool that is not installed, a parameter this kernel does not carry: all
    /// of them survive a privileged re-run unchanged.
    Environment,
    /// The producer did not determine which, so nothing is claimed and no
    /// remedy is offered. The default, deliberately: a wrong remedy costs an
    /// operator more than a missing one.
    #[default]
    Unknown,
}

/// A check the scanner could not evaluate.
///
/// Unchecked entries are not findings: they carry no severity, never enter
/// the security score, and map to `ManualReview` in compliance reports.
/// `unchecked_check_id` equals the `finding_id` the check would produce if it
/// failed, so consumers can correlate the two.
///
/// Privilege is one cause among several, not the definition. A plugin the
/// operator disabled, a filesystem with no POSIX modes and a probe that failed
/// for its own reasons all land here too, and sudo helps with none of them.
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
    /// What stopped the check, as far as the producer could tell.
    ///
    /// The producer is the only place that knows. `unchecked_reason` is prose
    /// for an operator, so a renderer wanting to offer "run with sudo" had to
    /// either assert privilege for every entry, which is what four of them did,
    /// or guess from the wording, which is worse.
    ///
    /// Defaults to [`UncheckedBlocker::Unknown`] on deserialisation, which is
    /// also what a scan persisted under the previous boolean field now reads
    /// as. That is lossy in one direction on purpose: an old entry that said
    /// `true` becomes "not determined" rather than keeping a claim four
    /// producers were making without checking. Claiming nothing costs an
    /// operator a remedy they might have wanted; claiming wrongly costs them a
    /// run that cannot help.
    #[serde(default)]
    pub unchecked_blocker: UncheckedBlocker,
    /// Compliance mappings the check covers (drives ManualReview).
    pub unchecked_compliance: Vec<ComplianceMapping>,
}

/// How many checks a run could not evaluate, and how many of those a
/// privileged re-run could reach.
///
/// The counting is split out from [`unchecked_summary`] because the desktop
/// asks the same question and cannot use a sentence for its answer: it offers a
/// button, and a button must appear only when pressing it would change
/// something.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UncheckedTally {
    /// Every check the run could not evaluate, whatever the cause.
    pub total: usize,
    /// Those whose producer said a privileged re-run would reach them.
    pub needing_privilege: usize,
}

impl UncheckedTally {
    /// Counts a run's unchecked checks.
    ///
    /// Takes an iterator rather than a slice so the scan footer, which
    /// summarises every plugin's entries at once, does not have to collect
    /// them first.
    pub fn from_checks<'a>(unchecked: impl IntoIterator<Item = &'a UncheckedCheck>) -> Self {
        unchecked
            .into_iter()
            .fold(Self::default(), |tally, check| Self {
                total: tally.total + 1,
                // Only `Privilege` counts. `Environment` and `Unknown` are both
                // "sudo will not help", for different reasons, and the tally's
                // one job is deciding whether to offer it.
                needing_privilege: tally.needing_privilege
                    + usize::from(check.unchecked_blocker == UncheckedBlocker::Privilege),
            })
    }

    /// Whether offering a privileged re-run would change anything.
    ///
    /// The one place that decision is made, so a renderer cannot come to
    /// offer sudo for a run sudo cannot help.
    pub fn privilege_would_help(&self) -> bool {
        self.needing_privilege > 0
    }
}

/// The one-line roll-up describing a run's unchecked checks, or `None` when
/// there are none to describe.
///
/// One definition because four renderers each grew their own, and every one of
/// them named root as the cause of every entry. Sudo is offered only for the
/// entries whose producer said it would help, so a run that could not check
/// something for a reason privilege cannot touch no longer sends the operator
/// to a remedy that changes nothing.
pub fn unchecked_summary<'a>(
    unchecked: impl IntoIterator<Item = &'a UncheckedCheck>,
) -> Option<String> {
    let tally = UncheckedTally::from_checks(unchecked);
    match (tally.total, tally.needing_privilege) {
        (0, _) => None,
        (total, 0) => Some(format!("{total} check(s) could not be verified")),
        (total, privileged) if privileged == total => Some(format!(
            "{total} check(s) require root; run with sudo for a full scan"
        )),
        (total, privileged) => Some(format!(
            "{total} check(s) could not be verified, {privileged} of them for want of root; \
             run with sudo for a fuller scan"
        )),
    }
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
    /// What the configuration had to say about this finding: nothing, an
    /// exception that applied, or an exception that did not.
    pub finding_exception: ExceptionOutcome,
    /// The `exceptions` key an operator writes to accept this finding as a
    /// documented deviation, where one would mean anything.
    ///
    /// [`Finding::finding_id`] cannot serve here: every plugin builds it from
    /// this key with a lossy transform, so `service_some_service` names either
    /// `some-service` or `some_service` and nothing can say which. Deriving
    /// the key back out of an id is therefore impossible, and it has to be
    /// carried.
    ///
    /// `None` where an exception would change nothing, which happens for two
    /// distinct reasons and both are correct. The plugin may consult no
    /// exception for this finding at all, as with the PAM layer-drift
    /// findings, which name a set of masked keys rather than one directive. Or
    /// the finding may not be about a value: PAM reports a directive that is
    /// already set correctly and simply unreadable by anything on the host,
    /// and an exception documents a value an operator accepts, so there is
    /// nothing for one to say.
    pub finding_exception_key: Option<String>,
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

/// What stands in the observed slot of [`exception_preview_line`] where the
/// plugin has no host reading to put there.
///
/// For `[services]`, `[mac]`, `[audit]` and `[firewall]` the exception key
/// already names the deviating item and there is no single system value to
/// compare, so the exception's own `value` field is advisory: recorded in the
/// audit trail and never matched against anything. Echoing that field into a
/// slot documented as the value the host keeps prints an operator's own text
/// as a reading taken from their machine, which is false exactly when the
/// declaration is stale. Naming what the run did to the setting claims
/// nothing the plugin cannot vouch for.
///
/// `[firewall]` spells its own stand-in at the site, because a rule that was
/// not applied is a different statement from a state left alone.
pub const EXCEPTION_OBSERVED_UNCHANGED: &str = "unchanged";

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
        matches!(self.finding_exception, ExceptionOutcome::Applied(_))
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
/// `/etc/sysctl.d`, `/etc/security` and `/etc/audit/rules.d` are the three
/// entries an apply can create, and they carry their own reasoning. None can be
/// recorded absent by the apply that creates it, for two different reasons: the
/// kernel and audit plugins create `/etc/sysctl.d` and `/etc/audit/rules.d`
/// above their own checkpoints, which capture those directories, so each
/// capture records its own as present; the pam plugin creates `/etc/security`
/// from its shared file writer and needs no such ordering, because no plugin
/// captures that directory at all, so no apply ever writes a row for it. All
/// three entries stay as a backstop for a checkpoint that did record one
/// absent, whether taken before that ordering existed or by `checkpoint
/// create`, whose own path list holds all three directories: the host has since
/// gained the directory, and deleting one the distribution shares between
/// packages would be far worse than leaving an empty one behind.
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
    "/etc/selinux/config",
    // `/etc/nftables.conf` is deliberately NOT here, and was removed from this
    // list when the nftables backend started rendering its whole ruleset into
    // that file and loading it: an apply creates it on every host that never
    // had one, which is exactly the membership rule's disqualifying condition.
    // Protecting it would leave the rendered ruleset on disk with
    // `nftables.service` enabled by the same apply, so the posture the operator
    // rolled back would return at the next boot. An earlier wording added that
    // the plugin's own `reload_after_rollback` would load it straight back in;
    // that route closed when the checkpoint was scoped to the selected
    // backend's own paths, so the next boot is the reason that stands. Same
    // precedent as the ssh and kernel drop-ins, each of which states the rule
    // at its own checkpoint call.
    // `/etc/linux-hardener/nftables/50-linux-hardener.nft` is excluded for
    // the same reason as `/etc/nftables.conf` above: an apply creates that
    // fragment, so a checkpoint row recording it absent is an instruction to
    // delete it on rollback. Protecting it would leave the applied ruleset
    // sitting on disk after an undo, which is the exact outcome this list
    // exists to prevent. Do not add it here.
    // Directories the plugins write files into, or capture and never touch.
    // `write_file` cannot create a missing parent, so a plugin whose target
    // directory may be absent creates it first: the kernel and audit applies
    // run `mkdir` for /etc/sysctl.d and /etc/audit/rules.d ahead of their
    // checkpoints, the pam apply runs one for /etc/security before creating a
    // file in it, and no other apply creates any of these.
    "/etc/sysctl.d",
    "/etc/pam.d",
    "/etc/security",
    "/etc/audit/rules.d",
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

/// Outcome of asking one plugin to re-read configuration a rollback restored.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReloadResult {
    /// Plugin that was asked to reload.
    pub reload_plugin_id: String,
    /// What was done, in the operator's words: "sshd restarted".
    pub reload_action: String,
    /// Whether the reload succeeded.
    pub reload_success: bool,
    /// Error message if the reload failed.
    pub reload_error: Option<String>,
}

/// Whether a subject came back, or could not be shown to have come back.
///
/// Two variants and no `Converged`, deliberately. A plugin emits a row for
/// every subject it examined and could not confirm returned, so an empty
/// vector has a defined meaning: everything checkable came back, and
/// everything uncheckable carries an `Unverifiable` row. Silence never
/// stands for "nobody looked", which is the conflation the checkpoint work
/// and the pam-unreadable-config arc both existed to remove.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub enum DivergenceState {
    /// Measured: the running system disagrees with the restored configuration.
    Diverged,
    /// The probe could not answer. Not a claim that anything is wrong.
    Unverifiable,
}

/// One thing a rollback knowingly left diverged, or could not check.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RollbackDivergence {
    /// Plugin that took the reading.
    pub divergence_plugin_id: String,
    /// What was examined: "net.ipv4.conf.all.log_martians", "ufw".
    pub divergence_subject: String,
    /// Measured divergence, or an unanswerable probe.
    pub divergence_state: DivergenceState,
    /// The operator's sentence, carrying both values where the probe has them.
    pub divergence_detail: String,
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
    /// Per-plugin reload results. Empty when no restored path needed a reload,
    /// and empty when the payload came from a release that predates them.
    #[serde(default)]
    pub rollback_reloads: Vec<ReloadResult>,
    /// What the rollback left diverged from the configuration it restored,
    /// and what it could not check. Empty when every subject examined came
    /// back. Reporting only: nothing may branch on this, because a branch is
    /// how reporting turns into behaviour.
    #[serde(default)]
    pub rollback_divergences: Vec<RollbackDivergence>,
}

impl RollbackResult {
    /// Whether every reload that was attempted succeeded.
    ///
    /// Vacuously true when none was attempted, which is what makes a payload
    /// from an older binary read as "nothing failed" rather than as a failure.
    /// Derived rather than stored: two fields that must agree can disagree.
    pub fn reloads_ok(&self) -> bool {
        self.rollback_reloads.iter().all(|r| r.reload_success)
    }
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

impl ValidationReport {
    /// Whether this report carries an issue serious enough to fail a dry run.
    ///
    /// **Critical and High only.** Lower severities are advisory, and promoting
    /// them would turn an informational note into a non-zero exit, which trains
    /// operators to ignore the exit code entirely.
    ///
    /// This is not the same question as `validation_report_is_valid`, which is
    /// `issues.is_empty()` and answers "has this report anything to say". A
    /// renderer deciding whether to show a clean marker wants that one; anything
    /// deciding whether a run **failed** wants this one.
    ///
    /// It lives on the type because the two callers that ask it are in
    /// different command modules and had drifted: the single-host dry run
    /// applied the Critical-or-High rule while the fleet path counted any issue
    /// at all, so one host, one report and two verbs gave exit 0 and exit 1. A
    /// Medium note is not hypothetical: PAM layer drift emits one on every host
    /// whose `/etc` file masks its vendor copy.
    pub fn has_blocking_issue(&self) -> bool {
        self.validation_report_issues.iter().any(|issue| {
            matches!(
                issue.validation_issue_severity,
                Severity::Critical | Severity::High
            )
        })
    }
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

/// One control's verdict on a fleet host, without the findings that produced
/// it.
///
/// This is [`ControlResult`] minus `control_findings`, and the omission is the
/// point. A control's findings are selected by a pure filter on each finding's
/// own `finding_compliance` mappings, so a consumer holding the host's
/// `scan_results` can reproduce them exactly with the same filter, and no
/// backend judgement is duplicated by doing so. What cannot be reproduced is
/// the [`ControlStatus`], which needs the exception and coverage logic the
/// report generator owns, so that is what travels.
///
/// Measured on one host across the nine fleet frameworks, 145 controls: these
/// rows are 23 KB where the full `ControlResult`s are 222 KB, against a fleet
/// response already carrying 122 KB of `scan_results` per host. Carrying the
/// findings twice would have roughly tripled a per-host payload that is sent
/// whether or not anyone drills into it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ControlOutcome {
    /// The control identifier (e.g. "1.5.1" for CIS).
    pub control_id: String,
    /// Human-readable title of the control.
    pub control_title: String,
    /// Section/category within the framework.
    pub control_section: String,
    /// Whether the control passed, failed, or needs manual review.
    pub control_status: ControlStatus,
}

impl From<&ControlResult> for ControlOutcome {
    fn from(result: &ControlResult) -> ControlOutcome {
        ControlOutcome {
            control_id: result.control_id.clone(),
            control_title: result.control_title.clone(),
            control_section: result.control_section.clone(),
            control_status: result.control_status.clone(),
        }
    }
}

/// One framework's compliance posture for a fleet host: the summary, plus one
/// verdict per control so the count can be drilled into.
///
/// The findings behind each verdict are not here. They already travel in
/// `FleetHostScan::scan_results`, and [`ControlOutcome`] says how to get from
/// one to the other.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FleetFrameworkPosture {
    /// The framework this posture is for.
    pub framework: ComplianceFramework,
    /// Pass/fail/manual/NA counts and the overall score.
    pub summary: ComplianceSummary,
    /// One verdict per control the summary counted, in the generator's own
    /// order.
    pub controls: Vec<ControlOutcome>,
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
    /// `reload_failed` is the subset of `failed` whose files came back but
    /// whose plugin would not reload them, so an operator reading the count
    /// can tell that failure apart from a file that never came back at all.
    RolledBack {
        restored: usize,
        failed: usize,
        #[serde(default)]
        reload_failed: usize,
    },
    /// No matching checkpoint for the selected plugins on this host.
    NothingToDo,
    /// Host-level error (connect / not privileged / selection query / usage).
    Failed { error: String },
}

/// How a fleet rollback names the failed half of a host's outcome.
///
/// One sentence for both surfaces. The CLI's text report and the desktop's
/// fleet table draw the same distinction, because it is the distinction an
/// operator acts on: a file that never came back needs the checkpoint looking
/// at, whereas a file that came back to a service that would not reload it
/// needs the service looking at. Written twice and kept in step by a comment,
/// the two wordings could drift; `hardener-cli` is a binary so the desktop
/// cannot borrow from it, and this crate is the one both already depend on.
pub fn rollback_failed_label(failed: usize, reload_failed: usize) -> String {
    match reload_failed {
        0 => format!("{failed} failed"),
        _ => format!("{failed} failed ({reload_failed} due to reload)"),
    }
}

#[cfg(test)]
mod tests;
