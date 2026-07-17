//! Audit Rules Plugin
//!
//! This plugin configures the Linux audit daemon (auditd) to monitor critical
//! system events for security compliance and intrusion detection.
//!
//! Monitors:
//! - Time changes
//! - User/Group modifications
//! - Network configuration changes
//! - Permission modifications
//! - Privileged command execution
//! - File deletions
//! - Kernel module operations

use async_trait::async_trait;
use hardener_common::{
    error::Result,
    types::{ComplianceFramework, ComplianceMapping, FindingCategory, PluginId, Severity},
};
use hardener_core::{
    ApplyResult, Change, ChangeType, Checkpoint, PluginConfig, ValidationIssue, ValidationReport,
    context::Context,
    plugin::{Finding, HardeningPlugin, PluginMetadata, ScanResult},
};
use std::{path::Path, time::Instant};
use tracing::{info, warn};

/// Audit Hardening Plugin
///
/// Configures auditd rules for comprehensive system monitoring and compliance.
pub struct AuditHardeningPlugin {}

impl Default for AuditHardeningPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditHardeningPlugin {
    /// Creates a new instance of the Audit Hardening Plugin.
    pub fn new() -> AuditHardeningPlugin {
        AuditHardeningPlugin {}
    }
}

/// Represents a single audit rule directive.
///
/// Each directive defines one audit rule with its category, content, finding_description, and severity.
#[derive(Clone, Debug)]
struct AuditRuleDirective {
    audit_rule_category: &'static str,
    audit_rule_content: &'static str,
    audit_rule_description: &'static str,
    audit_rule_severity: Severity,
}

/// Comprehensive audit rules for system security monitoring.
///
/// These rules monitor critical system events and are based on CIS Benchmark
/// and NIS2 compliance requirements.
const AUDIT_RULES: &[AuditRuleDirective] = &[
    // ============================================================================
    // TIME CHANGES - Monitor system time modifications
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category: "time-change",
        audit_rule_content: "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change",
        audit_rule_description: "Monitor system time modifications (64-bit)",
        audit_rule_severity: Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category: "time-change",
        audit_rule_content: "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change",
        audit_rule_description: "Monitor system time modifications (32-bit)",
        audit_rule_severity: Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category: "time-change",
        audit_rule_content: "-a always,exit -F arch=b64 -S clock_settime -k time-change",
        audit_rule_description: "Monitor clock_settime syscall (64-bit)",
        audit_rule_severity: Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category: "time-change",
        audit_rule_content: "-w /etc/localtime -p wa -k time-change",
        audit_rule_description: "Monitor timezone configuration changes",
        audit_rule_severity: Severity::Medium,
    },
    // ============================================================================
    // IDENTITY - Monitor user and group modifications
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category: "identity",
        audit_rule_content: "-w /etc/passwd -p wa -k identity",
        audit_rule_description: "Monitor user account file modifications",
        audit_rule_severity: Severity::Critical,
    },
    AuditRuleDirective {
        audit_rule_category: "identity",
        audit_rule_content: "-w /etc/shadow -p wa -k identity",
        audit_rule_description: "Monitor password hash file modifications",
        audit_rule_severity: Severity::Critical,
    },
    AuditRuleDirective {
        audit_rule_category: "identity",
        audit_rule_content: "-w /etc/group -p wa -k identity",
        audit_rule_description: "Monitor group account file modifications",
        audit_rule_severity: Severity::Critical,
    },
    AuditRuleDirective {
        audit_rule_category: "identity",
        audit_rule_content: "-w /etc/gshadow -p wa -k identity",
        audit_rule_description: "Monitor group password file modifications",
        audit_rule_severity: Severity::Critical,
    },
    AuditRuleDirective {
        audit_rule_category: "identity",
        audit_rule_content: "-w /etc/security/opasswd -p wa -k identity",
        audit_rule_description: "Monitor password history file modifications",
        audit_rule_severity: Severity::High,
    },
    // ============================================================================
    // NETWORK CHANGES - Monitor network configuration
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category: "network-change",
        audit_rule_content: "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network-change",
        audit_rule_description: "Monitor hostname and domain name changes (64-bit)",
        audit_rule_severity: Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category: "network-change",
        audit_rule_content: "-w /etc/hosts -p wa -k network-change",
        audit_rule_description: "Monitor hosts file modifications",
        audit_rule_severity: Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category: "network-change",
        audit_rule_content: "-w /etc/network/ -p wa -k network-change",
        audit_rule_description: "Monitor network configuration directory",
        audit_rule_severity: Severity::Medium,
    },
    // ============================================================================
    // PERMISSION MODIFICATIONS - Monitor file permission and ownership changes
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category: "perm-mod",
        audit_rule_content: "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm-mod",
        audit_rule_description: "Monitor file permission changes (64-bit)",
        audit_rule_severity: Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category: "perm-mod",
        audit_rule_content: "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -k perm-mod",
        audit_rule_description: "Monitor file permission changes (32-bit)",
        audit_rule_severity: Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category: "perm-mod",
        audit_rule_content: "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -k perm-mod",
        audit_rule_description: "Monitor file ownership changes (64-bit)",
        audit_rule_severity: Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category: "perm-mod",
        audit_rule_content: "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -k perm-mod",
        audit_rule_description: "Monitor file ownership changes (32-bit)",
        audit_rule_severity: Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category: "perm-mod",
        audit_rule_content: "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -k perm-mod",
        audit_rule_description: "Monitor extended attribute changes (64-bit)",
        audit_rule_severity: Severity::Medium,
    },
    // ============================================================================
    // PRIVILEGED COMMANDS - Monitor execution of privileged commands
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category: "privileged",
        audit_rule_content: "-w /usr/bin/sudo -p x -k privileged",
        audit_rule_description: "Monitor sudo command execution",
        audit_rule_severity: Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category: "privileged",
        audit_rule_content: "-w /usr/bin/su -p x -k privileged",
        audit_rule_description: "Monitor su command execution",
        audit_rule_severity: Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category: "privileged",
        audit_rule_content: "-w /usr/bin/passwd -p wa -k privileged",
        audit_rule_description: "Monitor passwd command execution",
        audit_rule_severity: Severity::Medium,
    },
    // ============================================================================
    // FILE DELETION - Monitor file and directory deletion
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category: "delete",
        audit_rule_content: "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete",
        audit_rule_description: "Monitor file deletion operations (64-bit)",
        audit_rule_severity: Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category: "delete",
        audit_rule_content: "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -k delete",
        audit_rule_description: "Monitor file deletion operations (32-bit)",
        audit_rule_severity: Severity::Medium,
    },
    // ============================================================================
    // KERNEL MODULES - Monitor kernel module operations
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category: "modules",
        audit_rule_content: "-w /sbin/insmod -p x -k modules",
        audit_rule_description: "Monitor kernel module insertion",
        audit_rule_severity: Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category: "modules",
        audit_rule_content: "-w /sbin/rmmod -p x -k modules",
        audit_rule_description: "Monitor kernel module removal",
        audit_rule_severity: Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category: "modules",
        audit_rule_content: "-w /sbin/modprobe -p x -k modules",
        audit_rule_description: "Monitor modprobe execution",
        audit_rule_severity: Severity::High,
    },
];

/// Path to custom audit rules file for hardening.
const AUDIT_RULES_PATH: &str = "/etc/audit/rules.d/hardening.rules";

/// ============================================================================
/// AUDITD HELPER FUNCTIONS
/// ============================================================================
/// Checks if auditd is installed on the system.
async fn is_auditd_installed(ctx: &Context) -> Result<bool> {
    ctx.executor()
        .command_exists("auditd")
        .await
        .map_err(|e| hardener_common::error::HardeningError::Plugin(e.to_string()))
}

/// Checks if auditd service is enabled to start at boot.
async fn is_auditd_enabled(ctx: &Context) -> Result<bool> {
    let output = ctx
        .executor()
        .execute_command("systemctl", &["is-enabled", "auditd"])
        .await?;
    Ok(output.success())
}

/// Checks if auditd service is currently running.
async fn is_auditd_running(ctx: &Context) -> Result<bool> {
    let output = ctx
        .executor()
        .execute_command("systemctl", &["is-active", "auditd"])
        .await?;
    Ok(output.success())
}

/// Result of reading audit rules - distinguishes success from permission error.
enum AuditRulesResult {
    /// Successfully read rules (may be empty if no rules configured).
    Rules(Vec<String>),
    /// Permission denied - cannot determine rule state.
    PermissionDenied,
}

/// Reads current audit rules from the system using auditctl.
///
/// Returns `AuditRulesResult` to distinguish between "no rules" and "permission denied".
async fn read_current_audit_rules(ctx: &Context) -> AuditRulesResult {
    let output = match ctx.executor().execute_command("auditctl", &["-l"]).await {
        Ok(output) => output,
        Err(_) => return AuditRulesResult::PermissionDenied,
    };

    // Check for permission denied in stderr or non-zero exit.
    if !output.success() {
        if output.stderr.contains("root") || output.stderr.contains("permission") {
            return AuditRulesResult::PermissionDenied;
        }
        // Other failure - treat as empty rules (conservative).
        return AuditRulesResult::Rules(Vec::new());
    }

    let rules = output
        .stdout
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.starts_with("No rules"))
        .collect();

    AuditRulesResult::Rules(rules)
}

/// Writes audit rules to the hardening rules file with backup.
async fn write_audit_rules_file(ctx: &Context, content: &str) -> Result<String> {
    // Create backup with timestamp + random suffix to prevent symlink attacks
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let backup_path = format!("{}.backup.{}.{:08x}", AUDIT_RULES_PATH, timestamp, nonce);

    // Backup existing file if it exists
    if ctx
        .executor()
        .path_exists(Path::new(AUDIT_RULES_PATH))
        .await
        .unwrap_or(false)
    {
        ctx.executor()
            .execute_command("cp", &["--no-dereference", AUDIT_RULES_PATH, &backup_path])
            .await?;
    }

    // Ensure directory exists
    if let Some(parent) = Path::new(AUDIT_RULES_PATH).parent() {
        ctx.executor()
            .execute_command(
                "mkdir",
                &["-p", parent.to_str().unwrap_or("/etc/audit/rules.d")],
            )
            .await?;
    }

    // Write new rules file
    ctx.executor()
        .write_file(Path::new(AUDIT_RULES_PATH), content)
        .await?;

    Ok(backup_path)
}

/// Reloads audit rules into the running daemon.
///
/// Tries `augenrules --load` first (merges rules and loads them without
/// restarting auditd). Falls back to `systemctl restart auditd` if
/// augenrules is unavailable. On many distributions (including Arch),
/// auditd ignores SIGTERM from systemd so a direct restart will fail —
/// augenrules is the supported mechanism.
async fn reload_audit_rules(ctx: &Context) -> Result<()> {
    // Preferred: augenrules merges /etc/audit/rules.d/*.rules and loads them
    if ctx
        .executor()
        .command_exists("augenrules")
        .await
        .unwrap_or(false)
    {
        let output = ctx
            .executor()
            .execute_command("augenrules", &["--load"])
            .await?;

        if output.success() {
            return Ok(());
        }
    }

    // Fallback: systemctl restart (works on some distros)
    let output = ctx
        .executor()
        .execute_command("systemctl", &["restart", "auditd"])
        .await?;

    if !output.success() {
        return Err(hardener_common::error::HardeningError::Plugin(
            "Failed to reload audit rules (augenrules --load and systemctl restart both failed)"
                .to_string(),
        ));
    }

    Ok(())
}

/// Returns compliance mappings for audit findings.
///
/// Multi-framework mappings are sourced from ComplianceAsCode/SSG rule
/// `references:` blocks (see `// SSG:` comments). NIST IDs are 800-53 Rev 5
/// (AU-* audit family); PCI-DSS is v4.0 (Requirement 10 — logging); STIG IDs
/// are the SSG-declared RHEL-family `stigid@ol8` values (the Oracle Linux 8
/// STIG mirrors the RHEL 8 STIG content). STIG is omitted for the generic
/// "rules"/"config" bucket because the concrete `stigid@` differs per audit
/// rule, so no single ID applies.
/// Finding types the audit plugin can raise — the keys understood by
/// [`get_audit_compliance_mappings`]. Keep in sync with that match.
const AUDIT_FINDING_TYPES: &[&str] = &[
    "not_installed",
    "not_enabled",
    "not_running",
    "config",
    "rules",
];

/// Every compliance mapping this plugin can emit, across all finding types it
/// raises. Aggregated into the engine's automated-coverage set.
pub fn coverage() -> Vec<ComplianceMapping> {
    AUDIT_FINDING_TYPES
        .iter()
        .flat_map(|&t| get_audit_compliance_mappings(t))
        .collect()
}

/// Builds a SOC 2 mapping. `id` is a 2017 Trust Services Criteria common
/// criterion (e.g. `CC7.2`); `title` tracks the published criterion text. The
/// section is the criterion's TSC series, derived from the id prefix.
fn soc2(id: &str, title: &str) -> ComplianceMapping {
    let series = if id.starts_with("CC7") {
        "System Operations"
    } else {
        "Logical and Physical Access Controls"
    };
    ComplianceMapping {
        compliance_framework: ComplianceFramework::SOC2,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some(series.to_string()),
    }
}

/// Builds a NIST SP 800-171 Revision 3 mapping. `id` is the requirement
/// number (e.g. `3.3.1`); `title` the published requirement name; the
/// section is the requirement's official family. Every id is translated from
/// this plugin's 800-53 entries via the r3 source-control table — never
/// invented.
fn nist171(id: &str, title: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: ComplianceFramework::NIST800171,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some("Audit and Accountability".to_string()),
    }
}

/// Builds a FedRAMP mapping. FedRAMP's control set is NIST 800-53 at the
/// Moderate (Rev 5) baseline, so `id`/`title` mirror this plugin's 800-53
/// entries verbatim — each id is checked against the GSA rev5 Moderate
/// baseline before it is mapped, never invented. The section is the control's
/// 800-53 family.
fn fedramp(id: &str, title: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: ComplianceFramework::FedRAMP,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some("Audit and Accountability".to_string()),
    }
}

fn get_audit_compliance_mappings(finding_type: &str) -> Vec<ComplianceMapping> {
    match finding_type {
        // SSG: package_audit_installed
        // (nist: AU-2(a),AU-12(2),AU-14,...; pcidss: Req-10.1; stigid@ol8: OL08-00-030180)
        "not_installed" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "4.1.1.1".to_string(),
                compliance_control_title: "Ensure auditd is installed".to_string(),
                compliance_section: Some("Logging and Auditing".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AU-2(a)".to_string(),
                compliance_control_title: "Event Logging".to_string(),
                compliance_section: Some("Audit and Accountability".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::STIG,
                compliance_control_id: "OL08-00-030180".to_string(),
                compliance_control_title: "The audit package must be installed".to_string(),
                compliance_section: Some("Audit and Accountability".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::PCIDSS,
                compliance_control_id: "10.1".to_string(),
                compliance_control_title: "Implement audit trails to link access to system \
                                           components"
                    .to_string(),
                compliance_section: Some("Track and Monitor Access".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(b)".to_string(),
                compliance_control_title: "Audit Controls".to_string(),
                compliance_section: Some("Technical Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.308(a)(1)(ii)(D)".to_string(),
                compliance_control_title: "Information System Activity Review".to_string(),
                compliance_section: Some("Administrative Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-AU".to_string(),
                compliance_control_title: "Audit Logging".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.15".to_string(),
                compliance_control_title: "Logging".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC7.2 mirrors the AU-2 event-logging intent (monitoring capability).
            soc2(
                "CC7.2",
                "Monitor system components for anomalies indicative of malicious acts or errors",
            ),
            // 800-171r3 3.3.1 ← 800-53 AU-2 (SP 800-171r3 source-control table).
            nist171("3.3.1", "Event Logging"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AU-2.
            fedramp("AU-2(a)", "Event Logging"),
        ],
        // SSG: service_auditd_enabled
        // (nist: AU-3,AU-12(c),...; pcidss: Req-10.1; stigid@ol8: OL08-00-030181)
        "not_enabled" | "not_running" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "4.1.1.2".to_string(),
                compliance_control_title: "Ensure auditd service is enabled and running"
                    .to_string(),
                compliance_section: Some("Logging and Auditing".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AU-12(c)".to_string(),
                compliance_control_title: "Audit Record Generation".to_string(),
                compliance_section: Some("Audit and Accountability".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::STIG,
                compliance_control_id: "OL08-00-030181".to_string(),
                compliance_control_title: "The auditd service must be enabled and running"
                    .to_string(),
                compliance_section: Some("Audit and Accountability".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::PCIDSS,
                compliance_control_id: "10.1".to_string(),
                compliance_control_title: "Implement audit trails to link access to system \
                                           components"
                    .to_string(),
                compliance_section: Some("Track and Monitor Access".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(b)".to_string(),
                compliance_control_title: "Audit Controls".to_string(),
                compliance_section: Some("Technical Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.308(a)(1)(ii)(D)".to_string(),
                compliance_control_title: "Information System Activity Review".to_string(),
                compliance_section: Some("Administrative Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-AU".to_string(),
                compliance_control_title: "Audit Logging".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.15".to_string(),
                compliance_control_title: "Logging".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC7.2 mirrors the AU-12 record-generation intent (monitoring runs).
            soc2(
                "CC7.2",
                "Monitor system components for anomalies indicative of malicious acts or errors",
            ),
            // 800-171r3 3.3.3 ← 800-53 AU-12 (SP 800-171r3 source-control table).
            nist171("3.3.3", "Audit Record Generation"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AU-12.
            fedramp("AU-12(c)", "Audit Record Generation"),
        ],
        // SSG: audit_rules_* family (e.g. audit_rules_usergroup_modification_*,
        // audit_rules_dac_modification_*, audit_rules_file_deletion_events_*).
        // The whole family shares nist: AU-12(c),AU-2(d),CM-6(a) and maps to
        // PCI-DSS Requirement 10 (audit trail). The CIS id below is retained
        // from the prior implementation.
        "config" | "rules" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "4.1.2.1".to_string(),
                compliance_control_title: "Ensure audit log storage size is configured".to_string(),
                compliance_section: Some("Logging and Auditing".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AU-12(c)".to_string(),
                compliance_control_title: "Audit Record Generation".to_string(),
                compliance_section: Some("Audit and Accountability".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::PCIDSS,
                compliance_control_id: "10.2.7".to_string(),
                compliance_control_title: "Record audit trail entries for security-relevant events"
                    .to_string(),
                compliance_section: Some("Track and Monitor Access".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(b)".to_string(),
                compliance_control_title: "Audit Controls".to_string(),
                compliance_section: Some("Technical Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.308(a)(1)(ii)(D)".to_string(),
                compliance_control_title: "Information System Activity Review".to_string(),
                compliance_section: Some("Administrative Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-AU".to_string(),
                compliance_control_title: "Audit Logging".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.15".to_string(),
                compliance_control_title: "Logging".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // Audit rules actively monitor security-relevant events → ISO 8.16.
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.16".to_string(),
                compliance_control_title: "Monitoring activities".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            // SOC 2: CC7.1 mirrors the change-detection intent — the rules watch
            // identity files, DAC changes and deletions for configuration change.
            soc2(
                "CC7.1",
                "Detection and monitoring of configuration changes and new vulnerabilities",
            ),
            // SOC 2: CC7.2 mirrors the AU-12 record-generation intent (anomaly analysis).
            soc2(
                "CC7.2",
                "Monitor system components for anomalies indicative of malicious acts or errors",
            ),
            // 800-171r3 3.3.3 ← 800-53 AU-12 (SP 800-171r3 source-control table).
            nist171("3.3.3", "Audit Record Generation"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AU-12.
            fedramp("AU-12(c)", "Audit Record Generation"),
        ],
        _ => vec![],
    }
}

/// ============================================================================
/// HARDENING PLUGIN TRAIT IMPLEMENTATION
/// ============================================================================
#[async_trait]
impl HardeningPlugin for AuditHardeningPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_category: FindingCategory::Audit,
            plugin_description: "Configures Linux audit daemon (auditd) rules for comprehensive system monitoring and compliance".to_string(),
            plugin_id: PluginId::new("audit-hardening"),
            plugin_name: "Audit Rules Hardening".to_string(),
            plugin_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        vec![] // No dependencies
    }

    async fn scan(&self, ctx: &Context) -> Result<ScanResult> {
        let start = Instant::now();
        let mut findings = Vec::new();

        // Check if auditd is installed
        if !is_auditd_installed(ctx).await.unwrap_or(false) {
            findings.push(Finding {
                finding_category: FindingCategory::Audit,
                finding_current_value: "not installed".to_string(),
                finding_description: "Audit daemon (auditd) is not installed".to_string(),
                finding_explanation: "The audit daemon is required for comprehensive system monitoring and compliance".to_string(),
                finding_id: "audit_not_installed".to_string(),
                finding_impact: "No system auditing - security events are not logged".to_string(),
                finding_recommended_value: "installed and running".to_string(),
                finding_remediation_steps: vec![
                    "Install auditd package (apt install auditd / dnf install auditd)".to_string(),
                    "Enable auditd service: systemctl enable auditd".to_string(),
                    "Start auditd service: systemctl start auditd".to_string(),
                ],
                finding_severity: Severity::Critical,
                finding_title: "Audit daemon is not installed".to_string(),
                finding_compliance: get_audit_compliance_mappings("not_installed"),
                finding_policy_exception: None,
            });

            // If not installed, no point checking further
            return Ok(ScanResult {
                scan_duration_us: start.elapsed().as_micros() as u64,
                scan_error: None,
                scan_findings: findings,
                scan_plugin_id: self.metadata().plugin_id,
                scan_success: true,
            });
        }

        // Check if auditd is enabled
        if !is_auditd_enabled(ctx).await.unwrap_or(false) {
            findings.push(Finding {
                finding_category: FindingCategory::Audit,
                finding_current_value: "disabled".to_string(),
                finding_description: "Audit daemon is not enabled to start at boot".to_string(),
                finding_explanation:
                    "Auditd should be enabled to ensure audit logging starts automatically"
                        .to_string(),
                finding_id: "audit_not_enabled".to_string(),
                finding_impact: "Audit logging may not start after reboot".to_string(),
                finding_recommended_value: "enabled".to_string(),
                finding_remediation_steps: vec!["systemctl enable auditd".to_string()],
                finding_severity: Severity::High,
                finding_title: "Audit daemon not enabled".to_string(),
                finding_compliance: get_audit_compliance_mappings("not_enabled"),
                finding_policy_exception: None,
            });
        }

        // Check if auditd is running
        if !is_auditd_running(ctx).await.unwrap_or(false) {
            findings.push(Finding {
                finding_category: FindingCategory::Audit,
                finding_current_value: "stopped".to_string(),
                finding_description: "Audit daemon is not currently running".to_string(),
                finding_explanation: "Auditd must be running".to_string(),
                finding_id: "auditd_not_running".to_string(),
                finding_impact: "No audit events are being collected".to_string(),
                finding_recommended_value: "running".to_string(),
                finding_remediation_steps: vec!["systemctl start auditd".to_string()],
                finding_severity: Severity::High,
                finding_title: "Audit daemon not running".to_string(),
                finding_compliance: get_audit_compliance_mappings("not_running"),
                finding_policy_exception: None,
            });
        }

        // Check current audit rules.
        // Handle permission denied separately to avoid false positives.
        match read_current_audit_rules(ctx).await {
            AuditRulesResult::Rules(current_rules) => {
                // Successfully read rules - check each required rule.
                for rule in AUDIT_RULES {
                    // Check if this rule category is present in current rules.
                    let rule_exists = current_rules
                        .iter()
                        .any(|current_rule| current_rule.contains(rule.audit_rule_category));

                    if !rule_exists {
                        findings.push(Finding {
                            finding_category: FindingCategory::Audit,
                            finding_current_value: "not configured".to_string(),
                            finding_description: rule.audit_rule_description.to_string(),
                            finding_explanation: format!(
                                "Audit rule for {} is not configured. This rule monitors: {}",
                                rule.audit_rule_category, rule.audit_rule_description
                            ),
                            finding_id: format!(
                                "audit_rule_{}",
                                rule.audit_rule_category.replace('-', "_")
                            ),
                            finding_impact:
                                "Security events in this category are not being audited"
                                    .to_string(),
                            finding_recommended_value: rule.audit_rule_content.to_string(),
                            finding_remediation_steps: vec![
                                format!("Add rule: {}", rule.audit_rule_content),
                                "Restart auditd: systemctl restart auditd".to_string(),
                            ],
                            finding_severity: rule.audit_rule_severity,
                            finding_title: format!(
                                "Missing audit rule: {}",
                                rule.audit_rule_category
                            ),
                            finding_compliance: get_audit_compliance_mappings("rules"),
                            finding_policy_exception: None,
                        });
                    }
                }
            }
            AuditRulesResult::PermissionDenied => {
                // Cannot verify rules - log warning, don't create false findings.
                warn!("Cannot verify audit rules: permission denied (requires root)");
            }
        }
        Ok(ScanResult {
            scan_duration_us: start.elapsed().as_micros() as u64,
            scan_error: None,
            scan_findings: findings,
            scan_plugin_id: self.metadata().plugin_id,
            scan_success: true,
        })
    }

    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> {
        let mut changes = Vec::new();

        // Create checkpoint before changes
        let audit_paths: Vec<&Path> = vec![
            Path::new("/etc/audit/auditd.conf"),
            Path::new("/etc/audit/rules.d"),
        ];
        let checkpoint_id =
            crate::create_checkpoint_for_apply(ctx, "audit-hardening-pre-apply", &audit_paths)
                .await?;

        if checkpoint_id.is_some() {
            changes.push(Change {
                change_type: ChangeType::ConfigFile,
                change_description: "Created checkpoint for rollback".to_string(),
                change_success: true,
                change_error: None,
            });
        }

        // Check if auditd is installed
        if !is_auditd_installed(ctx).await.unwrap_or(false) {
            return Ok(ApplyResult {
                apply_changes: vec![Change {
                    change_type: ChangeType::Service,
                    change_description: "Auditd not installed - cannot apply rules".to_string(),
                    change_error: Some("auditd package not found".to_string()),
                    change_success: false,
                }],
                apply_checkpoint_id: checkpoint_id,
                apply_error: Some("Auditd is not installed".to_string()),
                apply_plugin_id: self.metadata().plugin_id,
                apply_success: false,
            });
        }

        // Enable auditd if not enabled
        if !is_auditd_enabled(ctx).await.unwrap_or(false) {
            let result = ctx
                .executor()
                .execute_command("systemctl", &["enable", "auditd"])
                .await;
            match result {
                Ok(output) if output.success() => {
                    changes.push(Change {
                        change_type: ChangeType::Service,
                        change_description: "Enabled auditd service".to_string(),
                        change_error: None,
                        change_success: true,
                    });
                }
                _ => {
                    changes.push(Change {
                        change_type: ChangeType::Service,
                        change_description: "Failed to enable auditd service".to_string(),
                        change_error: Some("systemctl enable failed".to_string()),
                        change_success: false,
                    });
                }
            }
        }

        // Start auditd if not running
        if !is_auditd_running(ctx).await.unwrap_or(false) {
            let result = ctx
                .executor()
                .execute_command("systemctl", &["start", "auditd"])
                .await;
            match result {
                Ok(output) if output.success() => {
                    changes.push(Change {
                        change_type: ChangeType::Service,
                        change_description: "Started auditd service".to_string(),
                        change_error: None,
                        change_success: true,
                    });
                }
                _ => {
                    changes.push(Change {
                        change_type: ChangeType::Service,
                        change_description: "Failed to start auditd".to_string(),
                        change_error: Some("systemctl start failed".to_string()),
                        change_success: false,
                    });
                }
            }
        }

        // Build rules file content
        let mut rules_content = String::new();
        rules_content.push_str("# Audit rules generated by Linux Hardening Tool\n");
        rules_content.push_str("# DO NOT EDIT - Changes will be overwritten\n\n");

        for category in [
            "time-change",
            "identity",
            "network-change",
            "perm-mod",
            "privileged",
            "delete",
            "modules",
        ] {
            // Check for a valid exception — skip entire category if exempted
            if let Some(exception) = config.has_valid_exception(category) {
                info!(
                    "Skipping audit category '{}' — exception: {}",
                    category, exception.reason
                );
                rules_content.push_str(&format!(
                    "# {} — SKIPPED (exception: {})\n\n",
                    category.to_uppercase(),
                    exception.reason
                ));
                changes.push(Change {
                    change_description: format!(
                        "Audit category {}: skipped (exception: {})",
                        category, exception.reason
                    ),
                    change_type: ChangeType::ConfigFile,
                    change_success: true,
                    change_error: None,
                });
                continue;
            }

            rules_content.push_str(&format!("# {}\n", category.to_uppercase()));

            for rule in AUDIT_RULES
                .iter()
                .filter(|r| r.audit_rule_category == category)
            {
                rules_content.push_str(&format!("# {}\n", rule.audit_rule_description));
                rules_content.push_str(&format!("{}\n\n", rule.audit_rule_content));
            }
        }

        // Write rules file
        match write_audit_rules_file(ctx, &rules_content).await {
            Ok(backup_path) => {
                changes.push(Change {
                    change_type: ChangeType::ConfigFile,
                    change_description: format!(
                        "Created audit rules file (backup: {})",
                        backup_path
                    ),
                    change_error: None,
                    change_success: true,
                });
            }
            Err(e) => {
                changes.push(Change {
                    change_type: ChangeType::ConfigFile,
                    change_description: "Failed to write audit rules".to_string(),
                    change_error: Some(e.to_string()),
                    change_success: false,
                });
            }
        }

        // Reload audit rules into running daemon
        match reload_audit_rules(ctx).await {
            Ok(_) => {
                changes.push(Change {
                    change_type: ChangeType::Service,
                    change_description: "Loaded audit rules into running daemon".to_string(),
                    change_error: None,
                    change_success: true,
                });
            }
            Err(e) => {
                changes.push(Change {
                    change_type: ChangeType::Service,
                    change_description: "Failed to reload audit rules".to_string(),
                    change_error: Some(e.to_string()),
                    change_success: false,
                });
            }
        }

        // Determine overall success
        let all_successful = changes.iter().all(|c| c.change_success);

        Ok(ApplyResult {
            apply_changes: changes,
            apply_checkpoint_id: checkpoint_id,
            apply_error: if all_successful {
                None
            } else {
                Some("Some changes failed".to_string())
            },
            apply_plugin_id: self.metadata().plugin_id,
            apply_success: all_successful,
        })
    }

    async fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()> {
        info!(
            "Rolling back audit configuration to checkpoint: {}",
            checkpoint.checkpoint_id.as_str()
        );

        // Restore configuration files from checkpoint
        crate::rollback_files_from_checkpoint(ctx, checkpoint)?;

        info!("Audit configuration files restored from checkpoint");

        // Reload audit rules after restoring config
        match reload_audit_rules(ctx).await {
            Ok(_) => info!("Audit rules reloaded successfully"),
            Err(e) => warn!("Failed to reload audit rules: {}", e),
        }

        Ok(())
    }

    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> {
        let mut estimated_changes = Vec::new();
        let mut issues = Vec::new();

        // Check if auditd is installed
        match is_auditd_installed(ctx).await {
            Ok(true) => {
                // Check if auditd is enabled
                if let Ok(false) = is_auditd_enabled(ctx).await {
                    estimated_changes.push("Enable auditd service".to_string());
                }

                // Check if auditd is running
                if let Ok(false) = is_auditd_running(ctx).await {
                    estimated_changes.push("Start auditd service".to_string());
                }

                // Estimate rule changes
                if let AuditRulesResult::Rules(current_rules) = read_current_audit_rules(ctx).await
                {
                    let missing_rules = AUDIT_RULES
                        .iter()
                        .filter(|rule| {
                            // Skip rules whose category has a valid exception
                            config
                                .has_valid_exception(rule.audit_rule_category)
                                .is_none()
                                && !current_rules
                                    .iter()
                                    .any(|current| current.contains(rule.audit_rule_category))
                        })
                        .count();

                    if missing_rules > 0 {
                        estimated_changes.push(format!("Add {} audit-rules", missing_rules));
                    }
                }
            }
            Ok(false) => {
                issues.push(ValidationIssue {
                    validation_issue_config_key: None,
                    validation_issue_message:
                        "auditd is not installed - this plugin requires auditd".to_string(),
                    validation_issue_severity: Severity::Critical,
                });
            }
            Err(_) => {
                // Can't determine, add as issue
                issues.push(ValidationIssue {
                    validation_issue_config_key: None,
                    validation_issue_message: "Failed to check auditd installation status"
                        .to_string(),
                    validation_issue_severity: Severity::High,
                });
            }
        }

        Ok(ValidationReport {
            validation_report_estimated_changes: estimated_changes,
            validation_report_is_valid: issues.is_empty(),
            validation_report_issues: issues,
            validation_report_plugin_id: self.metadata().plugin_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A representative audit check (`not_installed`) must now carry
    /// multi-framework mappings: the existing CIS control plus NIST 800-53,
    /// STIG, and PCI-DSS sourced from SSG `package_audit_installed`.
    #[test]
    fn auditd_install_has_multi_framework_mappings() {
        let mappings = get_audit_compliance_mappings("not_installed");

        let has = |fw| mappings.iter().any(|m| m.compliance_framework == fw);
        assert!(
            has(ComplianceFramework::CIS),
            "CIS mapping must be retained"
        );
        assert!(
            has(ComplianceFramework::NIST),
            "NIST mapping must be present"
        );
        assert!(
            has(ComplianceFramework::STIG),
            "STIG mapping must be present"
        );
        assert!(
            has(ComplianceFramework::PCIDSS),
            "PCI-DSS mapping must be present"
        );

        // Verify the exact SSG-sourced STIG and NIST identifiers.
        let stig = mappings
            .iter()
            .find(|m| m.compliance_framework == ComplianceFramework::STIG)
            .unwrap();
        assert_eq!(stig.compliance_control_id, "OL08-00-030180");
        let nist = mappings
            .iter()
            .find(|m| m.compliance_framework == ComplianceFramework::NIST)
            .unwrap();
        assert_eq!(nist.compliance_control_id, "AU-2(a)");
    }

    /// Audit findings must also carry HIPAA, GDPR and ISO/IEC 27001:2022
    /// logging mappings alongside the existing CIS/NIST/STIG/PCI-DSS set.
    #[test]
    fn auditd_install_has_privacy_and_iso_mappings() {
        let mappings = get_audit_compliance_mappings("not_installed");

        let has = |fw| mappings.iter().any(|m| m.compliance_framework == fw);
        assert!(has(ComplianceFramework::HIPAA), "HIPAA must be present");
        assert!(has(ComplianceFramework::GDPR), "GDPR must be present");
        assert!(
            has(ComplianceFramework::ISO27001),
            "ISO 27001 must be present"
        );

        // ISO logging clause for audit controls.
        let iso = mappings
            .iter()
            .find(|m| m.compliance_framework == ComplianceFramework::ISO27001)
            .unwrap();
        assert_eq!(iso.compliance_control_id, "8.15");

        // HIPAA must include the Audit Controls safeguard.
        assert!(
            mappings
                .iter()
                .any(|m| m.compliance_framework == ComplianceFramework::HIPAA
                    && m.compliance_control_id == "164.312(b)")
        );
    }

    /// The audit-rules bucket additionally maps to ISO 8.16 (monitoring
    /// activities), since live rules actively monitor security events.
    #[test]
    fn audit_rules_map_to_iso_monitoring() {
        let mappings = get_audit_compliance_mappings("rules");
        assert!(
            mappings
                .iter()
                .any(|m| m.compliance_framework == ComplianceFramework::ISO27001
                    && m.compliance_control_id == "8.16"),
            "audit rules must map to ISO 8.16 monitoring activities"
        );
    }

    /// Confirms the SOC 2 mappings: every auditd service-state finding carries
    /// the anomaly-monitoring criterion CC7.2, and the rules bucket adds the
    /// configuration-change detection criterion CC7.1 — both filed under the
    /// "System Operations" TSC series.
    #[test]
    fn audit_findings_map_soc2_monitoring_criteria() {
        for finding_type in ["not_installed", "not_running"] {
            let soc2 = get_audit_compliance_mappings(finding_type)
                .into_iter()
                .find(|m| m.compliance_framework == ComplianceFramework::SOC2)
                .unwrap_or_else(|| panic!("{finding_type} must carry a SOC 2 mapping"));
            assert_eq!(soc2.compliance_control_id, "CC7.2");
            assert_eq!(
                soc2.compliance_section.as_deref(),
                Some("System Operations")
            );
        }

        let rule_ids: Vec<String> = get_audit_compliance_mappings("rules")
            .into_iter()
            .filter(|m| m.compliance_framework == ComplianceFramework::SOC2)
            .map(|m| m.compliance_control_id)
            .collect();
        assert!(rule_ids.contains(&"CC7.1".to_string()));
        assert!(rule_ids.contains(&"CC7.2".to_string()));
    }

    /// Confirms the 800-171r3 crosswalk: AU-2 → 3.3.1 for the install check
    /// and AU-12 → 3.3.3 for the service and rules checks, filed under the
    /// official Audit and Accountability family.
    #[test]
    fn audit_findings_map_nist_800_171_requirements() {
        for (finding_type, id) in [
            ("not_installed", "3.3.1"),
            ("not_running", "3.3.3"),
            ("rules", "3.3.3"),
        ] {
            let mapping = get_audit_compliance_mappings(finding_type)
                .into_iter()
                .find(|m| m.compliance_framework == ComplianceFramework::NIST800171)
                .unwrap_or_else(|| panic!("{finding_type} must carry an 800-171 mapping"));
            assert_eq!(mapping.compliance_control_id, id, "{finding_type}");
            assert_eq!(
                mapping.compliance_section.as_deref(),
                Some("Audit and Accountability")
            );
        }
    }

    /// Confirms the FedRAMP derivation: AU-2 and AU-12 are both GSA rev5
    /// Moderate baseline members, so each finding mirrors its existing 800-53
    /// entry verbatim under the Audit and Accountability family.
    #[test]
    fn audit_findings_map_fedramp_moderate_controls() {
        for (finding_type, id) in [
            ("not_installed", "AU-2(a)"),
            ("not_running", "AU-12(c)"),
            ("rules", "AU-12(c)"),
        ] {
            let mapping = get_audit_compliance_mappings(finding_type)
                .into_iter()
                .find(|m| m.compliance_framework == ComplianceFramework::FedRAMP)
                .unwrap_or_else(|| panic!("{finding_type} must carry a FedRAMP mapping"));
            assert_eq!(mapping.compliance_control_id, id, "{finding_type}");
            assert_eq!(
                mapping.compliance_section.as_deref(),
                Some("Audit and Accountability")
            );
        }
    }
}
