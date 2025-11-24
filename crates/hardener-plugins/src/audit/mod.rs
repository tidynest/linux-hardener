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

use hardener_common::{
    error::Result,
    types::{FindingCategory, PluginId, Severity}
};
use hardener_core::{
    ApplyResult, Change, ChangeType, Checkpoint, Config, ValidationIssue, ValidationReport,
    context::Context,
    plugin::{Finding, HardeningPlugin, PluginMetadata, ScanResult},
};
use std::{fs, path::Path, process::Command, time::Instant};
use tracing::warn;

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
    audit_rule_category:    &'static str,
    audit_rule_content:     &'static str,
    audit_rule_description: &'static str,
    audit_rule_severity:    Severity,
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
        audit_rule_category:    "time-change",
        audit_rule_content:     "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change",
        audit_rule_description: "Monitor system time modifications (64-bit)",
        audit_rule_severity:    Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category:    "time-change",
        audit_rule_content:     "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change",
        audit_rule_description: "Monitor system time modifications (32-bit)",
        audit_rule_severity:    Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category:    "time-change",
        audit_rule_content:     "-a always,exit -F arch=b64 -S clock_settime -k time-change",
        audit_rule_description: "Monitor clock_settime syscall (64-bit)",
        audit_rule_severity:    Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category:    "time-change",
        audit_rule_content:     "-w /etc/localtime -p wa -k time-change",
        audit_rule_description: "Monitor timezone configuration changes",
        audit_rule_severity:    Severity::Medium,
    },

    // ============================================================================
    // IDENTITY - Monitor user and group modifications
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category:    "identity",
        audit_rule_content:     "-w /etc/passwd -p wa -k identity",
        audit_rule_description: "Monitor user account file modifications",
        audit_rule_severity:    Severity::Critical,
    },
    AuditRuleDirective {
        audit_rule_category:    "identity",
        audit_rule_content:     "-w /etc/shadow -p wa -k identity",
        audit_rule_description: "Monitor password hash file modifications",
        audit_rule_severity:    Severity::Critical,
    },
    AuditRuleDirective {
        audit_rule_category:    "identity",
        audit_rule_content:     "-w /etc/group -p wa -k identity",
        audit_rule_description: "Monitor group account file modifications",
        audit_rule_severity:    Severity::Critical,
    },

    AuditRuleDirective {
        audit_rule_category:    "identity",
        audit_rule_content:     "-w /etc/gshadow -p wa -k identity",
        audit_rule_description: "Monitor group password file modifications",
        audit_rule_severity:    Severity::Critical,
    },
    AuditRuleDirective {
        audit_rule_category:    "identity",
        audit_rule_content:     "-w /etc/security/opasswd -p wa -k identity",
        audit_rule_description: "Monitor password history file modifications",
        audit_rule_severity:    Severity::High,
    },

    // ============================================================================
    // NETWORK CHANGES - Monitor network configuration
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category:    "network-change",
        audit_rule_content:     "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network-change",
        audit_rule_description: "Monitor hostname and domain name changes (64-bit)",
        audit_rule_severity:    Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category:    "network-change",
        audit_rule_content:     "-w /etc/hosts -p wa -k network-change",
        audit_rule_description: "Monitor hosts file modifications",
        audit_rule_severity:    Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category:    "network-change",
        audit_rule_content:     "-w /etc/network/ -p wa -k network-change",
        audit_rule_description: "Monitor network configuration directory",
        audit_rule_severity:    Severity::Medium,
    },

    // ============================================================================
    // PERMISSION MODIFICATIONS - Monitor file permission and ownership changes
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category:    "perm-mod",
        audit_rule_content:     "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm-mod",
        audit_rule_description: "Monitor file permission changes (64-bit)",
        audit_rule_severity:    Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category:    "perm-mod",
        audit_rule_content:     "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -k perm-mod",
        audit_rule_description: "Monitor file permission changes (32-bit)",
        audit_rule_severity:    Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category:    "perm-mod",
        audit_rule_content:     "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -k perm-mod",
        audit_rule_description: "Monitor file ownership changes (64-bit)",
        audit_rule_severity:    Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category:    "perm-mod",
        audit_rule_content:     "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -k perm-mod",
        audit_rule_description: "Monitor file ownership changes (32-bit)",
        audit_rule_severity:    Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category:    "perm-mod",
        audit_rule_content:     "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -k perm-mod",
        audit_rule_description: "Monitor extended attribute changes (64-bit)",
        audit_rule_severity:    Severity::Medium,
    },

    // ============================================================================
    // PRIVILEGED COMMANDS - Monitor execution of privileged commands
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category:    "privileged",
        audit_rule_content:     "-w /usr/bin/sudo -p x -k privileged",
        audit_rule_description: "Monitor sudo command execution",
        audit_rule_severity:    Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category:    "privileged",
        audit_rule_content:     "-w /usr/bin/su -p x -k privileged",
        audit_rule_description: "Monitor su command execution",
        audit_rule_severity:    Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category:    "privileged",
        audit_rule_content:     "-w /usr/bin/passwd -p wa -k privileged",
        audit_rule_description: "Monitor passwd command execution",
        audit_rule_severity:    Severity::Medium,
    },

    // ============================================================================
    // FILE DELETION - Monitor file and directory deletion
    // ============================================================================

    AuditRuleDirective {
        audit_rule_category:    "delete",
        audit_rule_content:     "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete",
        audit_rule_description: "Monitor file deletion operations (64-bit)",
        audit_rule_severity:    Severity::Medium,
    },
    AuditRuleDirective {
        audit_rule_category:    "delete",
        audit_rule_content:     "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -k delete",
        audit_rule_description: "Monitor file deletion operations (32-bit)",
        audit_rule_severity:    Severity::Medium,
    },

    // ============================================================================
    // KERNEL MODULES - Monitor kernel module operations
    // ============================================================================
    AuditRuleDirective {
        audit_rule_category:    "modules",
        audit_rule_content:     "-w /sbin/insmod -p x -k modules",
        audit_rule_description: "Monitor kernel module insertion",
        audit_rule_severity:    Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category:    "modules",
        audit_rule_content:     "-w /sbin/rmmod -p x -k modules",
        audit_rule_description: "Monitor kernel module removal",
        audit_rule_severity:    Severity::High,
    },
    AuditRuleDirective {
        audit_rule_category:    "modules",
        audit_rule_content:     "-w /sbin/modprobe -p x -k modules",
        audit_rule_description: "Monitor modprobe execution",
        audit_rule_severity:    Severity::High,
    },
];

/// Path to custom audit rules file for hardening.
const AUDIT_RULES_PATH: &str = "/etc/audit/rules.d/hardening.rules";

/// ============================================================================
/// AUDITD HELPER FUNCTIONS
/// ============================================================================
/// Checks if auditd is installed on the system.
fn is_auditd_installed() -> Result<bool> {
    let output = Command::new("which")
        .arg("auditd")
        .output()
        .map_err(hardener_common::error::HardeningError::System)?;

    Ok(output.status.success())
}

/// Checks if auditd service is enabled to start at boot.
fn is_auditd_enabled() -> Result<bool> {
    let output = Command::new("systemctl")
        .args(["is-enabled", "auditd"])
        .output()
        .map_err(hardener_common::error::HardeningError::System)?;

    Ok(output.status.success())
}

/// Checks if auditd service is currently running.
fn is_auditd_running() -> Result<bool> {
    let output = Command::new("systemctl")
        .args(["is-active", "auditd"])
        .output()
        .map_err(hardener_common::error::HardeningError::System)?;

    Ok(output.status.success())
}

/// Reads current audit rules from the system using auditctl.
fn read_current_audit_rules() -> Result<Vec<String>> {
    let output = Command::new("auditctl")
        .arg("-l")
        .output()
        .map_err(hardener_common::error::HardeningError::System)?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let rules = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.starts_with("No rules"))
        .collect();

    Ok(rules)
}

/// Writes audit rules to the hardening rules file with backup.
fn write_audit_rules_file(content: &str) -> Result<String> {
    // Create backup with timestamp
    let timestamp   = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let backup_path = format!("{}.backup.{}", AUDIT_RULES_PATH, timestamp);

    // Backup existing file if it exists
    if Path::new(AUDIT_RULES_PATH).exists() {
        fs::copy(AUDIT_RULES_PATH, &backup_path)
            .map_err(hardener_common::error::HardeningError::System)?;
    }

    // Ensure directory exists
    if let Some(parent) = Path::new(AUDIT_RULES_PATH).parent() {
        fs::create_dir_all(parent)
            .map_err(hardener_common::error::HardeningError::System)?;
    }

    // Write new rules file
    fs::write(AUDIT_RULES_PATH, content)
        .map_err(hardener_common::error::HardeningError::System)?;

    Ok(backup_path)
}

/// Restarts the auditd service to load new rules.
fn restart_auditd_service() -> Result<()> {
    // Try systemctl first
    let result = Command::new("systemctl")
        .args(["restart", "auditd"])
        .status()
        .map_err(hardener_common::error::HardeningError::System)?;

    if !result.success() {
        return Err(hardener_common::error::HardeningError::Plugin(
            "Failed to restart auditd service".to_string(),
        ));
    }

    Ok(())
}

/// ============================================================================
/// HARDENING PLUGIN TRAIT IMPLEMENTATION
/// ============================================================================
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
        vec![]  // No dependencies
    }

    fn validate(
        &self,
        _config: &Config
    ) -> Result<ValidationReport> {
        let mut estimated_changes = Vec::new();
        let mut issues = Vec::new();

        // Check if auditd is installed
        match is_auditd_installed() {
            Ok(true) => {
                // Check if auditd is enabled
                if let Ok(false) = is_auditd_enabled() {
                    estimated_changes.push("Enable auditd service".to_string());
                }

                // Check if auditd is running
                if let Ok(false) = is_auditd_running() {
                    estimated_changes.push("Start auditd service".to_string());
                }

                // Estimate rule changes
                if let Ok(current_rules) = read_current_audit_rules() {
                    let missing_rules = AUDIT_RULES
                        .iter()
                        .filter(|rule| {
                            !current_rules.iter().any(|current| {
                                current.contains(rule.audit_rule_category)
                            })
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
                    validation_issue_message: "auditd is not installed . this plugin requires auditd".to_string(),
                    validation_issue_severity: Severity::Critical,
                });
            }
            Err(_) => {
                // Can't determine, add as issue
                issues.push(ValidationIssue {
                    validation_issue_config_key: None,
                    validation_issue_message: "Failed to check auditd installation status".to_string(),
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

    fn scan(
        &self,
        _ctx: &Context
    ) -> Result<ScanResult> {
        let start = Instant::now();
        let mut findings = Vec::new();

        // Check if auditd is installed
        if !is_auditd_installed().unwrap_or(false) {
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
                finding_title: "Audit daemon not installed".to_string(),
            });

            // If not installed, no pint checking further
            return Ok(ScanResult {
                scan_duration_us: start.elapsed().as_micros() as u64,
                scan_error: None,
                scan_findings: findings,
                scan_plugin_id: self.metadata().plugin_id,
                scan_success: true,
            });
        }

        // Check if auditd is enabled
        if !is_auditd_enabled().unwrap_or(false) {
            findings.push(Finding {
                finding_category:          FindingCategory::Audit,
                finding_current_value:     "disabled".to_string(),
                finding_description:       "Audit daemon is not enable to start at boot".to_string(),
                finding_explanation:       "Auditd should be enabled to ensure audit logging starts automatically".to_string(),
                finding_id:                "audit_not_enabled".to_string(),
                finding_impact:            "Audit logging may not start after reboot".to_string(),
                finding_recommended_value: "enabled".to_string(),
                finding_remediation_steps: vec!["systemctl enable auditd".to_string()],
                finding_severity:          Severity::High,
                finding_title:             "Audit daemon not enabled".to_string(),
            });
        }

        // Check if auditd is running
        if !is_auditd_running().unwrap_or(false) {
            findings.push(Finding {
                finding_category:          FindingCategory::Audit,
                finding_current_value:     "stopped".to_string(),
                finding_description:       "Audit daemon is not currently running".to_string(),
                finding_explanation:       "Auditd must be running".to_string(),
                finding_id:                "auditd_not_running".to_string(),
                finding_impact:            "No audit events are being collected".to_string(),
                finding_recommended_value: "running".to_string(),
                finding_remediation_steps: vec!["systemctl start auditd".to_string()],
                finding_severity:          Severity::High,
                finding_title:             "Audit daemon not running".to_string(),
            });
        }

        // Check current audit rules
        if let Ok(current_rules) = read_current_audit_rules() {
            // Check each required rule
            for rule in AUDIT_RULES {
                // Check if this rule category is present in current rules
                let rule_exists = current_rules.iter().any(|current_rule| {
                    current_rule.contains(rule.audit_rule_category)
                        && current_rule.contains("-k")
                });

                if !rule_exists {
                    findings.push(Finding {
                        finding_category:       FindingCategory::Audit,
                        finding_current_value: "not configured".to_string(),
                        finding_description:   rule.audit_rule_description.to_string(),
                        finding_explanation:   format!(
                            "Audit rule for {} is not configured. This rule monitors: {}",
                            rule.audit_rule_category,
                            rule.audit_rule_description
                        ),
                        finding_id: format!(
                            "audit_rule_{}",
                            rule.audit_rule_category.replace("-", "_")
                        ),
                        finding_impact:            "Security events in this category are not being audited".to_string(),
                        finding_recommended_value: rule.audit_rule_content.to_string(),
                        finding_remediation_steps: vec![format!(
                            "Add rule: {}",
                            rule.audit_rule_content
                        ),
                        "Restart auditd: systemctl restart auditd".to_string(),
                        ],
                        finding_severity: rule.audit_rule_severity,
                        finding_title: format!(
                            "Missing audit rule: {}",
                            rule.audit_rule_category
                        ),
                    });
                }
            }
        }
        Ok(ScanResult {
            scan_duration_us: start.elapsed().as_micros() as u64,
            scan_error:       None,
            scan_findings: findings,
            scan_plugin_id:   self.metadata().plugin_id,
            scan_success: true,
        })
    }

    fn apply(
        &self,
        _ctx: &mut Context,
        _config: &Config
    ) -> Result<ApplyResult> {
        let mut changes = Vec::new();
        let _start      = Instant::now();

        // Check if auditd is installed
        if !is_auditd_installed().unwrap_or(false) {
            return Ok(ApplyResult {
                apply_changes: vec![Change {
                    change_type: ChangeType::Service,
                    change_description: "Auditd not installed - cannot apply rules".to_string(),
                    change_error: Some("auditd package not found".to_string()),
                    change_success: false,
                }],
                apply_checkpoint_id: None,
                apply_error: Some("Auditd is not installed".to_string()),
                apply_plugin_id: self.metadata().plugin_id,
                apply_success: false,
            });
        }

        // Enable auditd if not enabled
        if !is_auditd_enabled().unwrap_or(false) {
            match Command::new("systemctl").args(["enable", "auditd"]).status() {
                Ok(status) if status.success() => {
                    changes.push(Change {
                        change_type: ChangeType::Service,
                        change_description: "Enabled auditd service".to_string(),
                        change_error:       None,
                        change_success:     true,
                    });
                }
                _ => {
                    changes.push(Change {
                        change_type: ChangeType::Service,
                        change_description: "Failed to enable auditd service".to_string(),
                        change_error:       Some("systemctl enable failed".to_string()),
                        change_success:     false,
                    });
                }
            }
        }

        // Start auditd if not running
        if !is_auditd_running().unwrap_or(false) {
            match Command::new("systemctl").args(["start", "auditd"]).status() {
                Ok(status) if status.success() => {
                    changes.push(Change {
                        change_type: ChangeType::Service,
                        change_description: "Started auditd service".to_string(),
                        change_error:       None,
                        change_success:     true,
                    });
                }
                _ => {
                    changes.push(Change {
                        change_type: ChangeType::Service,
                        change_description: "Failed to start auditd".to_string(),
                        change_error:       Some("systemctl start failed".to_string()),
                        change_success:     false,
                    });
                }
            }
        }

        // Build rules file content
        let mut rules_content = String::new();
        rules_content.push_str("# Audit rules generated by Linux Hardening Tool\n");
        rules_content.push_str("# DO NOT EDIT - Changes will be overwritten\n\n");

        for category in ["time-change", "identity", "network-change", "perm-mod", "privileged", "delete", "modules"] {
            rules_content.push_str(&format!("# {}\n", category.to_uppercase()));

            for rule in AUDIT_RULES.iter().filter(|r| r.audit_rule_category == category) {
                rules_content.push_str(&format!("# {}\n", rule.audit_rule_description));
                rules_content.push_str(&format!("{}\n\n", rule.audit_rule_content));
            }
        }

        // Write rules file
        match write_audit_rules_file(&rules_content) {
            Ok(backup_path) => {
                changes.push(Change {
                    change_type: ChangeType::ConfigFile,
                    change_description: format!("Created audit rules file (backup: {})", backup_path),
                    change_error:       None,
                    change_success:     true,
                });
            }
            Err(e) => {
                changes.push(Change {
                    change_type: ChangeType::ConfigFile,
                    change_description: "Failed to write audit rules".to_string(),
                    change_error:       Some(e.to_string()),
                    change_success:     false,
                });
            }
        }

        // Restart auditd to load new rules
        match restart_auditd_service() {
            Ok(_) => {
                changes.push(Change {
                    change_type: ChangeType::Service,
                    change_description: "Restarted auditd service to load new rules".to_string(),
                    change_error:       None,
                    change_success:     true,
                });
            }
            Err(e) => {
                changes.push(Change {
                    change_type: ChangeType::Service,
                    change_description: "Failed to restart auditd service".to_string(),
                    change_error:       Some(e.to_string()),
                    change_success:     false,
                });
            }
        }

        // Determine overall success
        let all_successful = changes.iter().all(|c| c.change_success);

        Ok(ApplyResult {
            apply_changes:       changes,
            apply_checkpoint_id: None,
            apply_error:         if all_successful { None } else { Some("Some changes failed".to_string()) },
            apply_plugin_id:     self.metadata().plugin_id,
            apply_success:       all_successful,
        })
    }

    fn rollback(
        &self,
        _ctx: &mut Context,
        _checkpoint: &Checkpoint
    ) -> Result<()> {
        // Rollback not yet implemented - will be handled by checkpoint system
        warn!("Audit rules rollback not yet implemented");
        Ok(())
    }
}



