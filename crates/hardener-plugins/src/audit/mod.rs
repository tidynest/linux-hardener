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
    // Create backup with timestamp
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let backup_path = format!("{}.backup.{}", AUDIT_RULES_PATH, timestamp);

    // Backup existing file if it exists
    if ctx
        .executor()
        .path_exists(Path::new(AUDIT_RULES_PATH))
        .await
        .unwrap_or(false)
    {
        ctx.executor()
            .execute_command("cp", &[AUDIT_RULES_PATH, &backup_path])
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
fn get_audit_compliance_mappings(finding_type: &str) -> Vec<ComplianceMapping> {
    match finding_type {
        "not_installed" => vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "4.1.1.1".to_string(),
            compliance_control_title: "Ensure auditd is installed".to_string(),
            compliance_section: Some("Logging and Auditing".to_string()),
        }],
        "not_enabled" | "not_running" => vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "4.1.1.2".to_string(),
            compliance_control_title: "Ensure auditd service is enabled and running".to_string(),
            compliance_section: Some("Logging and Auditing".to_string()),
        }],
        "config" | "rules" => vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "4.1.2.1".to_string(),
            compliance_control_title: "Ensure audit log storage size is  configured".to_string(),
            compliance_section: Some("Logging and Auditing".to_string()),
        }],
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
                finding_title: "Audit daemon not installed".to_string(),
                finding_compliance: get_audit_compliance_mappings("not_installed"),
                finding_policy_exception: None,
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
        if !is_auditd_enabled(ctx).await.unwrap_or(false) {
            findings.push(Finding {
                finding_category: FindingCategory::Audit,
                finding_current_value: "disabled".to_string(),
                finding_description: "Audit daemon is not enable to start at boot".to_string(),
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
                    let rule_exists = current_rules.iter().any(|current_rule| {
                        current_rule.contains(rule.audit_rule_category)
                            && current_rule.contains("-k")
                    });

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
                                rule.audit_rule_category.replace("-", "_")
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

    async fn apply(&self, ctx: &mut Context, _config: &PluginConfig) -> Result<ApplyResult> {
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

    async fn validate(&self, ctx: &Context, _config: &PluginConfig) -> Result<ValidationReport> {
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
                            !current_rules
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
