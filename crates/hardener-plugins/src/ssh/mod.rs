//! SSH hardening plugin for OpenSSH server configuration management
//!
//! This plugin scans, applies and manages OpenSSH server security settings.
//! It focuses on critical authentication and protocol security including:
//!  - Disabling root login
//! - Enforcing key-based authentication
//! - Restricting protocol versions
//! - Limiting authentication attempts.
//!
//! The plugin reads the sshd_config file, compares against secure baselines,
//! and can apply hardening configurations with automatic backup support.

use async_trait::async_trait;
use chrono::Utc;
use hardener_common::{
    error::Result,
    file_utils::{ConfigFormat, parse_config_value, set_config_directive},
    types::{ComplianceFramework, ComplianceMapping, FindingCategory, PluginId, Severity},
};
use hardener_core::{
    ApplyResult, Change, ChangeType, Checkpoint, PluginConfig, ValidationIssue, ValidationReport,
    context::Context,
    plugin::{Finding, HardeningPlugin, PluginMetadata, ScanResult},
};
use std::{path::Path, time::Instant};
use tracing::{error, info, warn};

/// Represents a single SSH configuration directive to be hardened.
#[derive(Clone, Debug)]
struct SshConfigDirective {
    /// Human-readable finding_description of this directive's security purpose.
    ssh_description: &'static str,
    /// The directive name as it appears in sshd_config (e.g., "PermitRootLogin").
    ssh_directive_name: &'static str,
    /// The secure value for this directive (e.g., "no").
    ssh_secure_value: &'static str,
    /// Severity level if this directive is not set securely.
    ssh_severity: Severity,
}

/// Critical SSH config directives for security hardening.
///
/// These represent the minimum baseline for secure SSH configuration.
const SSH_DIRECTIVES: &[SshConfigDirective] = &[
    SshConfigDirective {
        ssh_directive_name: "PermitRootLogin",
        ssh_secure_value: "no",
        ssh_description: "Disable direct root login via SSH",
        ssh_severity: Severity::Critical,
    },
    SshConfigDirective {
        ssh_directive_name: "PasswordAuthentication",
        ssh_secure_value: "no",
        ssh_description: "Require key-based authentication only",
        ssh_severity: Severity::Critical,
    },
    SshConfigDirective {
        ssh_directive_name: "PermitEmptyPasswords",
        ssh_secure_value: "no",
        ssh_description: "Disallow empty passwords",
        ssh_severity: Severity::Critical,
    },
    SshConfigDirective {
        ssh_directive_name: "Protocol",
        ssh_secure_value: "2",
        ssh_description: "Use only SSH protocol version 2",
        ssh_severity: Severity::Critical,
    },
    SshConfigDirective {
        ssh_directive_name: "MaxAuthTries",
        ssh_secure_value: "3",
        ssh_description: "Limit authentication attempts to prevent brute force",
        ssh_severity: Severity::Medium,
    },
    SshConfigDirective {
        ssh_directive_name: "X11Forwarding",
        ssh_secure_value: "no",
        ssh_description: "Disable X11 forwarding to reduce attack surface",
        ssh_severity: Severity::Medium,
    },
    SshConfigDirective {
        ssh_directive_name: "ClientAliveInterval",
        ssh_secure_value: "300",
        ssh_description: "Disconnect idle SSH sessions after 5 minutes",
        ssh_severity: Severity::Low,
    },
    SshConfigDirective {
        ssh_directive_name: "ClientAliveCountMax",
        ssh_secure_value: "2",
        ssh_description: "Maximum idle connection checks before disconnect",
        ssh_severity: Severity::Low,
    },
];

/// SSH hardening plugin implementing OpenSSH configuration management.
pub struct SshHardeningPlugin;

impl Default for SshHardeningPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl SshHardeningPlugin {
    /// Creates a new instance of the SSH hardening plugin.
    pub fn new() -> SshHardeningPlugin {
        SshHardeningPlugin
    }

    /// Restarts the SSH daemon to apply configuration changes.
    ///
    /// Attempts to restart using systemctl (systemd) first, then falls back
    /// to service command for non-systemd systems.
    ///
    /// # Returns
    /// Ok(()) if restart succeeded, or an error describing the failure.
    async fn restart_ssh_service(ctx: &Context) -> Result<()> {
        // Try systemctl first (most modern distribution).
        let systemctl_result = ctx
            .executor()
            .execute_command("systemctl", &["restart", "sshd"])
            .await;

        match systemctl_result {
            Ok(output) if output.success() => {
                info!("SSH service restarted successfully via systemctl");
                return Ok(());
            }
            Ok(output) => {
                warn!("systemctl restart sshd failed: {}", output.stderr);
            }
            Err(e) => {
                warn!("systemctl command failed: {}", e);
            }
        }

        // Fallback to service command.
        let service_result = ctx
            .executor()
            .execute_command("service", &["ssh", "restart"])
            .await;

        match service_result {
            Ok(output) if output.success() => {
                info!("SSH service restarted successfully via service command");
                Ok(())
            }
            Ok(output) => Err(hardener_common::error::HardeningError::Plugin(format!(
                "Failed to restart SSH service: {}",
                output.stderr
            ))),
            Err(e) => Err(hardener_common::error::HardeningError::Plugin(format!(
                "Failed to execute service restart command: {}",
                e
            ))),
        }
    }
}

/// Returns compliance mappings for a given SSH directive.
fn get_ssh_compliance_mappings(directive_name: &str) -> Vec<ComplianceMapping> {
    match directive_name {
        "PermitRootLogin" => vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.2.10".to_string(),
            compliance_control_title: "Ensure SSH root login is disabled".to_string(),
            compliance_section: Some("Access Control".to_string()),
        }],
        "PasswordAuthentication" => vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.2.11".to_string(),
            compliance_control_title: "Ensure SSH PermitEmptyPasswords is disabled".to_string(),
            compliance_section: Some("Access Control".to_string()),
        }],
        "PermitEmptyPasswords" => vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.2.11".to_string(),
            compliance_control_title: "Ensure SSH PermitEmptyPasswords is disabled".to_string(),
            compliance_section: Some("Access Control".to_string()),
        }],
        "Protocol" => vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.2.4".to_string(),
            compliance_control_title: "Ensure SSH Protocol is set to 2".to_string(),
            compliance_section: Some("Access Control".to_string()),
        }],
        "MaxAuthTries" => vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.2.7".to_string(),
            compliance_control_title: "Ensure SSH MaxAuthTries is set to 4 or less".to_string(),
            compliance_section: Some("Access Control".to_string()),
        }],
        "X11Forwarding" => vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.2.6".to_string(),
            compliance_control_title: "Ensure SSH X11 forwarding is disabled".to_string(),
            compliance_section: Some("Access Control".to_string()),
        }],
        "ClientAliveInterval" | "ClientAliveCountMax" => vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.2.13".to_string(),
            compliance_control_title: "Ensure SSH Idle Timeout Interval is configured".to_string(),
            compliance_section: Some("Access Control".to_string()),
        }],
        _ => vec![],
    }
}

#[async_trait]
impl HardeningPlugin for SshHardeningPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_category: FindingCategory::Network,
            plugin_description: "Hardens OpenSSH server configuration".to_string(),
            plugin_id: PluginId::new("ssh-hardening"),
            plugin_name: "SSH Hardening".to_string(),
            plugin_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        // SSH hardening has no dependencies on other plugins
        vec![]
    }

    async fn scan(&self, ctx: &Context) -> Result<ScanResult> {
        let start_time = Instant::now();
        let mut findings = Vec::new();
        let plugin_id = PluginId::new("ssh-hardening");

        // Read the SSH configuration file using executor
        let config_content = match ctx
            .executor()
            .read_file(Path::new("/etc/ssh/sshd_config"))
            .await
        {
            Ok(content) => content,
            Err(e) => {
                // If we can't read the config, create a critical finding.
                let duration_us = start_time.elapsed().as_micros() as u64;
                return Ok(ScanResult {
                    scan_plugin_id: plugin_id,
                    scan_success: false,
                    scan_findings: vec![],
                    scan_duration_us: duration_us,
                    scan_error: Some(format!("Failed to read /etc/ssh/sshd_config: {}", e)),
                });
            }
        };

        // Check each SSH directive
        for directive in SSH_DIRECTIVES {
            let current_value = parse_config_value(
                &config_content,
                directive.ssh_directive_name,
                ConfigFormat::SpaceSeparated,
                false,
            );

            let is_insecure = match current_value {
                Some(ref value) => value != directive.ssh_secure_value,
                None => true, // Missing directive is insecure
            };

            if is_insecure {
                findings.push(Finding {
                    finding_category: FindingCategory::Network,
                    finding_current_value: current_value.unwrap_or_else(|| "not set".to_string()),
                    finding_description: directive.ssh_description.to_string(),
                    finding_explanation: format!(
                        "The SSH directive '{}' is not configured securely. {}",
                        directive.ssh_directive_name, directive.ssh_description,
                    ),
                    finding_id: format!("ssh-{}", directive.ssh_directive_name.to_lowercase()),
                    finding_impact: "May allow unauthorised access or weaken SSH security"
                        .to_string(),
                    finding_recommended_value: directive.ssh_secure_value.to_string(),
                    finding_remediation_steps: vec![
                        format!(
                            "Edit /etc/ssh/sshd_config and set: {} {}",
                            directive.ssh_directive_name, directive.ssh_secure_value,
                        ),
                        "Restart SSH service: systemctl restart sshd".to_string(),
                    ],
                    finding_severity: directive.ssh_severity,
                    finding_title: format!(
                        "Insecure SSH setting: {}",
                        directive.ssh_directive_name,
                    ),
                    finding_compliance: get_ssh_compliance_mappings(directive.ssh_directive_name),
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

    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> {
        let plugin_id = PluginId::new("ssh-hardening");
        let mut changes = Vec::new();
        let config_path = "/etc/ssh/sshd_config";

        // Step 1: Create checkpoint to capture current state before changes.
        let checkpoint_id = crate::create_checkpoint_for_apply(
            ctx,
            "ssh-hardening-pre-apply",
            &[Path::new(config_path)],
        )
        .await?;

        if checkpoint_id.is_some() {
            changes.push(Change {
                change_description: "Created checkpoint for rollback".to_string(),
                change_type: ChangeType::ConfigFile,
                change_success: true,
                change_error: None,
            });
        }

        // Step 2: Create backup (legacy backup in addition to checkpoint).
        let backup_path = format!(
            "{}.backup.{}",
            config_path,
            Utc::now().format("%Y%m%d_%H%M%S")
        );
        match ctx
            .executor()
            .execute_command("cp", &["-p", config_path, &backup_path])
            .await
        {
            Ok(output) if output.success() => {
                changes.push(Change {
                    change_description: format!("Created backup: {}", backup_path),
                    change_type: ChangeType::ConfigFile,
                    change_success: true,
                    change_error: None,
                });
                info!("SSH config backup created: {}", backup_path);
            }
            Ok(output) => {
                return Ok(ApplyResult {
                    apply_plugin_id: plugin_id,
                    apply_success: false,
                    apply_changes: changes,
                    apply_checkpoint_id: checkpoint_id,
                    apply_error: Some(format!("Failed to create backup: {}", output.stderr)),
                });
            }
            Err(e) => {
                return Ok(ApplyResult {
                    apply_plugin_id: plugin_id,
                    apply_success: false,
                    apply_changes: changes,
                    apply_checkpoint_id: checkpoint_id,
                    apply_error: Some(format!("Failed to create backup: {}", e)),
                });
            }
        }

        // Step 3: Read current configuration using executor.
        let mut config_content = ctx
            .executor()
            .read_file(Path::new(config_path))
            .await
            .map_err(|e| {
                hardener_common::error::HardeningError::Plugin(format!(
                    "Failed to read {}: {}",
                    config_path, e
                ))
            })?;

        // Step 3: Apply each directive.
        for directive in SSH_DIRECTIVES {
            // Check for a valid exception — skip this directive if exempted
            if let Some(exception) = config.has_valid_exception(directive.ssh_directive_name) {
                info!(
                    "Skipping {} — exception: {}",
                    directive.ssh_directive_name, exception.reason
                );
                changes.push(Change {
                    change_description: format!(
                        "{}: skipped (exception: {})",
                        directive.ssh_directive_name, exception.reason
                    ),
                    change_type: ChangeType::ConfigFile,
                    change_success: true,
                    change_error: None,
                });
                continue;
            }

            // Determine target value: user directive override or hardcoded baseline
            let target_value = config
                .directives
                .get(directive.ssh_directive_name)
                .map(|s| s.as_str())
                .unwrap_or(directive.ssh_secure_value);

            let original_value = parse_config_value(
                &config_content,
                directive.ssh_directive_name,
                ConfigFormat::SpaceSeparated,
                false,
            );

            let needs_change = match &original_value {
                Some(value) => value != target_value,
                None => true,
            };

            if needs_change {
                config_content = set_config_directive(
                    &config_content,
                    directive.ssh_directive_name,
                    target_value,
                    ConfigFormat::SpaceSeparated,
                    false,
                );

                changes.push(Change {
                    change_description: format!(
                        "{}: {} -> {}",
                        directive.ssh_directive_name,
                        original_value.unwrap_or_else(|| "not set".to_string()),
                        target_value
                    ),
                    change_type: ChangeType::ConfigFile,
                    change_success: true,
                    change_error: None,
                });

                info!(
                    "Applied SSH directive: {} = {}",
                    directive.ssh_directive_name, target_value
                );
            }
        }

        // Step 4: Write modified configuration using executor.
        match ctx
            .executor()
            .write_file(Path::new(config_path), &config_content)
            .await
        {
            Ok(_) => {
                changes.push(Change {
                    change_description: format!("Updated {}", config_path),
                    change_type: ChangeType::ConfigFile,
                    change_success: true,
                    change_error: None,
                });
                info!("SSH configuration updated successfully");
            }
            Err(e) => {
                changes.push(Change {
                    change_description: format!("Failed to write {}", config_path),
                    change_type: ChangeType::ConfigFile,
                    change_success: false,
                    change_error: Some(e.to_string()),
                });
                error!("Failed to write SSH config: {}", e);
            }
        }

        // Step 5: Restart SSH service to apply changes.
        match Self::restart_ssh_service(ctx).await {
            Ok(_) => {
                changes.push(Change {
                    change_description: "Restarted SSH service".to_string(),
                    change_type: ChangeType::Service,
                    change_success: true,
                    change_error: None,
                });
                info!("SSH service restarted successfully");
            }
            Err(e) => {
                changes.push(Change {
                    change_description: "Failed to restart SSH service".to_string(),
                    change_type: ChangeType::Service,
                    change_success: false,
                    change_error: Some(e.to_string()),
                });
                error!("Failed to restart SSH service: {}", e);
            }
        }

        let success = changes.iter().all(|c| c.change_success);
        Ok(ApplyResult {
            apply_plugin_id: plugin_id,
            apply_success: success,
            apply_changes: changes,
            apply_checkpoint_id: checkpoint_id,
            apply_error: None,
        })
    }

    async fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()> {
        info!(
            "Rolling back SSH configuration to checkpoint: {}",
            checkpoint.checkpoint_id.as_str()
        );

        // Use the common rollback helper
        crate::rollback_files_from_checkpoint(ctx, checkpoint)?;

        info!("SSH configuration files restored from checkpoint");

        // Restart SSH service to apply the restored configuration
        match Self::restart_ssh_service(ctx).await {
            Ok(_) => {
                info!("SSH service restarted after rollback");
            }
            Err(e) => {
                error!("Failed to restart SSH service after rollback: {}", e);
                return Err(e);
            }
        }

        Ok(())
    }

    async fn validate(&self, ctx: &Context, _config: &PluginConfig) -> Result<ValidationReport> {
        let mut issues = Vec::new();
        let plugin_id = PluginId::new("ssh-hardening");
        let config_path = Path::new("/etc/ssh/sshd_config");

        // Check if SSH config file exists and is readable using executor.
        match ctx.executor().file_metadata(config_path).await {
            Ok(metadata) => {
                // Check if it is a regular file.
                if !metadata.is_file {
                    issues.push(ValidationIssue {
                        validation_issue_severity: Severity::Critical,
                        validation_issue_message: format!(
                            "{} is not a regular file",
                            config_path.display()
                        ),
                        validation_issue_config_key: None,
                    });
                }
            }
            Err(e) => {
                issues.push(ValidationIssue {
                    validation_issue_severity: Severity::Critical,
                    validation_issue_message: format!(
                        "Cannot access {}: {}",
                        config_path.display(),
                        e
                    ),
                    validation_issue_config_key: None,
                });
            }
        }

        // Try to read the configuration and check which directives need changing.
        let mut estimated_changes = Vec::new();

        match ctx.executor().read_file(config_path).await {
            Ok(content) => {
                // Check each directive to see if it needs updating.
                for directive in SSH_DIRECTIVES {
                    // SSHD config is space-separated and case-insensitive.
                    let current_value = parse_config_value(
                        &content,
                        directive.ssh_directive_name,
                        ConfigFormat::SpaceSeparated,
                        false, // case-insensitive
                    );

                    match current_value {
                        Some(val) if val == directive.ssh_secure_value => {
                            // Already set to secure value - no change needed.
                        }
                        Some(val) => {
                            // Value exists but is insecure.
                            estimated_changes.push(format!(
                                "{}: {} → {}",
                                directive.ssh_directive_name, val, directive.ssh_secure_value
                            ));
                        }
                        None => {
                            // Directive not set - will add it.
                            estimated_changes.push(format!(
                                "{}: (not set) → {}",
                                directive.ssh_directive_name, directive.ssh_secure_value
                            ));
                        }
                    }
                }
            }
            Err(e) => {
                issues.push(ValidationIssue {
                    validation_issue_severity: Severity::Critical,
                    validation_issue_message: format!(
                        "Cannot read {}: {}",
                        config_path.display(),
                        e
                    ),
                    validation_issue_config_key: None,
                });
            }
        }

        let valid = issues.is_empty();
        Ok(ValidationReport {
            validation_report_plugin_id: plugin_id,
            validation_report_is_valid: valid,
            validation_report_issues: issues,
            validation_report_estimated_changes: estimated_changes,
        })
    }
}
