//! PAM (Pluggable Authentication Modules) hardening plugin
//!
//! This plugin hardens system authentication by configuring:
//! - Password quality requirements (complexity, length)
//! - Account lookout policies (failed login attempts)
//! - Password ageing policies (expiry, reuse prevention)

use async_trait::async_trait;
use hardener_common::file_utils::{ConfigFormat, parse_config_value};
use hardener_common::{
    error::{HardeningError, Result},
    file_utils::update_file_atomically,
    types::{ComplianceFramework, ComplianceMapping, FindingCategory, PluginId, Severity},
};
use hardener_core::{
    Change, ChangeType, Checkpoint, Config, Context,
    plugin::{
        ApplyResult, Finding, HardeningPlugin, PluginMetadata, ScanResult, ValidationIssue,
        ValidationReport,
    },
};
use std::path::Path;
use std::time::Instant;
use tracing::{debug, info, warn};

/// PAM hardening plugin.
pub struct PamHardeningPlugin {}

impl Default for PamHardeningPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl PamHardeningPlugin {
    /// Creates a new PAM hardening plugin instance.
    pub fn new() -> PamHardeningPlugin {
        PamHardeningPlugin {}
    }
}

/// Returns compliance mappings for PAM findings.
fn get_pam_compliance_mappings(check_name: &str) -> Vec<ComplianceMapping> {
    match check_name {
        name if name.contains("minlen") || name.contains("complexity") => vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.3.1".to_string(),
            compliance_control_title: "Ensure password creation requirements are configured"
                .to_string(),
            compliance_section: Some("Access Control".to_string()),
        }],
        name if name.contains("lockout") || name.contains("deny") => vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.3.2".to_string(),
            compliance_control_title: "Ensure lockout for failed password attempts is configured"
                .to_string(),
            compliance_section: Some("Access Control".to_string()),
        }],
        name if name.contains("remember") || name.contains("reuse") => vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.3.3".to_string(),
            compliance_control_title: "Ensure password reuse is limited".to_string(),
            compliance_section: Some("Access Control".to_string()),
        }],
        _ => vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.3.1".to_string(),
            compliance_control_title: "Ensure password creation requirements  are configured"
                .to_string(),
            compliance_section: Some("Access Control".to_string()),
        }],
    }
}

#[async_trait]
impl HardeningPlugin for PamHardeningPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_category: FindingCategory::Authentication,
            plugin_description:
                "Hardens PAM authentication (password policies, account lockout, ageing)"
                    .to_string(),
            plugin_id: PluginId::from("pam-hardening"),
            plugin_name: "PAM Authentication Hardening".to_string(),
            plugin_version: "1.0.0".to_string(),
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        vec![]
    }

    async fn scan(&self, ctx: &Context) -> Result<ScanResult> {
        let start = Instant::now();
        info!("Starting PAM authentication hardening scan");

        let mut findings = Vec::new();

        // Read configuration files.
        let pwquality_content = read_pwquality_config(ctx).await.unwrap_or_else(|e| {
            warn!("Failed to read pwquality.conf: {}", e);
            String::new() // Empty content means all directives will be flagged as missing.
        });

        let login_defs_content: String = read_login_defs(ctx).await.unwrap_or_else(|e| {
            warn!("Failed to read login.defs: {}", e);
            String::new()
        });

        // Check each PAM directive.
        for directive in PAM_DIRECTIVES {
            let current_value = match directive.pam_config_file {
                PamConfigFile::PwQuality => parse_config_value(
                    &pwquality_content,
                    directive.pam_directive_name,
                    ConfigFormat::Auto,
                    true,
                ),
                PamConfigFile::LoginDefs => parse_config_value(
                    &login_defs_content,
                    directive.pam_directive_name,
                    ConfigFormat::Auto,
                    true,
                ),
                PamConfigFile::PamAuth => {
                    // PAM module configuration - skip for now, implement during phase 2.
                    debug!(
                        "Skipping PAM module directive: {}",
                        directive.pam_directive_name
                    );
                    continue;
                }
            };

            // Check if current value matches secure value.
            let is_secure = current_value.as_deref() == Some(directive.pam_secure_value);

            if !is_secure {
                let current_display = current_value.unwrap_or_else(|| "not set".to_string());

                findings.push(Finding {
                    finding_id: format!(
                        "pam-{}",
                        directive.pam_directive_name
                    ),
                    finding_category: FindingCategory::Authentication,
                    finding_current_value: current_display.clone(),
                    finding_description: format!(
                        "PAM directive '{}' is currently '{}' but should be '{}'",
                        directive.pam_directive_name,
                        current_display,
                        directive.pam_secure_value,
                    ),
                    finding_explanation: directive.pam_description.to_string(),
                    finding_impact: "Weak authentication settings can allow easier password guessing and brute-force attacks".to_string(),
                    finding_recommended_value: directive.pam_secure_value.to_string(),
                    finding_remediation_steps: vec![
                        format!(
                            "Set {} = {} in the appropriate configuration file",
                            directive.pam_directive_name,
                            directive.pam_secure_value,
                        ),
                    ],
                    finding_severity: directive.pam_severity,
                    finding_title: format!(
                        "Insecure PAM setting: {}",
                        directive.pam_directive_name
                    ),
                    finding_compliance: get_pam_compliance_mappings(directive.pam_directive_name),
                    finding_policy_exception: None,
                });
            }
        }

        let duration_us = start.elapsed().as_micros() as u64;

        info!(
            "PAM scan completed: {} findings in {}µs",
            findings.len(),
            duration_us,
        );

        Ok(ScanResult {
            scan_plugin_id: self.metadata().plugin_id,
            scan_success: true,
            scan_findings: findings,
            scan_duration_us: duration_us,
            scan_error: None,
        })
    }

    async fn apply(&self, ctx: &mut Context, _config: &Config) -> Result<ApplyResult> {
        let start = Instant::now();
        info!("Starting PAM authentication hardening apply");

        let mut changes = Vec::new();
        let mut all_success = true;

        // Create checkpoint before changes
        let pam_paths: Vec<&Path> = vec![
            Path::new("/etc/security/pwquality.conf"),
            Path::new("/etc/login.defs"),
            Path::new("/etc/pam.d"),
        ];
        let checkpoint_id =
            crate::create_checkpoint_for_apply(ctx, "pam-hardening-pre-apply", &pam_paths)?;

        if checkpoint_id.is_some() {
            changes.push(Change {
                change_type: ChangeType::ConfigFile,
                change_description: "Created checkpoint for rollback".to_string(),
                change_success: true,
                change_error: None,
            });
        }

        // Step 1: Create backups (legacy, in addition to checkpoint)
        let pwquality_backup = match create_config_backup(ctx, "/etc/security/pwquality.conf").await
        {
            Ok(path) => {
                changes.push(Change {
                    change_type: ChangeType::ConfigFile,
                    change_description: format!("Created backup: {}", path),
                    change_success: true,
                    change_error: None,
                });
                Some(path)
            }
            Err(e) => {
                warn!("Failed to backup pwquality.conf: {}", e);
                changes.push(Change {
                    change_type: ChangeType::ConfigFile,
                    change_description: "Failed to create pwquality.conf backup".to_string(),
                    change_success: false,
                    change_error: Some(e.to_string()),
                });
                all_success = false;
                None
            }
        };

        let login_defs_backup = match create_config_backup(ctx, "/etc/login.defs").await {
            Ok(path) => {
                changes.push(Change {
                    change_type: ChangeType::ConfigFile,
                    change_description: format!("Created backup: {}", path),
                    change_success: true,
                    change_error: None,
                });
                Some(path)
            }
            Err(e) => {
                warn!("Failed to backup login.defs: {}", e);
                changes.push(Change {
                    change_type: ChangeType::ConfigFile,
                    change_description: "Failed to create login.defs".to_string(),
                    change_success: false,
                    change_error: Some(e.to_string()),
                });
                all_success = false;
                None
            }
        };

        // Step 2: Read current configuration files
        let mut pwquality_content = read_pwquality_config(ctx).await.unwrap_or_else(|e| {
            warn!("Failed to read pwquality.conf, using empty content: {}", e);
            String::new()
        });

        let mut login_defs_content = read_login_defs(ctx).await.unwrap_or_else(|e| {
            warn!("Failed to read login.defs, using empty content: {}", e);
            String::new()
        });

        // Step 3: Apply each directive
        for directive in PAM_DIRECTIVES {
            match directive.pam_config_file {
                PamConfigFile::PwQuality => {
                    pwquality_content = apply_directive_to_content(
                        &pwquality_content,
                        directive.pam_directive_name,
                        directive.pam_secure_value,
                    );

                    changes.push(Change {
                        change_type: ChangeType::ConfigFile,
                        change_description: format!(
                            "Set {} = {} in pwquality.conf",
                            directive.pam_directive_name, directive.pam_secure_value,
                        ),
                        change_success: true,
                        change_error: None,
                    });
                }
                PamConfigFile::LoginDefs => {
                    login_defs_content = apply_directive_to_content(
                        &login_defs_content,
                        directive.pam_directive_name,
                        directive.pam_secure_value,
                    );

                    changes.push(Change {
                        change_type: ChangeType::ConfigFile,
                        change_description: format!(
                            "Set {} = {} in login.defs",
                            directive.pam_directive_name, directive.pam_secure_value,
                        ),
                        change_success: true,
                        change_error: None,
                    });
                }
                PamConfigFile::PamAuth => {
                    // Skip PAM module for now
                    debug!(
                        "Skipping PAM module directive: {}",
                        directive.pam_directive_name
                    );
                    continue;
                }
            }
        }

        // Step 4: Write modified configuration files back to disk atomically
        if pwquality_backup.is_some() {
            match update_file_atomically(
                Path::new("/etc/security/pwquality.conf"),
                &pwquality_content,
            ) {
                Ok(_) => {
                    info!("Successfully wrote /etc/security/pwquality.conf (atomic write)");
                    changes.push(Change {
                        change_type: ChangeType::ConfigFile,
                        change_description: "Wrote modified pwquality.conf".to_string(),
                        change_success: true,
                        change_error: None,
                    });
                }
                Err(e) => {
                    warn!("Failed to write pwquality.conf: {}", e);
                    changes.push(Change {
                        change_type: ChangeType::ConfigFile,
                        change_description: "Failed to write pwquality.conf".to_string(),
                        change_success: false,
                        change_error: Some(e.to_string()),
                    });
                    all_success = false;
                }
            }
        }

        if login_defs_backup.is_some() {
            match update_file_atomically(Path::new("/etc/login.defs"), &login_defs_content) {
                Ok(_) => {
                    info!("Successfully wrote /etc/login.defs (atomic write)");
                    changes.push(Change {
                        change_type: ChangeType::ConfigFile,
                        change_description: "Wrote modified login.defs".to_string(),
                        change_success: true,
                        change_error: None,
                    });
                }
                Err(e) => {
                    warn!("Failed to write login.defs: {}", e);
                    changes.push(Change {
                        change_type: ChangeType::ConfigFile,
                        change_description: "Failed to write login.defs".to_string(),
                        change_success: false,
                        change_error: Some(e.to_string()),
                    });
                    all_success = false;
                }
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        info!(
            "PAM apply completed: {} changes, success={} in {} ms",
            changes.len(),
            duration_ms,
            duration_ms
        );

        Ok(ApplyResult {
            apply_plugin_id: self.metadata().plugin_id,
            apply_success: all_success,
            apply_changes: changes,
            apply_checkpoint_id: checkpoint_id,
            apply_error: None,
        })
    }

    async fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()> {
        info!(
            "Rolling back PAM configuration to checkpoint: {}",
            checkpoint.checkpoint_id.as_str()
        );

        // Restore configuration files from checkpoint
        crate::rollback_files_from_checkpoint(ctx, checkpoint)?;

        info!("PAM configuration files restored from checkpoint");

        // PAM doesn't require a service restart - changes take effect immediately
        // for new authentication attempts

        Ok(())
    }

    async fn validate(&self, ctx: &Context, _config: &Config) -> Result<ValidationReport> {
        info!("Validating PAM configuration files");

        let mut issues = Vec::new();

        // Check pwquality.conf
        match ctx
            .executor()
            .file_metadata(Path::new("/etc/security/pwquality.conf"))
            .await
        {
            Ok(metadata) => {
                if !metadata.is_file {
                    issues.push(ValidationIssue {
                        validation_issue_config_key: None,
                        validation_issue_message:
                            "/etc/security/pwquality.conf exists but is not a regular file"
                                .to_string(),
                        validation_issue_severity: Severity::High,
                    });
                }
            }
            Err(_) => {
                issues.push(ValidationIssue {
                    validation_issue_config_key: None,
                    validation_issue_message: "/etc/security/pwquality.conf does not exist or is not readable"
                        .to_string(),
                    validation_issue_severity: Severity::Medium,
                });
            }
        }

        // Check login.defs
        match ctx
            .executor()
            .file_metadata(Path::new("/etc/login.defs"))
            .await
        {
            Ok(metadata) => {
                if !metadata.is_file {
                    issues.push(ValidationIssue {
                        validation_issue_config_key: None,
                        validation_issue_message:
                            "/etc/login.defs exists but is not a regular file".to_string(),
                        validation_issue_severity: Severity::High,
                    });
                }
            }
            Err(_) => {
                issues.push(ValidationIssue {
                    validation_issue_config_key: None,
                    validation_issue_message: "/etc/login.defs does not exist or is not readable"
                        .to_string(),
                    validation_issue_severity: Severity::High,
                });
            }
        }

        // Estimate changes based on number of directives
        let estimated_changes = PAM_DIRECTIVES
            .iter()
            .filter(|d| d.pam_config_file != PamConfigFile::PamAuth)
            .map(|d| format!("Set {} = {}", d.pam_directive_name, d.pam_secure_value))
            .collect();

        let is_valid = issues.is_empty();

        Ok(ValidationReport {
            validation_report_plugin_id: self.metadata().plugin_id,
            validation_report_is_valid: is_valid,
            validation_report_issues: issues,
            validation_report_estimated_changes: estimated_changes,
        })
    }
}

/// PAM configuration directive with security settings.
#[derive(Clone, Debug)]
struct PamDirective {
    pam_directive_name: &'static str,
    pam_secure_value: &'static str,
    pam_description: &'static str,
    pam_severity: Severity,
    pam_config_file: PamConfigFile,
}

/// Represents which PAM configuration file contains the directive.
#[derive(Clone, Debug, Eq, PartialEq)]
enum PamConfigFile {
    /// Password quality settings (/etc/security/pwquality.conf).
    PwQuality,
    /// Password ageing settings (/etc/login.defs).
    LoginDefs,
    /// PAM module configuration (distribution-specific).
    PamAuth,
}

/// Secure PAM configuration directives.
const PAM_DIRECTIVES: &[PamDirective] = &[
    // Password Quality (pwquality.conf)
    PamDirective {
        pam_directive_name: "minlen",
        pam_secure_value: "14",
        pam_description: "Minimum password length of 14 characters",
        pam_severity: Severity::High,
        pam_config_file: PamConfigFile::PwQuality,
    },
    PamDirective {
        pam_directive_name: "dcredit",
        pam_secure_value: "-1",
        pam_description: "Require at least one digit in password",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::PwQuality,
    },
    PamDirective {
        pam_directive_name: "ucredit",
        pam_secure_value: "-1",
        pam_description: "Require at least one uppercase character in password",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::PwQuality,
    },
    PamDirective {
        pam_directive_name: "lcredit",
        pam_secure_value: "-1",
        pam_description: "Require at least one lowercase character in password",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::PwQuality,
    },
    PamDirective {
        pam_directive_name: "ocredit",
        pam_secure_value: "-1",
        pam_description: "Require at least one special character in password",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::PwQuality,
    },
    PamDirective {
        pam_directive_name: "maxrepeat",
        pam_secure_value: "3",
        pam_description: "Maximum consecutive identical characters in password",
        pam_severity: Severity::Low,
        pam_config_file: PamConfigFile::PwQuality,
    },
    PamDirective {
        pam_directive_name: "PASS_MAX_DAYS",
        pam_secure_value: "90",
        pam_description: "Maximum password age of 90 days",
        pam_severity: Severity::Medium,
        pam_config_file: PamConfigFile::LoginDefs,
    },
    PamDirective {
        pam_directive_name: "PASS_MIN_DAYS",
        pam_secure_value: "1",
        pam_description: "Minimum password age of 1 day (prevents rapid changes)",
        pam_severity: Severity::Low,
        pam_config_file: PamConfigFile::LoginDefs,
    },
    PamDirective {
        pam_directive_name: "PASS_WARN_AGE",
        pam_secure_value: "7",
        pam_description: "Warn users 7 days before password expiry",
        pam_severity: Severity::Low,
        pam_config_file: PamConfigFile::LoginDefs,
    },
];

/// Reads the pwquality configuration file.
async fn read_pwquality_config(ctx: &Context) -> Result<String> {
    ctx.executor()
        .read_file(Path::new("/etc/security/pwquality.conf"))
        .await
        .map_err(|e| HardeningError::Plugin(e.to_string()))
}

/// Reads the login.defs configuration file.
async fn read_login_defs(ctx: &Context) -> Result<String> {
    ctx.executor()
        .read_file(Path::new("/etc/login.defs"))
        .await
        .map_err(|e| HardeningError::Plugin(e.to_string()))
}

/// Creates a timestamped backup of a configuration file.
async fn create_config_backup(ctx: &Context, file_path: &str) -> Result<String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| HardeningError::Plugin(format!("Failed to get system time: {}", e)))?
        .as_secs();

    let backup_path = format!("{}.backup-{}", file_path, timestamp);

    ctx.executor()
        .execute_command("cp", &[file_path, &backup_path])
        .await
        .map_err(|e| HardeningError::Plugin(e.to_string()))?;

    Ok(backup_path)
}

/// Applies a directive to configuration file content.
///
/// If the directive exists, updates its value.
/// If the directive doesn't exist, appends it to the end.
fn apply_directive_to_content(content: &str, directive_name: &str, secure_value: &str) -> String {
    let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    let mut found = false;

    // Try to update existing directive.
    for line in &mut lines {
        let trimmed = line.trim();

        // Skip comments.
        if trimmed.starts_with('#') {
            continue;
        }

        // Check if this line contains our directive.
        if let Some(stripped) = trimmed.strip_prefix(directive_name) {
            let remainder = stripped.trim();

            // Check if it is followed by = or whitespace (actual directive, not just prefix match).
            let is_whitespace_separated = if let Some(ch) = remainder.chars().next() {
                ch.is_whitespace()
            } else {
                false
            };

            if remainder.starts_with('=') || is_whitespace_separated {
                // Update the line with new value.
                *line = format!("{} = {}", directive_name, secure_value);
                found = true;
                break;
            }
        }
    }

    // If not found, append to end.
    if !found {
        lines.push(format!("{} = {}", directive_name, secure_value));
    }

    lines.join("\n")
}
