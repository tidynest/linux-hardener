//! PAM (Pluggable Authentication Modules) hardening plugin
//!
//! This plugin hardens system authentication by configuring:
//! - Password quality requirements (complexity, length)
//! - Account lockout policies (failed login attempts)
//! - Password ageing policies (expiry, reuse prevention)

use async_trait::async_trait;
use hardener_common::file_utils::{ConfigFormat, parse_config_value};
use hardener_common::{
    error::{HardeningError, Result},
    types::{ComplianceFramework, ComplianceMapping, FindingCategory, PluginId, Severity},
};
use hardener_core::{
    Change, ChangeType, Checkpoint, Context, PluginConfig,
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

/// Builds a single [`ComplianceMapping`] under the shared "Access Control" section.
///
/// Keeps the per-check mapping tables below terse and free of repetition.
fn pam_mapping(framework: ComplianceFramework, control_id: &str, title: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: framework,
        compliance_control_id: control_id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some("Access Control".to_string()),
    }
}

/// Returns compliance mappings for PAM findings.
///
/// Multi-framework control IDs are sourced from the ComplianceAsCode/SSG rule
/// `references:` blocks for the matching SSG rule (cited per arm). NIST IDs use
/// 800-53 Rev 5 base controls; STIG IDs are the RHEL 8 DISA STIG group IDs;
/// PCI-DSS uses v4.0 requirement numbers. A framework is omitted where the SSG
/// rule carries no authoritative mapping for it.
fn get_pam_compliance_mappings(check_name: &str) -> Vec<ComplianceMapping> {
    match check_name {
        // SSG: accounts_password_pam_minlen (stigid RHEL-08-020230)
        name if name.contains("minlen") || name.contains("complexity") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.3.1",
                "Ensure password creation requirements are configured",
            ),
            pam_mapping(
                ComplianceFramework::STIG,
                "RHEL-08-020230",
                "RHEL 8 passwords must have a minimum of 15 characters",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "IA-5(1)(a)",
                "Authenticator Management | Password-Based Authentication",
            ),
            pam_mapping(
                ComplianceFramework::PCIDSS,
                "8.2.3",
                "Strong passwords and passphrases",
            ),
        ],
        // SSG: accounts_password_pam_dcredit (stigid RHEL-08-020130)
        name if name.contains("dcredit") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.3.1",
                "Ensure password creation requirements are configured",
            ),
            pam_mapping(
                ComplianceFramework::STIG,
                "RHEL-08-020130",
                "RHEL 8 must enforce password complexity by requiring at least one numeric character",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "IA-5(1)(a)",
                "Authenticator Management | Password-Based Authentication",
            ),
            pam_mapping(
                ComplianceFramework::PCIDSS,
                "8.2.3",
                "Strong passwords and passphrases",
            ),
        ],
        // SSG: accounts_password_pam_ucredit (stigid RHEL-08-020110)
        name if name.contains("ucredit") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.3.1",
                "Ensure password creation requirements are configured",
            ),
            pam_mapping(
                ComplianceFramework::STIG,
                "RHEL-08-020110",
                "RHEL 8 must enforce password complexity by requiring at least one uppercase character",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "IA-5(1)(a)",
                "Authenticator Management | Password-Based Authentication",
            ),
            pam_mapping(
                ComplianceFramework::PCIDSS,
                "8.2.3",
                "Strong passwords and passphrases",
            ),
        ],
        // SSG: accounts_password_pam_lcredit (stigid RHEL-08-020120)
        name if name.contains("lcredit") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.3.1",
                "Ensure password creation requirements are configured",
            ),
            pam_mapping(
                ComplianceFramework::STIG,
                "RHEL-08-020120",
                "RHEL 8 must enforce password complexity by requiring at least one lowercase character",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "IA-5(1)(a)",
                "Authenticator Management | Password-Based Authentication",
            ),
            pam_mapping(
                ComplianceFramework::PCIDSS,
                "8.2.3",
                "Strong passwords and passphrases",
            ),
        ],
        // SSG: accounts_password_pam_ocredit (stigid RHEL-08-020280). No PCI-DSS in SSG.
        name if name.contains("ocredit") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.3.1",
                "Ensure password creation requirements are configured",
            ),
            pam_mapping(
                ComplianceFramework::STIG,
                "RHEL-08-020280",
                "RHEL 8 must enforce password complexity by requiring at least one special character",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "IA-5(1)(a)",
                "Authenticator Management | Password-Based Authentication",
            ),
        ],
        // SSG: accounts_password_pam_maxrepeat (stigid RHEL-08-020150). No PCI-DSS in SSG.
        name if name.contains("maxrepeat") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.3.1",
                "Ensure password creation requirements are configured",
            ),
            pam_mapping(
                ComplianceFramework::STIG,
                "RHEL-08-020150",
                "RHEL 8 passwords must not contain more than three consecutive repeating characters",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "IA-5(1)(a)",
                "Authenticator Management | Password-Based Authentication",
            ),
        ],
        // SSG: accounts_passwords_pam_faillock_deny (stigid RHEL-08-020011)
        name if name.contains("lockout") || name.contains("deny") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.3.2",
                "Ensure lockout for failed password attempts is configured",
            ),
            pam_mapping(
                ComplianceFramework::STIG,
                "RHEL-08-020011",
                "RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "AC-7(a)",
                "Unsuccessful Logon Attempts",
            ),
            pam_mapping(
                ComplianceFramework::PCIDSS,
                "8.1.6",
                "Limit repeated access attempts by locking out the user ID",
            ),
        ],
        // SSG: accounts_password_pam_pwhistory_remember. SSG rule carries no
        // NIST/STIG/PCI-DSS reference, so only CIS is mapped (no guessing).
        name if name.contains("remember") || name.contains("reuse") => vec![pam_mapping(
            ComplianceFramework::CIS,
            "5.3.3",
            "Ensure password reuse is limited",
        )],
        // SSG: accounts_maximum_age_login_defs (stigid RHEL-08-020200)
        name if name.contains("PASS_MAX_DAYS") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.4.1.1",
                "Ensure password expiration is 365 days or less",
            ),
            pam_mapping(
                ComplianceFramework::STIG,
                "RHEL-08-020200",
                "RHEL 8 user account passwords must have a 60-day maximum password lifetime restriction",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "IA-5(1)(d)",
                "Authenticator Management | Password-Based Authentication",
            ),
            pam_mapping(
                ComplianceFramework::PCIDSS,
                "8.2.4",
                "Change user passwords/passphrases at least once every 90 days",
            ),
        ],
        // SSG: accounts_minimum_age_login_defs (stigid RHEL-08-020190). No PCI-DSS in SSG.
        name if name.contains("PASS_MIN_DAYS") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.4.1.2",
                "Ensure minimum days between password changes is configured",
            ),
            pam_mapping(
                ComplianceFramework::STIG,
                "RHEL-08-020190",
                "RHEL 8 passwords for new users must have a minimum of 24 hours between password changes",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "IA-5(1)(d)",
                "Authenticator Management | Password-Based Authentication",
            ),
        ],
        // SSG: accounts_password_warn_age_login_defs. SSG rule carries no STIG, so
        // STIG is omitted; NIST and PCI-DSS are mapped from its references block.
        name if name.contains("PASS_WARN_AGE") => vec![
            pam_mapping(
                ComplianceFramework::CIS,
                "5.4.1.3",
                "Ensure password expiration warning days is 7 or more",
            ),
            pam_mapping(
                ComplianceFramework::NIST,
                "IA-5(1)(d)",
                "Authenticator Management | Password-Based Authentication",
            ),
            pam_mapping(
                ComplianceFramework::PCIDSS,
                "8.2.4",
                "Change user passwords/passphrases at least once every 90 days",
            ),
        ],
        _ => vec![pam_mapping(
            ComplianceFramework::CIS,
            "5.3.1",
            "Ensure password creation requirements are configured",
        )],
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
            plugin_version: env!("CARGO_PKG_VERSION").to_string(),
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

    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> {
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
            crate::create_checkpoint_for_apply(ctx, "pam-hardening-pre-apply", &pam_paths).await?;

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
            // Check for a valid exception — skip this directive if exempted
            if let Some(exception) = config.has_valid_exception(directive.pam_directive_name) {
                info!(
                    "Skipping {} — exception: {}",
                    directive.pam_directive_name, exception.reason
                );
                changes.push(Change {
                    change_type: ChangeType::ConfigFile,
                    change_description: format!(
                        "{}: skipped (exception: {})",
                        directive.pam_directive_name, exception.reason
                    ),
                    change_success: true,
                    change_error: None,
                });
                continue;
            }

            // Determine target value: user directive override or hardcoded baseline
            let target_value = config
                .directives
                .get(directive.pam_directive_name)
                .map(|s| s.as_str())
                .unwrap_or(directive.pam_secure_value);

            match directive.pam_config_file {
                PamConfigFile::PwQuality => {
                    pwquality_content = apply_directive_to_content(
                        &pwquality_content,
                        directive.pam_directive_name,
                        target_value,
                    );

                    changes.push(Change {
                        change_type: ChangeType::ConfigFile,
                        change_description: format!(
                            "Set {} = {} in pwquality.conf",
                            directive.pam_directive_name, target_value,
                        ),
                        change_success: true,
                        change_error: None,
                    });
                }
                PamConfigFile::LoginDefs => {
                    login_defs_content = apply_directive_to_content(
                        &login_defs_content,
                        directive.pam_directive_name,
                        target_value,
                    );

                    changes.push(Change {
                        change_type: ChangeType::ConfigFile,
                        change_description: format!(
                            "Set {} = {} in login.defs",
                            directive.pam_directive_name, target_value,
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
            match ctx
                .executor()
                .write_file(
                    Path::new("/etc/security/pwquality.conf"),
                    &pwquality_content,
                )
                .await
            {
                Ok(_) => {
                    info!("Successfully wrote /etc/security/pwquality.conf");
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
            match ctx
                .executor()
                .write_file(Path::new("/etc/login.defs"), &login_defs_content)
                .await
            {
                Ok(_) => {
                    info!("Successfully wrote /etc/login.defs");
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
            all_success,
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

    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> {
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

        // Estimate changes based on non-excepted directives
        let estimated_changes = PAM_DIRECTIVES
            .iter()
            .filter(|d| d.pam_config_file != PamConfigFile::PamAuth)
            .filter(|d| config.has_valid_exception(d.pam_directive_name).is_none())
            .map(|d| {
                let target_value = config
                    .directives
                    .get(d.pam_directive_name)
                    .map(|s| s.as_str())
                    .unwrap_or(d.pam_secure_value);
                format!("Set {} = {}", d.pam_directive_name, target_value)
            })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirms a representative PAM finding (minimum password length) now
    /// carries multi-framework mappings: CIS (existing) plus STIG, NIST and
    /// PCI-DSS sourced from the SSG `accounts_password_pam_minlen` rule.
    #[test]
    fn pam_minlen_maps_cis_stig_nist_and_pcidss() {
        let frameworks: Vec<ComplianceFramework> = get_pam_compliance_mappings("minlen")
            .iter()
            .map(|m| m.compliance_framework)
            .collect();

        for expected in [
            ComplianceFramework::CIS,
            ComplianceFramework::STIG,
            ComplianceFramework::NIST,
            ComplianceFramework::PCIDSS,
        ] {
            assert!(
                frameworks.contains(&expected),
                "minlen must map framework {expected:?}"
            );
        }
    }
}
