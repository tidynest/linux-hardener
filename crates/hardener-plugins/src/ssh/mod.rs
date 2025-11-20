//! SSH hardening plugin for OpenSSH server configuration management
//!
//! This plugin scans, applies and manages OpenSSH server security settings.
//! It focuses on critical authentication and protocol security including:
//!  - Disabling root login
//! - Enforcing key-based authentication
//! - Restricting protocol versions
//! - Limiting authentication attempts
//!
//! The plugin reads the sshd_config file, compares against secure baselines,
//! and can apply hardening configurations with automatic backup support.

use hardener_common::{
    error::Result,
    types::{
        FindingCategory,
        PluginId,
        Severity,
    }
};
use hardener_core::{context::Context, plugin::{
    Finding,
    HardeningPlugin,
    PluginMetadata,
    ScanResult,
}, ApplyResult, Checkpoint, Config, ValidationIssue, ValidationReport};
use std::{
    fs,
    time::Instant,
};

/// Represents a single SSH configuration directive to be hardened.
#[derive(Clone, Debug)]
struct SshConfigDirective {
    /// The directive name as it appears in sshd_config (e.g., "PermitRootLogin")
    ssh_directive_name: &'static str,
    /// The secure value for this directive (e.g., "no")
    ssh_secure_value: &'static str,
    /// Human-readable description of this directive's security purpose
    ssh_description: &'static str,
    /// Severity level if this directive is not set securely
    severity: Severity,
}

/// Critical SSH config directives for security hardening.
///
/// These represent the minimum baseline for secure SSH configuration.
const SSH_DIRECTIVES: &[SshConfigDirective] = &[
    SshConfigDirective {
        ssh_directive_name: "PermitRootLogin",
        ssh_secure_value:   "no",
        ssh_description:    "Disable direct root login via SSH",
        severity:           Severity::Critical,
    },
    SshConfigDirective {
        ssh_directive_name: "PasswordAuthentication",
        ssh_secure_value:   "no",
        ssh_description:    "Require key-based authentication only",
        severity:           Severity::Critical,
    },
    SshConfigDirective {
        ssh_directive_name: "PermitEmptyPasswords",
        ssh_secure_value:   "no",
        ssh_description:    "Disallow empty passwords",
        severity:           Severity::Critical,
    },
    SshConfigDirective {
        ssh_directive_name: "Protocol",
        ssh_secure_value:   "2",
        ssh_description:    "Use only SSH protocol version 2",
        severity:           Severity::Critical,
    },
    SshConfigDirective {
        ssh_directive_name: "MaxAuthTries",
        ssh_secure_value:   "3",
        ssh_description:    "Limit authentication attempts to prevent brute force",
        severity:           Severity::Medium,
    },
    SshConfigDirective {
        ssh_directive_name: "X11Forwarding",
        ssh_secure_value:   "no",
        ssh_description:    "Disable X11 forwarding to reduce attack surface",
        severity:           Severity::Medium,
    },
    SshConfigDirective {
        ssh_directive_name: "ClientAliveInterval",
        ssh_secure_value:   "300",
        ssh_description:    "Disconnect idle SSH sessions after 5 minutes",
        severity:           Severity::Low,
    },
    SshConfigDirective {
        ssh_directive_name: "ClientAliveCountMax",
        ssh_secure_value:   "2",
        ssh_description:    "Maximum idle connection checks before disconnect",
        severity:           Severity::Low,
    },
];

/// SSH hardening plugin implementing OpenSSH configuration management.
pub struct SshHardeningPlugin;

impl SshHardeningPlugin {
    /// Creates a new instance of the SSH hardening plugin.
    pub fn new() -> SshHardeningPlugin {
        SshHardeningPlugin
    }

    /// Reads the SSH daemon configuration file.
    ///
    /// # Returns
    /// The entire sshd_config file contents as a string, or an error if the file cannot be read.
    fn read_ssh_config() -> Result<String> {
        let config_path = "/etc/ssh/sshd_config";
        fs::read_to_string(config_path)
            .map_err(|e| hardener_common::error::HardeningError::Plugin(format!(
                "Failed to read {}: {}", config_path, e
            )))
    }

    /// Parses a specific directive value from the SSH config content.
    ///
    /// # Arguments
    /// * `config_content` - The full sshd_config file content
    /// * `directive_name` - The directive to search for (e.g., "PermitRootLogin")
    ///
    /// # Returns
    /// The directive's value if found, or None if not present or commented out.
    fn parse_ssh_directive(
        config_content: &str,
        directive_name: &str,
    ) -> Option<String> {
        for line in config_content.lines() {
            let trimmed = line.trim();

            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Split on whitespace to get directive and value
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 && parts[0].eq_ignore_ascii_case(directive_name) {
                return Some(parts[1].to_string());
            }
        }
        None
    }
}

impl HardeningPlugin for SshHardeningPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            id:          PluginId::new("ssh-hardening"),
            name:        "SSH Hardening".to_string(),
            version:     "0.1.0".to_string(),
            description: "Hardens OpenSSH server configuration".to_string(),
            category:    FindingCategory::Network,
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        // SSH hardening has no dependencies on other plugins
        vec![]
    }

    fn scan(
        &self,
        _ctx: &Context,
    ) -> Result<ScanResult> {
        let start_time = Instant::now();
        let mut findings = Vec::new();
        let plugin_id = PluginId::new("ssh-hardening");

        // Read the SSH configuration file
        let config_content = match Self::read_ssh_config() {
            Ok(content) => content,
            Err(e) => {
                // If we can't read the config, create a critical finding
                let duration_us = start_time.elapsed().as_micros() as u64;
                return Ok(ScanResult {
                    plugin_id,
                    success: false,
                    findings: vec![],
                    duration_us,
                    error: Some(format!("Failed to read /etc/ssh/sshd_config: {}", e)),
                });
            }
        };

        // Check each SSH directive
        for directive in SSH_DIRECTIVES {
            let current_value = Self::parse_ssh_directive(
                &config_content,
                directive.ssh_directive_name
            );

            let is_insecure = match current_value {
                Some(ref value) => value != directive.ssh_secure_value,
                None => true,  // Missing directive is insecure
            };

            if is_insecure {
                findings.push(Finding {
                    id: format!(
                        "ssh-{}",
                        directive.ssh_directive_name.to_lowercase()),
                    severity: directive.severity.clone(),
                    category: FindingCategory::Network,
                    title: format!(
                        "Insecure SSH setting: {}",
                        directive.ssh_directive_name,
                    ),
                    description: directive.ssh_description.to_string(),
                    current_value: current_value.unwrap_or_else(|| "not set".to_string()),
                    recommended_value: directive.ssh_secure_value.to_string(),
                    explanation: format!(
                        "The SSH directive '{}' is not configured securely. {}",
                        directive.ssh_directive_name,
                        directive.ssh_description,
                    ),
                    impact: "May allow unauthorised access or weaken SSH security".to_string(),
                    remediation_steps: vec![
                        format!(
                            "Edit /etc/ssh/sshd_config and set: {} {}",
                            directive.ssh_directive_name,
                            directive.ssh_secure_value,
                        ),
                        "Restart SSH service: systemctl restart sshd".to_string(),
                    ],
                });
            }
        }

        let duration_us = start_time.elapsed().as_micros() as u64;
        Ok(ScanResult {
            plugin_id,
            success: true,
            findings,
            duration_us,
            error: None,
        })
    }

    fn validate(
        &self,
        _config: &Config,
    ) -> Result<ValidationReport> {
        let mut issues  = Vec::new();
        let plugin_id   = PluginId::new("ssh-hardening");
        let config_path = "/etc/ssh/sshd_config";

        // Check if SSH config file exists and is readable
        match fs::metadata(config_path) {
            Ok(metadata) => {
                // Check if it's a regular file
                if !metadata.is_file() {
                    issues.push(ValidationIssue {
                        severity: Severity::Critical,
                        message: format!("{} is not a regular file", config_path),
                        config_key: None,
                    });
                }
            }
            Err(e) => {
                issues.push(ValidationIssue {
                    severity: Severity::Critical,
                    message: format!("Cannot access {}: {}", config_path, e),
                    config_key: None,
                });
            }
        }

        // Try tp read the configuration
        if let Err(e) = Self::read_ssh_config() {
            issues.push(ValidationIssue {
                severity: Severity::Critical,
                message:  format!("Cannot access {}: {}", config_path, e),
                config_key: None,
            });
        }

        let valid = issues.is_empty();
        Ok(ValidationReport {
            plugin_id,
            valid,
            issues,
            estimated_changes: vec![],
        })
    }

    fn apply(
    &self,
    _ctx: &mut Context,
    _config: &Config
    ) -> Result<ApplyResult> {
        let plugin_id   = PluginId::new("ssh-hardening");
        let changes = Vec::new();
        let _config_path = "/etc/ssh/sshd_config";

        // Read current configuration
        let _config_content = Self::read_ssh_config()?;

        // Full implementation will write secure SSH config.
        // For now a stub implementation is used
        tracing::warn!("SSH apply() method is not yet fully implemented - stub only");

        Ok(ApplyResult {
            plugin_id,
            success: true,
            changes,
            checkpoint_id: None,
            error: None,
        })
    }

    fn rollback(
        &self,
        _ctx: &mut Context,
        _checkpoint: &Checkpoint
    ) -> Result<()> {
        // Stub implementation - will be completed during checkpoint integration
        tracing::warn!("SSH rollback() method is not yet fully implemented - stub only");
        Ok(())
    }
}
