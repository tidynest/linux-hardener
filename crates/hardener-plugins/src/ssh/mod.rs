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

use hardener_common::{
    error::Result,
    file_utils::update_file_atomically,
    types::{FindingCategory, PluginId, Severity},
};
use hardener_core::{
    ApplyResult, Change, ChangeType, Checkpoint, Config, ValidationIssue, ValidationReport,
    context::Context,
    plugin::{Finding, HardeningPlugin, PluginMetadata, ScanResult},
};
use std::{fs, path::Path, process::Command, time::Instant};

/// Represents a single SSH configuration directive to be hardened.
#[derive(Clone, Debug)]
struct SshConfigDirective {
    /// Human-readable description of this directive's security purpose.
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

    /// Reads the SSH daemon configuration file.
    ///
    /// # Returns
    /// The entire sshd_config file contents as a string, or an error if the file cannot be read.
    fn read_ssh_config() -> Result<String> {
        let config_path = "/etc/ssh/sshd_config";
        fs::read_to_string(config_path).map_err(|e| {
            hardener_common::error::HardeningError::Plugin(format!(
                "Failed to read {}: {}",
                config_path, e
            ))
        })
    }

    /// Parses a specific directive value from the SSH config content.
    ///
    /// # Arguments
    /// * `config_content` - The full sshd_config file content
    /// * `directive_name` - The directive to search for (e.g., "PermitRootLogin")
    ///
    /// # Returns
    /// The directive's value if found, or None if not present or commented out.
    fn parse_ssh_directive(config_content: &str, directive_name: &str) -> Option<String> {
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

    /// Creates a timestamped backup of the SSH configuration file.
    ///
    /// # Returns
    /// The path to the backup file on success, or an error if backup fails.
    fn create_ssh_backup() -> Result<String> {
        let config_path = "/etc/ssh/sshd_config";
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| {
                hardener_common::error::HardeningError::Plugin(format!(
                    "Failed to get timestamp: {}",
                    e
                ))
            })?
            .as_secs();

        let backup_path = format!("{}.backup.{}", config_path, timestamp);

        fs::copy(config_path, &backup_path).map_err(|e| {
            hardener_common::error::HardeningError::Plugin(format!(
                "Failed to create backup at {}: {}",
                backup_path, e
            ))
        })?;

        tracing::info!("Created SSH config backup: {}", backup_path);
        Ok(backup_path)
    }

    /// Modifies SSH configuration content to apply secure directives.
    ///
    /// This updates existing directives or adds them if missing.
    ///
    /// # Arguments
    /// * `config_content` - The current sshd_config file content.
    /// * `directive`      - The directive to set securely.
    ///
    /// # Returns
    /// Modified configuration content with the directive set to the secure value.
    fn apply_ssh_directive(config_content: &str, directive: &SshConfigDirective) -> String {
        let mut lines: Vec<String> = config_content.lines().map(String::from).collect();
        let mut directive_found = false;

        // First pass: update existing directive.
        for line in &mut lines {
            let trimmed = line.trim();

            // Skip empty lines.
            if trimmed.is_empty() {
                continue;
            }

            // Check else if this line is out directive (active or commented).
            let parts: Vec<&str> = trimmed.trim_start_matches('#').split_whitespace().collect();
            if !parts.is_empty() && parts[0].eq_ignore_ascii_case(directive.ssh_directive_name) {
                // Replace the line with secure setting.
                *line = format!(
                    "{} {}",
                    directive.ssh_directive_name, directive.ssh_secure_value
                );
                directive_found = true;
                break;
            }
        }

        // Second pass: add directive if not found.
        if !directive_found {
            lines.push(format!(
                "{} {}",
                directive.ssh_directive_name, directive.ssh_secure_value
            ));
        }

        lines.join("\n")
    }

    /// Restarts the SSH daemon to apply configuration changes.
    ///
    /// Attempts to restart using systemctl (systemd) first, then falls back
    /// to service command for non-systemd systems.
    ///
    /// # Returns
    /// Ok(()) if restart succeeded, or an error describing the failure.
    fn restart_ssh_service() -> Result<()> {
        // Try systemctl first (most modern distribution).
        let systemctl_result = Command::new("systemctl")
            .arg("restart")
            .arg("sshd")
            .output();

        match systemctl_result {
            Ok(output) if output.status.success() => {
                tracing::info!("SSH service restarted successfully via systemctl");
                return Ok(());
            }
            Ok(output) => {
                tracing::warn!("systemctl restart sshd failed: {:?}", output.stderr);
            }
            Err(e) => {
                tracing::warn!("systemctl command failed: {}", e);
            }
        }

        // Fallback to service command.
        let service_result = Command::new("service").arg("ssh").arg("restart").output();

        match service_result {
            Ok(output) if output.status.success() => {
                tracing::info!("SSH service restarted successfully via service command");
                Ok(())
            }
            Ok(output) => Err(hardener_common::error::HardeningError::Plugin(format!(
                "Failed to restart SSH service: {}",
                String::from_utf8_lossy(&output.stderr)
            ))),
            Err(e) => Err(hardener_common::error::HardeningError::Plugin(format!(
                "Failed to execute service restart command: {}",
                e
            ))),
        }
    }
}

impl HardeningPlugin for SshHardeningPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_category: FindingCategory::Network,
            plugin_description: "Hardens OpenSSH server configuration".to_string(),
            plugin_id: PluginId::new("ssh-hardening"),
            plugin_name: "SSH Hardening".to_string(),
            plugin_version: "0.1.0".to_string(),
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        // SSH hardening has no dependencies on other plugins
        vec![]
    }

    fn scan(&self, _ctx: &Context) -> Result<ScanResult> {
        let start_time = Instant::now();
        let mut findings = Vec::new();
        let plugin_id = PluginId::new("ssh-hardening");

        // Read the SSH configuration file
        let config_content = match Self::read_ssh_config() {
            Ok(content) => content,
            Err(e) => {
                // If we can't read the config, create a critical finding.
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
            let current_value =
                Self::parse_ssh_directive(&config_content, directive.ssh_directive_name);

            let is_insecure = match current_value {
                Some(ref value) => value != directive.ssh_secure_value,
                None => true, // Missing directive is insecure
            };

            if is_insecure {
                findings.push(Finding {
                    category: FindingCategory::Network,
                    current_value: current_value.unwrap_or_else(|| "not set".to_string()),
                    description: directive.ssh_description.to_string(),
                    explanation: format!(
                        "The SSH directive '{}' is not configured securely. {}",
                        directive.ssh_directive_name, directive.ssh_description,
                    ),
                    finding_id: format!("ssh-{}", directive.ssh_directive_name.to_lowercase()),
                    impact: "May allow unauthorised access or weaken SSH security".to_string(),
                    recommended_value: directive.ssh_secure_value.to_string(),
                    remediation_steps: vec![
                        format!(
                            "Edit /etc/ssh/sshd_config and set: {} {}",
                            directive.ssh_directive_name, directive.ssh_secure_value,
                        ),
                        "Restart SSH service: systemctl restart sshd".to_string(),
                    ],
                    severity: directive.ssh_severity,
                    title: format!("Insecure SSH setting: {}", directive.ssh_directive_name,),
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

    fn apply(&self, _ctx: &mut Context, _config: &Config) -> Result<ApplyResult> {
        let plugin_id = PluginId::new("ssh-hardening");
        let mut changes = Vec::new();
        let config_path = "/etc/ssh/sshd_config";

        // Step 1: Create backup.
        match Self::create_ssh_backup() {
            Ok(backup_path) => {
                changes.push(Change {
                    description: format!("Created backup: {}", backup_path),
                    change_type: ChangeType::ConfigFile,
                    success: true,
                    error: None,
                });
                tracing::info!("SSH config backup created: {}", backup_path);
            }
            Err(e) => {
                return Ok(ApplyResult {
                    plugin_id,
                    success: false,
                    changes,
                    checkpoint_id: None,
                    error: Some(format!("Failed to create backup: {}", e)),
                });
            }
        }

        // Step 2: Read current configuration.
        let mut config_content = Self::read_ssh_config()?;

        // Step 3: Apply each directive.
        for directive in SSH_DIRECTIVES {
            let original_value =
                Self::parse_ssh_directive(&config_content, directive.ssh_directive_name);

            // Check if change is needed.
            let needs_change = match &original_value {
                Some(value) => value != directive.ssh_secure_value,
                None => true,
            };

            if needs_change {
                config_content = Self::apply_ssh_directive(&config_content, directive);

                changes.push(Change {
                    description: format!(
                        "{}: {} → {}",
                        directive.ssh_directive_name,
                        original_value.unwrap_or_else(|| "not set".to_string()),
                        directive.ssh_secure_value
                    ),
                    change_type: ChangeType::ConfigFile,
                    success: true,
                    error: None,
                });

                tracing::info!(
                    "Applied SSH directive: {} = {}",
                    directive.ssh_directive_name,
                    directive.ssh_secure_value
                );
            }
        }

        // Step 4: Write modified configuration atomically.
        match update_file_atomically(Path::new(config_path), &config_content) {
            Ok(_) => {
                changes.push(Change {
                    description: format!("Updated {}", config_path),
                    change_type: ChangeType::ConfigFile,
                    success: true,
                    error: None,
                });
                tracing::info!("SSH configuration updated successfully (atomic write)");
            }
            Err(e) => {
                changes.push(Change {
                    description: format!("Failed to write {}", config_path),
                    change_type: ChangeType::ConfigFile,
                    success: false,
                    error: Some(e.to_string()),
                });
                tracing::error!("Failed to write SSH config: {}", e);
            }
        }

        // Step 5: Restart SSH service to apply changes.
        match Self::restart_ssh_service() {
            Ok(_) => {
                changes.push(Change {
                    description: "Restarted SSH service".to_string(),
                    change_type: ChangeType::Service,
                    success: true,
                    error: None,
                });
                tracing::info!("SSH service restarted successfully");
            }
            Err(e) => {
                changes.push(Change {
                    description: "Failed to restart SSH service".to_string(),
                    change_type: ChangeType::Service,
                    success: false,
                    error: Some(e.to_string()),
                });
                tracing::error!("Failed to restart SSH service: {}", e);
            }
        }

        let success = changes.iter().all(|c| c.success);
        Ok(ApplyResult {
            plugin_id,
            success,
            changes,
            checkpoint_id: None,
            error: None,
        })
    }

    fn rollback(&self, _ctx: &mut Context, _checkpoint: &Checkpoint) -> Result<()> {
        // Stub implementation - will be completed during checkpoint integration
        tracing::warn!("SSH rollback() method is not yet fully implemented - stub only");
        Ok(())
    }

    fn validate(&self, _config: &Config) -> Result<ValidationReport> {
        let mut issues = Vec::new();
        let plugin_id = PluginId::new("ssh-hardening");
        let config_path = "/etc/ssh/sshd_config";

        // Check if SSH config file exists and is readable.
        match fs::metadata(config_path) {
            Ok(metadata) => {
                // Check if it is a regular file.
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

        // Try to read the configuration.
        if let Err(e) = Self::read_ssh_config() {
            issues.push(ValidationIssue {
                severity: Severity::Critical,
                message: format!("Cannot access {}: {}", config_path, e),
                config_key: None,
            });
        }

        // Test.
        let valid = issues.is_empty();
        Ok(ValidationReport {
            plugin_id,
            is_valid: valid,
            issues,
            estimated_changes: vec![],
        })
    }
}
