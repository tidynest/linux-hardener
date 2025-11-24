//! Service Minimisation Plugin
//!
//! This plugin identifies and disables unnecessary systemd services to reduce
//! the attack surface of the system. It focuses on services that are commonly
//! enabled by default but not required for typical server operations.
//!
//! The plugin uses systemctl to manage services on all supported distributions
//! (all target distributions use systemd)

use hardener_common::{
    error::Result,
    types::{FindingCategory, PluginId, Severity},
};
use hardener_core::{
    ApplyResult, Change, ChangeType, Checkpoint, Config, ValidationIssue, ValidationReport,
    context::Context,
    plugin::{Finding, HardeningPlugin, PluginMetadata, ScanResult},
};
use std::{process::Command, time::Instant};
use tracing::warn;

/// Service Minimisation Plugin
///
/// Identifies and disables unnecessary systemd services to reduce attack surface.
pub struct ServicesHardeningPlugin {}

impl Default for ServicesHardeningPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl ServicesHardeningPlugin {
    /// Creates a new instance of the Services Plugin.
    pub fn new() -> ServicesHardeningPlugin {
        ServicesHardeningPlugin {}
    }
}

/// Represents a service that should be disabled for security hardening.
struct ServiceDirective {
    service_description: &'static str,
    service_name: &'static str,
    service_issue_severity: Severity,
}

/// List of unnecessary services that should be disabled.
///
/// These services are commonly enabled by default but not required for
/// typical server operations. Disabling them reduces attack surface.
const UNNECESSARY_SERVICES: &[ServiceDirective] = &[
    ServiceDirective {
        service_description: "Bluetooth service - rarely needed on servers",
        service_name: "bluetooth",
        service_issue_severity: Severity::High,
    },
    ServiceDirective {
        service_description: "Printing service - not needed on most servers",
        service_name: "cups",
        service_issue_severity: Severity::Medium,
    },
    ServiceDirective {
        service_description: "Network discovery service - potential information disclosure",
        service_name: "avahi-daemon",
        service_issue_severity: Severity::Medium,
    },
    ServiceDirective {
        service_description: "Modem management - not needed without mobile broadband",
        service_name: "ModemManager",
        service_issue_severity: Severity::Low,
    },
];

/// Checks if a systemd service unit exists on the system.
fn is_service_exists(service_name: &str) -> Result<bool> {
    let output = Command::new("systemctl")
        .args(["list-unit-files", service_name])
        .output()
        .map_err(hardener_common::error::HardeningError::System)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains(service_name))
}

/// Checks if a service is enabled to start at boot.
fn is_service_enabled(service_name: &str) -> Result<bool> {
    let output = Command::new("systemctl")
        .args(["is-enabled", service_name])
        .output()
        .map_err(hardener_common::error::HardeningError::System)?;

    Ok(output.status.success())
}

/// Checks if a service is currently active (running).
fn is_service_active(service_name: &str) -> Result<bool> {
    let output = Command::new("systemctl")
        .args(["is-active", service_name])
        .output()
        .map_err(hardener_common::error::HardeningError::System)?;

    Ok(output.status.success())
}

/// Stops a running service.
fn stop_service(service_name: &str) -> Result<()> {
    Command::new("systemctl")
        .args(["stop", service_name])
        .output()
        .map_err(hardener_common::error::HardeningError::System)?;

    Ok(())
}

/// Disable a service from starting at boot.
fn disable_service(service_name: &str) -> Result<()> {
    Command::new("systemctl")
        .args(["disable", service_name])
        .output()
        .map_err(hardener_common::error::HardeningError::System)?;

    Ok(())
}

/// Masks a service to prevent it from being started.
fn mask_service(service_name: &str) -> Result<()> {
    Command::new("systemctl")
        .args(["mask", service_name])
        .output()
        .map_err(hardener_common::error::HardeningError::System)?;

    Ok(())
}

impl HardeningPlugin for ServicesHardeningPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_category: FindingCategory::Services,
            plugin_description: "Identifies and disables unnecessary systemd services".to_string(),
            plugin_id: PluginId::new("service-minimisation"),
            plugin_name: "Service Minimisation".to_string(),
            plugin_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        vec![]
    }

    fn validate(&self, _config: &Config) -> Result<ValidationReport> {
        let mut estimated_changes = Vec::new();
        let mut issues = Vec::new();

        // Check if systemctl is available
        let systemctl_check = Command::new("which").arg("systemctl").status();

        match systemctl_check {
            Ok(status) if status.success() => {
                // systemctl is available, list services that would be disabled
                for directive in UNNECESSARY_SERVICES {
                    if let Ok(true) = is_service_exists(directive.service_name) {
                        let is_enabled =
                            is_service_enabled(directive.service_name).unwrap_or(false);
                        let is_active = is_service_active(directive.service_name).unwrap_or(false);
                        if is_enabled || is_active {
                            estimated_changes.push(format!(
                                "Disable and mask service: {}",
                                directive.service_name
                            ));
                        }
                    }
                }
            }
            _ => {
                issues.push(ValidationIssue {
                    validation_issue_config_key: None,
                    validation_issue_message: "systemctl command not found - this plugin requires systemd"
                        .to_string(),
                    validation_issue_severity: Severity::Critical,
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

    fn scan(&self, _ctx: &Context) -> Result<ScanResult> {
        let start = Instant::now();
        let mut findings = Vec::new();

        // Check each service in our list
        for directive in UNNECESSARY_SERVICES {
            // Skip if service doesn't exist on the system
            if !is_service_exists(directive.service_name).unwrap_or(false) {
                continue;
            }

            let is_enabled = is_service_enabled(directive.service_name).unwrap_or(false);
            let is_active = is_service_active(directive.service_name).unwrap_or(false);

            // Only create finding if service is enabled or active
            if is_enabled || is_active {
                let current_state = if is_enabled && is_active {
                    "enabled and active"
                } else if is_enabled {
                    "enabled"
                } else {
                    "active"
                };

                findings.push(Finding {
                    finding_category: FindingCategory::Services,
                    finding_current_value: current_state.to_string(),
                    finding_description: directive.service_description.to_string(),
                    finding_explanation: format!(
                        "Service {} is currently {}. {}",
                        directive.service_name, current_state, directive.service_description
                    ),
                    finding_id: format!("service_{}", directive.service_name.replace("-", "_")),
                    finding_impact: "Reduces attack surface by disabling unnecessary service".to_string(),
                    finding_recommended_value: "disabled and masked".to_string(),
                    finding_remediation_steps: vec![
                        format!("systemctl stop {}", directive.service_name),
                        format!("systemctl disable {}", directive.service_name),
                        format!("systemctl mask {}", directive.service_name),
                    ],
                    finding_severity: directive.service_issue_severity,
                    finding_title: format!("Unnecessary service {} is running", directive.service_name),
                });
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

    fn apply(&self, _ctx: &mut Context, _config: &Config) -> Result<ApplyResult> {
        let _start = Instant::now();
        let mut changes = Vec::new();

        // Process each service
        for directive in UNNECESSARY_SERVICES {
            // Skip if service does not exist
            if !is_service_exists(directive.service_name).unwrap_or(false) {
                continue;
            }

            let is_enabled = is_service_enabled(directive.service_name).unwrap_or(false);
            let is_active = is_service_active(directive.service_name).unwrap_or(false);

            // Only process if service is enabled or active
            if !is_enabled || !is_active {
                continue;
            }

            // Stop the service if it is running
            if is_active {
                match stop_service(directive.service_name) {
                    Ok(_) => {
                        changes.push(Change {
                            change_type: ChangeType::Service,
                            change_description: format!("Stopped service {}", directive.service_name),
                            change_error: None,
                            change_success: true,
                        });
                    }
                    Err(e) => {
                        changes.push(Change {
                            change_type: ChangeType::Service,
                            change_description: format!(
                                "Failed to stop service {}",
                                directive.service_name
                            ),
                            change_error: Some(e.to_string()),
                            change_success: false,
                        });
                        continue; // Skip disable/mask if stop failed
                    }
                }
            }

            // Disable the service
            if is_enabled {
                match disable_service(directive.service_name) {
                    Ok(_) => {
                        changes.push(Change {
                            change_type: ChangeType::Service,
                            change_description: format!("Disabled service {}", directive.service_name),
                            change_error: None,
                            change_success: true,
                        });
                    }
                    Err(e) => {
                        changes.push(Change {
                            change_type: ChangeType::Service,
                            change_description: format!(
                                "Failed to disable service {}",
                                directive.service_name
                            ),
                            change_error: Some(e.to_string()),
                            change_success: false,
                        });
                    }
                }
            }

            // Mask the service (prevents re-enabling)
            match mask_service(directive.service_name) {
                Ok(_) => {
                    changes.push(Change {
                        change_type: ChangeType::Service,
                        change_description: format!("Masked service {}", directive.service_name),
                        change_error: None,
                        change_success: true,
                    });
                }
                Err(e) => {
                    changes.push(Change {
                        change_type: ChangeType::Service,
                        change_description: format!("Failed to mask service {}", directive.service_name),
                        change_error: Some(e.to_string()),
                        change_success: false,
                    });
                }
            }
        }

        let all_successful = changes.iter().all(|c| c.change_success);

        Ok(ApplyResult {
            apply_changes: changes,
            apply_checkpoint_id: None,
            apply_error: None,
            apply_plugin_id: self.metadata().plugin_id,
            apply_success: all_successful,
        })
    }

    fn rollback(&self, _ctx: &mut Context, _checkpoint: &Checkpoint) -> Result<()> {
        // Rollback not yet implemented - will be handled by checkpoint system
        warn!("Service rollback not yet implemented");
        Ok(())
    }
}
