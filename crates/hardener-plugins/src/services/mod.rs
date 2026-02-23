//! Service Minimisation Plugin
//!
//! This plugin identifies and disables unnecessary systemd services to reduce
//! the attack surface of the system. It focuses on services that are commonly
//! enabled by default but not required for typical server operations.
//!
//! The plugin uses systemctl to manage services on all supported distributions
//! (all target distributions use systemd)

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
use std::time::Instant;
use tracing::{info, warn};

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

/// Returns compliance mappings for service findings.
fn get_service_compliance_mappings(service_name: &str) -> Vec<ComplianceMapping> {
    match service_name {
        "xinetd" => vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "2.1.1".to_string(),
            compliance_control_title: "Ensure xinetd is not installed".to_string(),
            compliance_section: Some("Services".to_string()),
        }],
        "avahi-daemon" | "avahi" => vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "2.2.3".to_string(),
            compliance_control_title: "Ensure Avahi Server is not installed".to_string(),
            compliance_section: Some("Services".to_string()),
        }],
        "cups" | "cupsd" => vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "2.2.4".to_string(),
            compliance_control_title: "Ensure CUPS is not installed".to_string(),
            compliance_section: Some("Services".to_string()),
        }],
        _ => vec![],
    }
}

/// Represents a service that should be disabled for security hardening.
struct ServiceDirective {
    service_description: &'static str,
    service_name: &'static str,
    service_severity: Severity,
}

/// List of unnecessary services that should be disabled.
///
/// These services are commonly enabled by default but not required for
/// typical server operations. Disabling them reduces attack surface.
const UNNECESSARY_SERVICES: &[ServiceDirective] = &[
    ServiceDirective {
        service_description: "Bluetooth service - rarely needed on servers",
        service_name: "bluetooth",
        service_severity: Severity::High,
    },
    ServiceDirective {
        service_description: "Printing service - not needed on most servers",
        service_name: "cups",
        service_severity: Severity::Medium,
    },
    ServiceDirective {
        service_description: "Network discovery service - potential information disclosure",
        service_name: "avahi-daemon",
        service_severity: Severity::Medium,
    },
    ServiceDirective {
        service_description: "Modem management - not needed without mobile broadband",
        service_name: "ModemManager",
        service_severity: Severity::Low,
    },
];

/// Checks if a systemd service unit exists on the system.
async fn is_service_exists(ctx: &Context, service_name: &str) -> Result<bool> {
    let output = ctx
        .executor()
        .execute_command("systemctl", &["list-unit-files", service_name])
        .await?;

    Ok(output.stdout.contains(service_name))
}

/// Checks if a service is enabled to start at boot.
async fn is_service_enabled(ctx: &Context, service_name: &str) -> Result<bool> {
    let output = ctx
        .executor()
        .execute_command("systemctl", &["is-enabled", service_name])
        .await?;
    Ok(output.success())
}

/// Checks if a service is currently active (running).
async fn is_service_active(ctx: &Context, service_name: &str) -> Result<bool> {
    let output = ctx
        .executor()
        .execute_command("systemctl", &["is-active", service_name])
        .await?;
    Ok(output.success())
}

/// Stops a running service.
async fn stop_service(ctx: &Context, service_name: &str) -> Result<()> {
    ctx.executor()
        .execute_command("systemctl", &["stop", service_name])
        .await?;
    Ok(())
}

/// Disables a service from starting at boot.
async fn disable_service(ctx: &Context, service_name: &str) -> Result<()> {
    ctx.executor()
        .execute_command("systemctl", &["disable", service_name])
        .await?;
    Ok(())
}

/// Masks a service to prevent it from being started.
async fn mask_service(ctx: &Context, service_name: &str) -> Result<()> {
    ctx.executor()
        .execute_command("systemctl", &["mask", service_name])
        .await?;
    Ok(())
}

#[async_trait]
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

    async fn scan(&self, ctx: &Context) -> Result<ScanResult> {
        let start = Instant::now();
        let mut findings = Vec::new();

        // Check each service in our list
        for directive in UNNECESSARY_SERVICES {
            // Skip if service doesn't exist on the system
            if !is_service_exists(ctx, directive.service_name)
                .await
                .unwrap_or(false)
            {
                continue;
            }

            let is_enabled = is_service_enabled(ctx, directive.service_name)
                .await
                .unwrap_or(false);
            let is_active = is_service_active(ctx, directive.service_name)
                .await
                .unwrap_or(false);

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
                    finding_id: format!("service_{}", directive.service_name.replace('-', "_")),
                    finding_impact: "Reduces attack surface by disabling unnecessary service"
                        .to_string(),
                    finding_recommended_value: "disabled and masked".to_string(),
                    finding_remediation_steps: vec![
                        format!("systemctl stop {}", directive.service_name),
                        format!("systemctl disable {}", directive.service_name),
                        format!("systemctl mask {}", directive.service_name),
                    ],
                    finding_severity: directive.service_severity,
                    finding_title: format!(
                        "Unnecessary service {} is running",
                        directive.service_name
                    ),
                    finding_compliance: get_service_compliance_mappings(directive.service_name),
                    finding_policy_exception: None,
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

    async fn apply(&self, ctx: &mut Context, _config: &PluginConfig) -> Result<ApplyResult> {
        use std::path::Path;

        let mut changes = Vec::new();

        // Create checkpoint for systemd unit files
        let service_paths: Vec<&Path> = vec![
            Path::new("/etc/systemd/system"),
            Path::new("/usr/lib/systemd/system"),
        ];
        let checkpoint_id =
            crate::create_checkpoint_for_apply(ctx, "services-hardening-pre-apply", &service_paths)
                .await?;

        if checkpoint_id.is_some() {
            changes.push(Change {
                change_type: ChangeType::Service,
                change_description: "Created checkpoint for rollback".to_string(),
                change_success: true,
                change_error: None,
            });
        }

        // Process each service
        for directive in UNNECESSARY_SERVICES {
            // Skip if service does not exist
            if !is_service_exists(ctx, directive.service_name)
                .await
                .unwrap_or(false)
            {
                continue;
            }

            let is_enabled = is_service_enabled(ctx, directive.service_name)
                .await
                .unwrap_or(false);
            let is_active = is_service_active(ctx, directive.service_name)
                .await
                .unwrap_or(false);

            // Only process if service is enabled or active
            if !is_enabled && !is_active {
                continue;
            }

            // Stop the service if it is running
            if is_active {
                match stop_service(ctx, directive.service_name).await {
                    Ok(_) => {
                        changes.push(Change {
                            change_type: ChangeType::Service,
                            change_description: format!(
                                "Stopped service {}",
                                directive.service_name
                            ),
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
                match disable_service(ctx, directive.service_name).await {
                    Ok(_) => {
                        changes.push(Change {
                            change_type: ChangeType::Service,
                            change_description: format!(
                                "Disabled service {}",
                                directive.service_name
                            ),
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
            match mask_service(ctx, directive.service_name).await {
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
                        change_description: format!(
                            "Failed to mask service {}",
                            directive.service_name
                        ),
                        change_error: Some(e.to_string()),
                        change_success: false,
                    });
                }
            }
        }

        let all_successful = changes.iter().all(|c| c.change_success);

        Ok(ApplyResult {
            apply_changes: changes,
            apply_checkpoint_id: checkpoint_id,
            apply_error: None,
            apply_plugin_id: self.metadata().plugin_id,
            apply_success: all_successful,
        })
    }

    async fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()> {
        info!(
            "Rolling back service configuration to checkpoint: {}",
            checkpoint.checkpoint_id.as_str()
        );

        // Restore configuration files from checkpoint
        crate::rollback_files_from_checkpoint(ctx, checkpoint)?;

        info!("Service configuration files restored from checkpoint");

        // Reload systemd to pick up any restored unit files
        let reload_result = ctx
            .executor()
            .execute_command("systemctl", &["daemon-reload"])
            .await;

        match reload_result {
            Ok(output) if output.success() => {
                info!("Systemd daemon reloaded successfully");
            }
            Ok(output) => {
                warn!(
                    "systemctl daemon-reload returned non-zero: {}",
                    output.stderr
                );
            }
            Err(e) => {
                warn!("Failed to reload systemd daemon: {}", e);
            }
        }

        Ok(())
    }

    async fn validate(&self, ctx: &Context, _config: &PluginConfig) -> Result<ValidationReport> {
        let mut estimated_changes = Vec::new();
        let mut issues = Vec::new();

        // Check if systemctl is available
        let systemctl_available = ctx.executor().command_exists("systemctl").await?;

        if systemctl_available {
            // systemctl is available, list services that would be disabled
            for directive in UNNECESSARY_SERVICES {
                if is_service_exists(ctx, directive.service_name)
                    .await
                    .unwrap_or(false)
                {
                    let is_enabled = is_service_enabled(ctx, directive.service_name)
                        .await
                        .unwrap_or(false);
                    let is_active = is_service_active(ctx, directive.service_name)
                        .await
                        .unwrap_or(false);
                    if is_enabled || is_active {
                        estimated_changes.push(format!(
                            "Disable and mask service: {}",
                            directive.service_name
                        ));
                    }
                }
            }
        } else {
            issues.push(ValidationIssue {
                validation_issue_config_key: None,
                validation_issue_message:
                    "systemctl command not found - this plugin requires systemd".to_string(),
                validation_issue_severity: Severity::Critical,
            });
        }

        Ok(ValidationReport {
            validation_report_estimated_changes: estimated_changes,
            validation_report_is_valid: issues.is_empty(),
            validation_report_issues: issues,
            validation_report_plugin_id: self.metadata().plugin_id,
        })
    }
}
