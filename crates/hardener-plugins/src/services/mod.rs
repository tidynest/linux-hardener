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

/// Builds a single [`ComplianceMapping`] under the shared "Services" section.
///
/// Keeps the per-service mapping table below terse and free of repetition.
fn service_mapping(
    framework: ComplianceFramework,
    control_id: &str,
    title: &str,
) -> ComplianceMapping {
    service_mapping_in(framework, control_id, title, "Services")
}

/// Builds a [`ComplianceMapping`] under an explicit section.
///
/// Used for frameworks whose catalogue groups controls differently from the
/// default "Services" section — notably ISO/IEC 27001:2022, whose Annex A
/// controls live under the "Technological" theme.
fn service_mapping_in(
    framework: ComplianceFramework,
    control_id: &str,
    title: &str,
    section: &str,
) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: framework,
        compliance_control_id: control_id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some(section.to_string()),
    }
}

/// GDPR mapping for service-minimisation controls.
///
/// Disabling unnecessary daemons is a system-hardening technical measure for
/// security of processing under Article 32; "TM-SH" is the project's
/// system-hardening technical-measure tag.
fn service_gdpr_hardening() -> ComplianceMapping {
    service_mapping(
        ComplianceFramework::GDPR,
        "TM-SH",
        "Technical measure: system hardening",
    )
}

/// ISO/IEC 27001:2022 Annex A mappings for removing/disabling unneeded daemons.
///
/// Maps to 8.19 (Installation of software on operational systems) and 8.9
/// (Configuration management); both sit under the "Technological" theme.
fn service_iso_minimisation() -> [ComplianceMapping; 2] {
    [
        service_mapping_in(
            ComplianceFramework::ISO27001,
            "8.19",
            "Installation of software on operational systems",
            "Technological",
        ),
        service_mapping_in(
            ComplianceFramework::ISO27001,
            "8.9",
            "Configuration management",
            "Technological",
        ),
    ]
}

/// ISO/IEC 27001:2022 Annex A mapping for disabling network-exposed services.
///
/// Control 8.20 (Networks security) covers reducing exposure from network
/// daemons such as Bluetooth and the Avahi/mDNS responder; "Technological" theme.
fn service_iso_networks() -> ComplianceMapping {
    service_mapping_in(
        ComplianceFramework::ISO27001,
        "8.20",
        "Networks security",
        "Technological",
    )
}

/// Returns compliance mappings for service findings.
///
/// Multi-framework control IDs are sourced from the ComplianceAsCode/SSG rule
/// `references:` blocks for the matching service/package rule (cited per arm).
/// NIST IDs use 800-53 Rev 5 base controls. The SSG service-disable rules for
/// these daemons carry no STIG or PCI-DSS reference, so those frameworks are
/// omitted rather than guessed.
///
/// GDPR and ISO/IEC 27001:2022 apply to every mapped daemon as service
/// minimisation: GDPR "TM-SH" (Article 32 system-hardening technical measure)
/// and ISO 27001 Annex A 8.19 (Installation of software on operational systems)
/// plus 8.9 (Configuration management), both under the "Technological" theme.
/// Network-exposed daemons (Bluetooth, Avahi/mDNS) additionally map ISO 8.20
/// (Networks security). HIPAA is omitted — none of these daemons map cleanly to
/// a Security Rule specification.
/// Every compliance mapping this plugin can emit, across all services it
/// assesses. Aggregated into the engine's automated-coverage set.
pub fn coverage() -> Vec<ComplianceMapping> {
    UNNECESSARY_SERVICES
        .iter()
        .flat_map(|s| get_service_compliance_mappings(s.service_name))
        .collect()
}

fn get_service_compliance_mappings(service_name: &str) -> Vec<ComplianceMapping> {
    match service_name {
        // SSG: package_xinetd_removed
        "xinetd" => [
            service_mapping(
                ComplianceFramework::CIS,
                "2.1.1",
                "Ensure xinetd is not installed",
            ),
            service_mapping(ComplianceFramework::NIST, "CM-7", "Least Functionality"),
            service_gdpr_hardening(),
        ]
        .into_iter()
        .chain(service_iso_minimisation())
        .collect(),
        // SSG: service_avahi-daemon_disabled. Avahi is an mDNS network responder,
        // so ISO 8.20 (Networks security) applies in addition to minimisation.
        "avahi-daemon" | "avahi" => [
            service_mapping(
                ComplianceFramework::CIS,
                "2.2.3",
                "Ensure Avahi Server is not installed",
            ),
            service_mapping(ComplianceFramework::NIST, "CM-7", "Least Functionality"),
            service_gdpr_hardening(),
            service_iso_networks(),
        ]
        .into_iter()
        .chain(service_iso_minimisation())
        .collect(),
        // SSG: service_cups_disabled
        "cups" | "cupsd" => [
            service_mapping(
                ComplianceFramework::CIS,
                "2.2.4",
                "Ensure CUPS is not installed",
            ),
            service_mapping(ComplianceFramework::NIST, "CM-7", "Least Functionality"),
            service_gdpr_hardening(),
        ]
        .into_iter()
        .chain(service_iso_minimisation())
        .collect(),
        // SSG: service_bluetooth_disabled (NIST AC-18 wireless access + CM-7).
        // Bluetooth is a wireless network interface, so ISO 8.20 (Networks
        // security) applies in addition to minimisation.
        "bluetooth" => [
            service_mapping(ComplianceFramework::NIST, "AC-18", "Wireless Access"),
            service_mapping(ComplianceFramework::NIST, "CM-7", "Least Functionality"),
            service_gdpr_hardening(),
            service_iso_networks(),
        ]
        .into_iter()
        .chain(service_iso_minimisation())
        .collect(),
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
    let output = ctx
        .executor()
        .execute_command("systemctl", &["stop", service_name])
        .await?;
    if !output.success() {
        return Err(hardener_common::error::HardeningError::Plugin(format!(
            "systemctl stop {} failed: {}",
            service_name,
            output.stderr.trim()
        )));
    }
    Ok(())
}

/// Disables a service from starting at boot.
async fn disable_service(ctx: &Context, service_name: &str) -> Result<()> {
    let output = ctx
        .executor()
        .execute_command("systemctl", &["disable", service_name])
        .await?;
    if !output.success() {
        return Err(hardener_common::error::HardeningError::Plugin(format!(
            "systemctl stop {} failed: {}",
            service_name,
            output.stderr.trim()
        )));
    }
    Ok(())
}

/// Masks a service to prevent it from being started.
async fn mask_service(ctx: &Context, service_name: &str) -> Result<()> {
    let output = ctx
        .executor()
        .execute_command("systemctl", &["mask", service_name])
        .await?;
    if !output.success() {
        return Err(hardener_common::error::HardeningError::Plugin(format!(
            "systemctl stop {} failed: {}",
            service_name,
            output.stderr.trim()
        )));
    }
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

    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> {
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

            // Check for a valid exception — skip this service if exempted
            if let Some(exception) = config.has_valid_exception(directive.service_name) {
                info!(
                    "Skipping {} — exception: {}",
                    directive.service_name, exception.reason
                );
                changes.push(Change {
                    change_description: format!(
                        "{}: skipped (exception: {})",
                        directive.service_name, exception.reason
                    ),
                    change_type: ChangeType::Service,
                    change_success: true,
                    change_error: None,
                });
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

    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> {
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
                    // Skip services with valid exceptions
                    if config.has_valid_exception(directive.service_name).is_some() {
                        continue;
                    }

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirms a representative service finding (xinetd) now carries a NIST
    /// mapping (`CM-7`, from the SSG `package_xinetd_removed` rule) alongside
    /// the existing CIS mapping.
    ///
    /// STIG and PCI-DSS are intentionally not asserted: the SSG service-disable
    /// and package-removal rules for these daemons carry no STIG or PCI-DSS
    /// reference, so those frameworks are omitted rather than invented.
    #[test]
    fn service_xinetd_maps_cis_and_nist() {
        let frameworks: Vec<ComplianceFramework> = get_service_compliance_mappings("xinetd")
            .iter()
            .map(|m| m.compliance_framework)
            .collect();

        assert!(
            frameworks.contains(&ComplianceFramework::CIS),
            "xinetd must preserve its CIS mapping"
        );
        assert!(
            frameworks.contains(&ComplianceFramework::NIST),
            "xinetd must add a NIST mapping"
        );
    }

    /// Confirms a representative disabled service (bluetooth) now carries the
    /// governance-framework mappings: ISO/IEC 27001:2022 (8.20 Networks security
    /// plus the 8.19/8.9 minimisation pair, under "Technological") and GDPR
    /// "TM-SH". HIPAA is intentionally absent — no service maps cleanly to a
    /// HIPAA Security Rule specification.
    #[test]
    fn service_bluetooth_maps_iso_and_gdpr() {
        let mappings = get_service_compliance_mappings("bluetooth");
        let frameworks: Vec<ComplianceFramework> =
            mappings.iter().map(|m| m.compliance_framework).collect();

        assert!(
            frameworks.contains(&ComplianceFramework::ISO27001),
            "bluetooth must add an ISO 27001 mapping"
        );
        assert!(
            frameworks.contains(&ComplianceFramework::GDPR),
            "bluetooth must add a GDPR mapping"
        );
        assert!(
            !frameworks.contains(&ComplianceFramework::HIPAA),
            "services carry no HIPAA mapping"
        );

        // Bluetooth, being network-exposed, must carry the Networks security
        // control filed under the "Technological" theme.
        let iso_networks = mappings.iter().find(|m| {
            m.compliance_framework == ComplianceFramework::ISO27001
                && m.compliance_control_id == "8.20"
        });
        let iso_networks = iso_networks.expect("bluetooth must map ISO 8.20");
        assert_eq!(
            iso_networks.compliance_section.as_deref(),
            Some("Technological")
        );
    }
}
