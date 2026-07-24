//! Mandatory Access Control (MAC) hardening plugin
//!
//! This plugin manages SELinux and AppArmor configurations across different
//! Linux distributions, automatically detecting which MAC system is in use.
//!
//! Supported MAC systems:
//! - SELinux (RHEL, Fedora, CentOS, Rocky Linux, AlmaLinux)
//! - AppArmor (Ubuntu, Debian, openSUSE)

use async_trait::async_trait;
use hardener_common::types::PluginId;
use hardener_common::{
    error::{HardeningError, Result},
    types::{ComplianceFramework, ComplianceMapping, FindingCategory, Severity},
};
use hardener_core::{
    ApplyResult, Change, ChangeType, Checkpoint, PluginConfig, ValidationIssue, ValidationReport,
    context::Context,
    plugin::{Finding, HardeningPlugin, PluginMetadata, ScanResult, UncheckedCheck},
};
use std::path::Path;
use std::time::Instant;
use tracing::{info, warn};

/// Represents the type of MAC system detected on the host.
#[derive(Clone, Debug, PartialEq)]
pub enum MacSystem {
    /// AppArmor
    AppArmor,
    /// SELinux (Security-Enhanced Linux)
    SELinux,
}

/// Main MAC (Mandatory Access Control) hardening plugin.
///
/// Automatically detects whether the system uses AppArmor or SELinux
/// and applies appropriate hardening configurations.
pub struct MacHardeningPlugin {}

impl Default for MacHardeningPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl MacHardeningPlugin {
    pub fn new() -> MacHardeningPlugin {
        MacHardeningPlugin {}
    }

    /// Detects which MAC system is available on this system.
    ///
    /// Detection Logic:
    /// 1. Check for SELinux (/sys/fs/selinux directory exists)
    /// 2. Check for AppArmor (/sys/kernel/security/apparmor directory exists)
    /// 3. Return None if neither is found
    async fn detect_mac_system(&self, ctx: &Context) -> Option<MacSystem> {
        // Check for SELinux first
        if ctx
            .executor()
            .path_exists(Path::new("/sys/fs/selinux"))
            .await
            .unwrap_or(false)
        {
            info!("Detected SELinux MAC system");
            return Some(MacSystem::SELinux);
        }

        // Check for AppArmor second
        if ctx
            .executor()
            .path_exists(Path::new("/sys/kernel/security/apparmor"))
            .await
            .unwrap_or(false)
        {
            info!("Detected AppArmor MAC system");
            return Some(MacSystem::AppArmor);
        }

        info!("No MAC system detected (checked SELinux and AppArmor)");
        None
    }

    /// Checks if SELinux is enabled and gets its current mode.
    ///
    /// Returns one of: "Enforcing", "Permissive", or "Disabled"
    async fn get_selinux_mode(&self, ctx: &Context) -> Result<String> {
        let output = ctx
            .executor()
            .execute_command("getenforce", &[])
            .await
            .map_err(|e| HardeningError::Plugin(format!("Failed to execute getenforce: {}", e)))?;

        if !output.success() {
            return Err(HardeningError::Plugin(
                "getenforce command failed".to_string(),
            ));
        }

        let mode = output.stdout.trim().to_string();

        Ok(mode)
    }

    /// Sets SELinux to enforcing mode (requires root).
    async fn set_selinux_enforcing(&self, ctx: &Context) -> Result<Change> {
        let current_mode = self.get_selinux_mode(ctx).await?;

        if current_mode == "Enforcing" {
            return Ok(Change {
                change_description: "SELinux already in enforcing mode".to_string(),
                change_type: ChangeType::Skipped,
                change_success: true,
                change_error: None,
            });
        }

        // Set to enforcing mode
        let output = ctx
            .executor()
            .execute_command("setenforce", &["1"])
            .await
            .map_err(|e| HardeningError::Plugin(format!("Failed to execute setenforce: {}", e)))?;

        if output.success() {
            Ok(Change {
                change_description: format!("Set SELinux mode from {} to Enforcing", current_mode),
                change_type: ChangeType::ConfigFile,
                change_success: true,
                change_error: None,
            })
        } else {
            Ok(Change {
                change_description: "Failed to set SELinux to enforcing mode".to_string(),
                change_type: ChangeType::ConfigFile,
                change_success: false,
                change_error: Some(output.stderr),
            })
        }
    }

    /// Probes AppArmor profile status via `aa-status --verbose` and
    /// classifies the outcome.
    ///
    /// `aa-status` exits non-zero both when AppArmor is not installed and
    /// when it is installed but the caller lacks the privilege to read
    /// profile state, so the raw stderr is classified before either case is
    /// treated as "no MAC in effect" (see [`ApparmorProbe`]).
    async fn probe_apparmor(&self, ctx: &Context) -> ApparmorProbe {
        let output = match ctx
            .executor()
            .execute_command("aa-status", &["--verbose"])
            .await
        {
            Ok(output) => output,
            Err(_) => return ApparmorProbe::Unavailable,
        };

        if !output.success() {
            return if hardener_common::error::message_indicates_permission_denied(&output.stderr) {
                ApparmorProbe::PermissionDenied
            } else {
                ApparmorProbe::Unavailable
            };
        }

        let mut enforce_count = 0;
        let mut complain_count = 0;

        // Parse the aa-status output
        for line in output.stdout.trim().lines() {
            if line.contains("profiles are in enforce mode") {
                // Extract number from line like "   37 profiles are in enforce mode."
                if let Some(num_str) = line.split_whitespace().next() {
                    enforce_count = num_str.parse().unwrap_or(0);
                }
            } else if line.contains("profiles are in complain mode")
                && let Some(num_str) = line.split_whitespace().next()
            {
                complain_count = num_str.parse().unwrap_or(0);
            }
        }

        let total_loaded = enforce_count + complain_count;
        ApparmorProbe::Profiles(enforce_count, complain_count, total_loaded)
    }
}

/// Outcome of [`MacHardeningPlugin::probe_apparmor`].
enum ApparmorProbe {
    /// Profile counts: (enforce_count, complain_count, total_loaded).
    Profiles(usize, usize, usize),
    /// `aa-status` is present but the current privilege level cannot read
    /// profile state. Distinct from [`Self::Unavailable`] so a hardened,
    /// unprivileged scan is never reported as "no AppArmor profiles".
    PermissionDenied,
    /// `aa-status` could not be executed, or failed for a reason other than
    /// privilege (most commonly: AppArmor is not installed).
    Unavailable,
}

/// Returns compliance mappings for MAC findings.
///
/// Multi-framework mappings are sourced from ComplianceAsCode/SSG rule
/// `references:` blocks (see `// SSG:` comments). NIST IDs are 800-53 Rev 5;
/// STIG IDs are the SSG-declared RHEL-family `stigid@ol8` values (the Oracle
/// Linux 8 STIG mirrors the RHEL 8 STIG content). NIST `AC-3` (access
/// enforcement) is the controlling MAC family in `selinux_state` and applies
/// equally to the AppArmor and "no MAC" findings, which are the same control
/// expressed for a different implementation. STIG and PCI-DSS are omitted for
/// the AppArmor and "no-mac-system" findings: the relevant SSG rules
/// (`all_apparmor_profiles_enforced`, `package_apparmor_installed`) declare no
/// `stigid@`/`pcidss`, and `selinux_state` itself declares no `pcidss`.
/// Finding types the MAC plugin can raise: the keys understood by
/// [`get_mac_compliance_mappings`]. Keep in sync with that match.
const MAC_FINDING_TYPES: &[&str] = &[
    "no-mac-system",
    "selinux-not-enforcing",
    "apparmor-complain-mode",
    "apparmor-no-profiles",
];

/// Every compliance mapping this plugin can emit, across all finding types it
/// raises. Aggregated into the engine's automated-coverage set.
pub fn coverage() -> Vec<ComplianceMapping> {
    MAC_FINDING_TYPES
        .iter()
        .flat_map(|&t| get_mac_compliance_mappings(t))
        .collect()
}

/// Builds a SOC 2 mapping. `id` is a 2017 Trust Services Criteria common
/// criterion (e.g. `CC6.8`); `title` tracks the published criterion text. The
/// section is the criterion's TSC series, derived from the id prefix.
fn soc2(id: &str, title: &str) -> ComplianceMapping {
    let series = if id.starts_with("CC7") {
        "System Operations"
    } else {
        "Logical and Physical Access Controls"
    };
    ComplianceMapping {
        compliance_framework: ComplianceFramework::SOC2,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some(series.to_string()),
    }
}

/// Builds a NIST SP 800-171 Revision 3 mapping. `id` is the requirement
/// number (e.g. `3.1.2`); `title` the published requirement name; the
/// section is the requirement's official family. Every id is translated from
/// this plugin's 800-53 entries via the r3 source-control table, never
/// invented.
fn nist171(id: &str, title: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: ComplianceFramework::NIST800171,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some("Access Control".to_string()),
    }
}

/// Builds a FedRAMP mapping. FedRAMP's control set is NIST 800-53 at the
/// Moderate (Rev 5) baseline, so `id`/`title` mirror this plugin's 800-53
/// entries verbatim; each id is checked against the GSA rev5 Moderate
/// baseline before it is mapped, never invented. The section is the control's
/// 800-53 family.
fn fedramp(id: &str, title: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: ComplianceFramework::FedRAMP,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some("Access Control".to_string()),
    }
}

fn get_mac_compliance_mappings(finding_type: &str) -> Vec<ComplianceMapping> {
    match finding_type {
        // SSG: package_apparmor_installed / package_selinux (CIS only); MAC absence
        // maps to NIST AC-3 access enforcement (per selinux_state).
        "no-mac-system" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "1.6.1.1".to_string(),
                compliance_control_title: "Ensure SELinux or AppArmor is installed".to_string(),
                compliance_section: Some("Mandatory Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AC-3".to_string(),
                compliance_control_title: "Access Enforcement".to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(a)(1)".to_string(),
                compliance_control_title: "Access Control".to_string(),
                compliance_section: Some("Technical Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-AC".to_string(),
                compliance_control_title: "Access Control".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-SH".to_string(),
                compliance_control_title: "System Hardening".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.3".to_string(),
                compliance_control_title: "Information access restriction".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "5.15".to_string(),
                compliance_control_title: "Access control".to_string(),
                compliance_section: Some("Organizational".to_string()),
            },
            // SOC 2: CC6.8 mirrors the AC-3 enforcement intent expressed as MAC
            // confinement: enforced policy contains unauthorised software activity.
            soc2(
                "CC6.8",
                "Prevent or detect the introduction of unauthorized or malicious software",
            ),
            // 800-171r3 3.1.2 ← 800-53 AC-3 (SP 800-171r3 source-control table).
            nist171("3.1.2", "Access Enforcement"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AC-3.
            fedramp("AC-3", "Access Enforcement"),
        ],
        // SSG: selinux_state (nist: AC-3,AC-3(3)(a),AU-9,SC-7(21); stigid@ol8: OL08-00-010170)
        "selinux-not-enforcing" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "1.6.1.4".to_string(),
                compliance_control_title:
                    "Ensure the SELinux mode is enforcing or AppArmor is enabled".to_string(),
                compliance_section: Some("Mandatory Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AC-3".to_string(),
                compliance_control_title: "Access Enforcement".to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::STIG,
                compliance_control_id: "OL08-00-010170".to_string(),
                compliance_control_title: "SELinux must be in enforcing mode".to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(a)(1)".to_string(),
                compliance_control_title: "Access Control".to_string(),
                compliance_section: Some("Technical Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-AC".to_string(),
                compliance_control_title: "Access Control".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-SH".to_string(),
                compliance_control_title: "System Hardening".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.3".to_string(),
                compliance_control_title: "Information access restriction".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "5.15".to_string(),
                compliance_control_title: "Access control".to_string(),
                compliance_section: Some("Organizational".to_string()),
            },
            // SOC 2: CC6.8 mirrors the AC-3 enforcement intent expressed as MAC
            // confinement: enforced policy contains unauthorised software activity.
            soc2(
                "CC6.8",
                "Prevent or detect the introduction of unauthorized or malicious software",
            ),
            // 800-171r3 3.1.2 ← 800-53 AC-3 (SP 800-171r3 source-control table).
            nist171("3.1.2", "Access Enforcement"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AC-3.
            fedramp("AC-3", "Access Enforcement"),
        ],
        // SSG: all_apparmor_profiles_enforced (CIS only). NIST AC-3 access
        // enforcement applies; this is the AppArmor expression of the same
        // MAC-not-enforced control as selinux-not-enforcing.
        "apparmor-complain-mode" | "apparmor-no-profiles" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "1.6.1.4".to_string(),
                compliance_control_title:
                    "Ensure the SELinux mode is enforcing or AppArmor is enabled".to_string(),
                compliance_section: Some("Mandatory Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::NIST,
                compliance_control_id: "AC-3".to_string(),
                compliance_control_title: "Access Enforcement".to_string(),
                compliance_section: Some("Access Control".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::HIPAA,
                compliance_control_id: "164.312(a)(1)".to_string(),
                compliance_control_title: "Access Control".to_string(),
                compliance_section: Some("Technical Safeguards".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-AC".to_string(),
                compliance_control_title: "Access Control".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::GDPR,
                compliance_control_id: "TM-SH".to_string(),
                compliance_control_title: "System Hardening".to_string(),
                compliance_section: Some("Technical Measures".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "8.3".to_string(),
                compliance_control_title: "Information access restriction".to_string(),
                compliance_section: Some("Technological".to_string()),
            },
            ComplianceMapping {
                compliance_framework: ComplianceFramework::ISO27001,
                compliance_control_id: "5.15".to_string(),
                compliance_control_title: "Access control".to_string(),
                compliance_section: Some("Organizational".to_string()),
            },
            // SOC 2: CC6.8 mirrors the AC-3 enforcement intent expressed as MAC
            // confinement: enforced policy contains unauthorised software activity.
            soc2(
                "CC6.8",
                "Prevent or detect the introduction of unauthorized or malicious software",
            ),
            // 800-171r3 3.1.2 ← 800-53 AC-3 (SP 800-171r3 source-control table).
            nist171("3.1.2", "Access Enforcement"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AC-3.
            fedramp("AC-3", "Access Enforcement"),
        ],
        _ => vec![],
    }
}

#[async_trait]
impl HardeningPlugin for MacHardeningPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_category: FindingCategory::Kernel,
            plugin_description: "Manages SELinux and AppArmor MAC system configuration".to_string(),
            plugin_id: PluginId::new("mac-hardening"),
            plugin_name: "MAC System Hardening".to_string(),
            plugin_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        // MAC hardening has no dependencies
        vec![]
    }

    async fn scan(&self, ctx: &Context, _config: &PluginConfig) -> Result<ScanResult> {
        let start_time = Instant::now();
        let plugin_id = PluginId::new("mac-hardening");
        let mut findings = Vec::new();
        let mut unchecked = Vec::new();

        // Detect which MAC system is present
        match self.detect_mac_system(ctx).await {
            Some(MacSystem::SELinux) => {
                // Check SELinux mode
                match self.get_selinux_mode(ctx).await {
                    Ok(mode) => {
                        if mode != "Enforcing" {
                            findings.push(Finding {
                                finding_category:          FindingCategory::Kernel,
                                finding_current_value:     mode.clone(),
                                finding_description:       "SELinux is not in enforcing mode".to_string(),
                                finding_explanation:       "SELinux should be in enforcing mode to actively prevent security violations".to_string(),
                                finding_id:                "selinux-not-enforcing".to_string(),
                                finding_impact:            "Security policies are not being enforced".to_string(),
                                finding_recommended_value: "Enforcing".to_string(),
                                finding_remediation_steps: vec![
                                    "Run: setenforce 1".to_string(),
                                    "Edit /etc/selinux/config and set SELINUX=enforcing".to_string(),
                                ],
                                finding_severity: Severity::High,
                                finding_title:    "SELinux Not Enforcing".to_string(),
                                finding_compliance: get_mac_compliance_mappings("selinux-not-enforcing"),
                                finding_policy_exception: None,
                            });
                        }
                    }
                    Err(e) => {
                        warn!("Failed to check SELinux mode: {}", e);
                    }
                }
            }
            Some(MacSystem::AppArmor) => {
                // Check AppArmor profile status
                match self.probe_apparmor(ctx).await {
                    ApparmorProbe::Profiles(_enforce_count, complain_count, total_loaded) => {
                        if complain_count > 0 {
                            findings.push(Finding {
                                finding_category: FindingCategory::Kernel,
                                finding_current_value: format!("{} profiles in complain mode", complain_count),
                                finding_description: "Some AppArmor profiles are in complain mode".to_string(),
                                finding_explanation: "Profiles in complain mode only log violations instead of blocking them".to_string(),
                                finding_id: "apparmor-complain-mode".to_string(),
                                finding_impact: "Security policies are not being enforced for some applications".to_string(),
                                finding_recommended_value: "All profiles in enforce mode".to_string(),
                                finding_remediation_steps: vec![
                                    format!("Review {} profiles in complain mode", complain_count),
                                    "Use aa-enforce to set profiles to enforce mode".to_string(),
                                ],
                                finding_severity: Severity::Medium,
                                finding_title: "AppArmor Profiles in Complain Mode".to_string(),
                                finding_compliance: get_mac_compliance_mappings("apparmor-complain-mode"),
                                finding_policy_exception: None,
                            });
                        }

                        if total_loaded == 0 {
                            findings.push(Finding {
                                finding_category: FindingCategory::Kernel,
                                finding_current_value: "0 profiles loaded".to_string(),
                                finding_description: "No AppArmor profiles are loaded".to_string(),
                                finding_explanation:
                                    "AppArmor is installed but no profiles are active".to_string(),
                                finding_id: "apparmor-no-profiles".to_string(),
                                finding_impact: "No application confinement is in effect"
                                    .to_string(),
                                finding_recommended_value: "Load AppArmor profiles".to_string(),
                                finding_remediation_steps: vec![
                                    "Install apparmor-profiles package".to_string(),
                                    "Enable AppArmor service".to_string(),
                                ],
                                finding_severity: Severity::High,
                                finding_title: "No AppArmor Profiles Loaded".to_string(),
                                finding_compliance: get_mac_compliance_mappings(
                                    "apparmor-no-profiles",
                                ),
                                finding_policy_exception: None,
                            });
                        }
                    }
                    ApparmorProbe::PermissionDenied => {
                        warn!(
                            "aa-status requires elevated privileges to read AppArmor profile state"
                        );
                        // aa-status ran and refused for lack of privilege, so
                        // AppArmor is genuinely installed: a root-only probe
                        // must not read as "no profiles loaded".
                        if ctx
                            .executor()
                            .command_exists("aa-status")
                            .await
                            .unwrap_or(false)
                        {
                            unchecked.push(UncheckedCheck {
                                unchecked_check_id: "apparmor-no-profiles".to_string(),
                                unchecked_title: "AppArmor profile enforcement".to_string(),
                                unchecked_category: FindingCategory::Kernel,
                                unchecked_reason:
                                    "reading the AppArmor profile set (aa-status) requires root"
                                        .to_string(),
                                unchecked_compliance: get_mac_compliance_mappings(
                                    "apparmor-no-profiles",
                                ),
                            });
                        }
                    }
                    ApparmorProbe::Unavailable => {
                        warn!("Failed to check AppArmor status: aa-status unavailable");
                    }
                }
            }
            None => {
                // No MAC system detected
                findings.push(Finding {
                    finding_category: FindingCategory::Kernel,
                    finding_current_value: "None".to_string(),
                    finding_description: "No MAC system detected on this system".to_string(),
                    finding_explanation: "Neither SELinux nor AppArmor is available. Consider enabling one for enhanced security.".to_string(),
                    finding_id: "no-mac-system".to_string(),
                    finding_impact: "Missing kernel-level mandatory access controls".to_string(),
                    finding_recommended_value: "SELinux or AppArmor enabled".to_string(),
                    finding_remediation_steps: vec![
                        "Install and enable AppArmor (Ubuntu/Debian) or SELinux (RHEL/Fedora)".to_string(),
                    ],
                    finding_severity: Severity::Medium,
                    finding_title: "No MAC System Found".to_string(),
                    finding_compliance: get_mac_compliance_mappings("no-mac-system"),
                    finding_policy_exception: None,
                });
            }
        }

        let duration_us = start_time.elapsed().as_micros() as u64;
        Ok(ScanResult {
            scan_plugin_id: plugin_id,
            scan_success: true,
            scan_findings: findings,
            scan_unchecked: unchecked,
            scan_duration_us: duration_us,
            scan_error: None,
        })
    }

    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> {
        let apply_plugin_id = PluginId::new("mac-hardening");
        let mut apply_changes = Vec::new();

        // Create checkpoint for MAC config files
        let mac_paths: Vec<&Path> = vec![
            Path::new("/etc/selinux/config"),
            Path::new("/etc/apparmor"),
            Path::new("/etc/apparmor.d"),
        ];
        let checkpoint_id =
            crate::create_checkpoint_for_apply(ctx, "mac-hardening-pre-apply", &mac_paths).await?;

        apply_changes.extend(crate::checkpoint_change(&checkpoint_id));

        // Detect which MAC system is present
        match self.detect_mac_system(ctx).await {
            Some(MacSystem::SELinux) => {
                // Check for exception before enforcing
                if let Some(exception) = config.has_valid_exception("selinux-enforcing") {
                    info!(
                        "Skipping SELinux enforcement (exception: {})",
                        exception.reason
                    );
                    apply_changes.push(Change {
                        change_description: format!(
                            "SELinux enforcement: skipped (exception: {})",
                            exception.reason
                        ),
                        change_type: ChangeType::Skipped,
                        change_success: true,
                        change_error: None,
                    });
                } else {
                    // Try to set SELinux to enforcing mode
                    match self.set_selinux_enforcing(ctx).await {
                        Ok(change) => {
                            apply_changes.push(change);
                        }
                        Err(e) => {
                            return Ok(ApplyResult {
                                apply_plugin_id,
                                apply_success: false,
                                apply_changes,
                                apply_checkpoint_id: checkpoint_id,
                                apply_error: Some(format!(
                                    "Failed to set SELinux enforcing: {}",
                                    e
                                )),
                            });
                        }
                    }
                }
            }
            Some(MacSystem::AppArmor) => {
                // Check for exception before AppArmor enforcement guidance
                if let Some(exception) = config.has_valid_exception("apparmor-enforce") {
                    info!(
                        "Skipping AppArmor enforcement (exception: {})",
                        exception.reason
                    );
                    apply_changes.push(Change {
                        change_description: format!(
                            "AppArmor enforcement: skipped (exception: {})",
                            exception.reason
                        ),
                        change_type: ChangeType::Skipped,
                        change_success: true,
                        change_error: None,
                    });
                } else {
                    // Advisory only: apply does not touch the host, so this
                    // must not inflate the "N change(s) applied" count (see
                    // ChangeType::Skipped).
                    apply_changes.push(Change {
                        change_description: "AppArmor detected - use aa-enforce to set specific profiles to enforce mode"
                            .to_string(),
                        change_type: ChangeType::Skipped,
                        change_success: true,
                        change_error: None,
                    });
                }
            }
            None => {
                // Many distributions ship without SELinux or AppArmor; an
                // absent MAC system is a normal state, not a plugin failure.
                info!("No MAC system detected - nothing to apply");
                apply_changes.push(Change {
                    change_description: "No MAC system detected - nothing to configure (skipped)"
                        .to_string(),
                    change_type: ChangeType::Skipped,
                    change_success: true,
                    change_error: None,
                });
            }
        }

        let apply_success = apply_changes.iter().all(|c| c.change_success);

        Ok(ApplyResult {
            apply_plugin_id,
            apply_success,
            apply_changes,
            apply_checkpoint_id: checkpoint_id,
            apply_error: None,
        })
    }

    async fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()> {
        info!(
            "Rolling back MAC configuration to checkpoint: {}",
            checkpoint.checkpoint_id.as_str()
        );

        // Restore configuration files from checkpoint
        crate::rollback_files_from_checkpoint(ctx, checkpoint)?;

        info!("MAC configuration files restored from checkpoint");

        // Reload SELinux/AppArmor based on what's available
        // Try SELinux first: restore mode from the config we just rolled back
        let selinux_mode = std::fs::read_to_string("/etc/selinux/config")
            .ok()
            .and_then(|content| {
                content.lines().find_map(|line| {
                    let trimmed = line.trim();
                    trimmed
                        .strip_prefix("SELINUX=")
                        .filter(|_| !trimmed.starts_with('#'))
                        .map(|v| {
                            if v.trim().eq_ignore_ascii_case("enforcing") {
                                "1"
                            } else {
                                "0"
                            }
                        })
                })
            })
            .unwrap_or("1");

        let selinux_result = ctx
            .executor()
            .execute_command("setenforce", &[selinux_mode])
            .await;

        if selinux_result.is_ok() {
            info!("SELinux policy reloaded");
        } else {
            // Try AppArmor
            let apparmor_result = ctx
                .executor()
                .execute_command("systemctl", &["reload", "apparmor"])
                .await;

            match apparmor_result {
                Ok(output) if output.success() => {
                    info!("AppArmor profiles reloaded");
                }
                _ => {
                    warn!("Could not reload MAC system (SELinux/AppArmor)");
                }
            }
        }

        Ok(())
    }

    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> {
        let validation_plugin_id = PluginId::new("mac-hardening");
        let mut issues = Vec::new();
        let mut estimated_changes = Vec::new();

        // Detect which MAC system is present
        match self.detect_mac_system(ctx).await {
            Some(MacSystem::SELinux) => {
                // Skip if SELinux enforcement is excepted
                if config.has_valid_exception("selinux-enforcing").is_none() {
                    match self.get_selinux_mode(ctx).await {
                        Ok(mode) => {
                            if mode != "Enforcing" {
                                estimated_changes.push("Set SELinux to enforcing mode".to_string());
                            }
                        }
                        Err(_) => {
                            issues.push(ValidationIssue {
                                validation_issue_severity: Severity::High,
                                validation_issue_message:
                                    "Cannot read SELinux status - getenforce may not be available"
                                        .to_string(),
                                validation_issue_config_key: Some("selinux.mode".to_string()),
                            });
                        }
                    }
                }
            }
            // The suggested collapse into a match guard breaks exhaustiveness
            // here (guarded arms do not count as covering their pattern), so
            // the nested `if` stays.
            #[allow(clippy::collapsible_match)]
            Some(MacSystem::AppArmor) => {
                // Skip if AppArmor enforcement is excepted
                if config.has_valid_exception("apparmor-enforce").is_none()
                    && matches!(
                        self.probe_apparmor(ctx).await,
                        ApparmorProbe::Unavailable | ApparmorProbe::PermissionDenied
                    )
                {
                    issues.push(ValidationIssue {
                        validation_issue_severity: Severity::High,
                        validation_issue_message:
                            "Cannot read AppArmor status - aa-status may not be available"
                                .to_string(),
                        validation_issue_config_key: Some("apparmor.status".to_string()),
                    });
                }
            }
            None => {
                // No MAC system - this is expected on some distributions.
                // Apply will record a skip, not a change, so the preview
                // must not list it as one either (see ChangeType::Skipped).
            }
        }

        let is_valid = issues.is_empty();

        Ok(ValidationReport {
            validation_report_plugin_id: validation_plugin_id,
            validation_report_is_valid: is_valid,
            validation_report_issues: issues,
            validation_report_estimated_changes: estimated_changes,
            validation_report_compliant_count: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A representative MAC check (`selinux-not-enforcing`) must now carry
    /// multi-framework mappings: the existing CIS control plus NIST 800-53 and
    /// STIG sourced from SSG `selinux_state`.
    #[test]
    fn selinux_enforcing_has_multi_framework_mappings() {
        let mappings = get_mac_compliance_mappings("selinux-not-enforcing");

        let has = |fw| mappings.iter().any(|m| m.compliance_framework == fw);
        assert!(
            has(ComplianceFramework::CIS),
            "CIS mapping must be retained"
        );
        assert!(
            has(ComplianceFramework::NIST),
            "NIST mapping must be present"
        );
        assert!(
            has(ComplianceFramework::STIG),
            "STIG mapping must be present"
        );

        // Verify the exact SSG-sourced STIG and NIST identifiers.
        let stig = mappings
            .iter()
            .find(|m| m.compliance_framework == ComplianceFramework::STIG)
            .unwrap();
        assert_eq!(stig.compliance_control_id, "OL08-00-010170");
        let nist = mappings
            .iter()
            .find(|m| m.compliance_framework == ComplianceFramework::NIST)
            .unwrap();
        assert_eq!(nist.compliance_control_id, "AC-3");
    }

    /// MAC enforcement findings must also carry HIPAA, GDPR and ISO/IEC
    /// 27001:2022 mappings alongside the existing CIS/NIST/STIG set. ISO uses
    /// both the Technological (8.3) and Organizational (5.15) access clauses.
    #[test]
    fn selinux_enforcing_has_privacy_and_iso_mappings() {
        let mappings = get_mac_compliance_mappings("selinux-not-enforcing");

        let has = |fw| mappings.iter().any(|m| m.compliance_framework == fw);
        assert!(has(ComplianceFramework::HIPAA), "HIPAA must be present");
        assert!(has(ComplianceFramework::GDPR), "GDPR must be present");
        assert!(
            has(ComplianceFramework::ISO27001),
            "ISO 27001 must be present"
        );

        // Both ISO access-control clauses (technological + organizational).
        let iso_ids: Vec<&str> = mappings
            .iter()
            .filter(|m| m.compliance_framework == ComplianceFramework::ISO27001)
            .map(|m| m.compliance_control_id.as_str())
            .collect();
        assert!(iso_ids.contains(&"8.3"), "ISO 8.3 must be present");
        assert!(iso_ids.contains(&"5.15"), "ISO 5.15 must be present");

        // HIPAA access-control safeguard for MAC enforcement. SSG cites
        // 164.312(a) (not the integrity standard) for SELinux state, so
        // 164.312(c)(1) is intentionally absent.
        assert!(
            mappings
                .iter()
                .any(|m| m.compliance_framework == ComplianceFramework::HIPAA
                    && m.compliance_control_id == "164.312(a)(1)")
        );
        assert!(
            !mappings
                .iter()
                .any(|m| m.compliance_framework == ComplianceFramework::HIPAA
                    && m.compliance_control_id == "164.312(c)(1)")
        );
    }

    /// Confirms every MAC finding type carries the SOC 2 unauthorised-software
    /// criterion CC6.8, filed under its Trust Services Criteria series.
    #[test]
    fn mac_findings_map_soc2_unauthorised_software() {
        for finding_type in MAC_FINDING_TYPES {
            let soc2 = get_mac_compliance_mappings(finding_type)
                .into_iter()
                .find(|m| m.compliance_framework == ComplianceFramework::SOC2)
                .unwrap_or_else(|| panic!("{finding_type} must carry a SOC 2 mapping"));
            assert_eq!(soc2.compliance_control_id, "CC6.8");
            assert_eq!(
                soc2.compliance_section.as_deref(),
                Some("Logical and Physical Access Controls")
            );
        }
    }

    /// Confirms the 800-171r3 crosswalk: every MAC finding translates its
    /// AC-3 entry to requirement 3.1.2 under the Access Control family.
    #[test]
    fn mac_findings_map_nist_800_171_access_enforcement() {
        for finding_type in MAC_FINDING_TYPES {
            let mapping = get_mac_compliance_mappings(finding_type)
                .into_iter()
                .find(|m| m.compliance_framework == ComplianceFramework::NIST800171)
                .unwrap_or_else(|| panic!("{finding_type} must carry an 800-171 mapping"));
            assert_eq!(mapping.compliance_control_id, "3.1.2");
            assert_eq!(
                mapping.compliance_section.as_deref(),
                Some("Access Control")
            );
        }
    }

    /// Confirms the FedRAMP derivation: AC-3 is a GSA rev5 Moderate baseline
    /// member, so every MAC finding mirrors its existing 800-53 entry
    /// verbatim under the Access Control family.
    #[test]
    fn mac_findings_map_fedramp_access_enforcement() {
        for finding_type in MAC_FINDING_TYPES {
            let mapping = get_mac_compliance_mappings(finding_type)
                .into_iter()
                .find(|m| m.compliance_framework == ComplianceFramework::FedRAMP)
                .unwrap_or_else(|| panic!("{finding_type} must carry a FedRAMP mapping"));
            assert_eq!(mapping.compliance_control_id, "AC-3");
            assert_eq!(
                mapping.compliance_section.as_deref(),
                Some("Access Control")
            );
        }
    }
}
