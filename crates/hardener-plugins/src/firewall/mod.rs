//! Firewall hardening plugin supporting multiple firewall backends.
//!
//! This plugin provides unified firewall management across different Linux
//! firewall systems including nftables, firewalld, and ufw.
//!
//! The plugin automatically detects which firewall backend is available on
//! the system and uses the appropriate implementation.

pub mod firewalld;
pub mod nftables;
pub mod ufw;

use async_trait::async_trait;
use hardener_common::{
    error::Result,
    types::{ComplianceFramework, ComplianceMapping, FindingCategory, PluginId, Severity},
};
use hardener_core::{
    ApplyResult, Change, ChangeType, Checkpoint, PluginConfig, ValidationReport,
    context::Context,
    plugin::{Finding, HardeningPlugin, PluginMetadata, ScanResult, UncheckedCheck},
};
use std::time::Instant;
use tracing::{info, warn};

/// Represents a single firewall rule in a backend-agnostic format.
#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    /// Rule description for logging and display.
    pub rule_description: String,
    /// Protocol (tcp, udp, icmp, all).
    pub rule_protocol: String,
    /// Port or port range (e.g. "22", "80:443", "any").
    pub rule_port: String,
    /// Source address (CIDR notation or "any").
    pub rule_source: String,
    /// Action to take (accept, drop, reject).
    pub rule_action: String,
}

/// Trait for firewall backend implementations.
///
/// Each firewall system (nftables, firewalld, ufw) implements this trait
/// to provide unified firewall management.
#[async_trait]
pub trait FirewallBackend: Send + Sync {
    /// Returns the name of this backend (e.g., "nftables", "firewalld", "ufw").
    fn backend_name(&self) -> &str;

    /// The systemd unit that runs this backend, used as a root-free
    /// activity hint when the backend's own probe needs privileges.
    fn systemd_unit(&self) -> &'static str;

    /// Detects if this backend is available on the system.
    ///
    /// This typically checks if the backend's command-line tool exists and is executable.
    async fn detect(&self, ctx: &Context) -> Result<bool>;

    /// Checks if the firewall is currently enabled and running.
    async fn is_enabled(&self, ctx: &Context) -> Result<()>;

    /// Enables and starts the firewall service.
    async fn enable(&self, ctx: &Context) -> Result<()>;

    /// Lists current firewall rules in a backend-agnostic format.
    ///
    /// This converts the backend's rule format into the unified Rule structure.
    async fn list_rules(&self, ctx: &Context) -> Result<Vec<Rule>>;

    /// Applies a set of firewall rules.
    ///
    /// # Arguments
    /// * `rules` - The rules to apply in a backend-agnostic format.
    ///
    /// # Returns
    /// A list of changes made, or an error if application fails.
    async fn apply_rules(&self, ctx: &Context, rules: &[Rule]) -> Result<Vec<Change>>;

    /// Returns the recommended baseline firewall rules.
    ///
    /// These are sensible defaults that work across most systems:
    /// - Allow established/related connections
    /// - Allow loopback
    /// - Allow SSH (port 22)
    /// - Drop all other inbound by default.
    fn get_default_rules(&self) -> Vec<Rule>;
}

/// Builds a HIPAA Security Rule (45 CFR §164.312) technical-safeguards mapping.
/// `id` is the official CFR citation; `title` the safeguard standard name.
fn hipaa(id: &str, title: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: ComplianceFramework::HIPAA,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some("Technical Safeguards".to_string()),
    }
}

/// Builds a GDPR Article 32 ("Security of processing") technical-measure
/// mapping. `id` is the project's technical-measure tag (e.g. `TM-SH` system
/// hardening, `TM-NW` network protection); `title` the measure description.
fn gdpr(id: &str, title: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: ComplianceFramework::GDPR,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some("Article 32 - Security of Processing".to_string()),
    }
}

/// Builds an ISO/IEC 27001:2022 Annex A control mapping. `id`/`title` use the
/// official clause number and control name; `section` is the control theme.
fn iso(id: &str, title: &str, theme: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: ComplianceFramework::ISO27001,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some(theme.to_string()),
    }
}

/// Builds a SOC 2 mapping. `id` is a 2017 Trust Services Criteria common
/// criterion (e.g. `CC6.6`); `title` tracks the published criterion text. The
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
/// number (e.g. `3.13.1`); `title` the published requirement name; the
/// section is the requirement's official family. Every id is translated from
/// this plugin's 800-53 entries via the r3 source-control table, never
/// invented.
fn nist171(id: &str, title: &str) -> ComplianceMapping {
    let family = if id.starts_with("3.13.") {
        "System and Communications Protection"
    } else {
        "Configuration Management"
    };
    ComplianceMapping {
        compliance_framework: ComplianceFramework::NIST800171,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some(family.to_string()),
    }
}

/// Builds a FedRAMP mapping. FedRAMP's control set is NIST 800-53 at the
/// Moderate (Rev 5) baseline, so `id`/`title` mirror this plugin's 800-53
/// entries verbatim; each id is checked against the GSA rev5 Moderate
/// baseline before it is mapped, never invented. The section is the control's
/// 800-53 family, derived from the id prefix.
fn fedramp(id: &str, title: &str) -> ComplianceMapping {
    let family = if id.starts_with("SC-") {
        "System and Communications Protection"
    } else {
        "Configuration Management"
    };
    ComplianceMapping {
        compliance_framework: ComplianceFramework::FedRAMP,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some(family.to_string()),
    }
}

/// Returns compliance mappings for firewall findings.
///
/// CIS is the project's existing benchmark mapping. STIG/NIST/PCI-DSS entries
/// are sourced from the matching ComplianceAsCode/SSG rule's `references:`
/// block; NIST titles/sections and the PCI-DSS v4.0 id/title are reconciled
/// with the project's framework definitions in
/// `hardener-compliance/src/frameworks/`. HIPAA/GDPR/ISO 27001 entries map the
/// host firewall to data-in-transit and network-security controls.
/// Every compliance mapping this plugin can emit. The firewall plugin raises a
/// single fixed mapping set, so coverage is exactly that set.
pub fn coverage() -> Vec<ComplianceMapping> {
    get_firewall_compliance_mappings()
}

fn get_firewall_compliance_mappings() -> Vec<ComplianceMapping> {
    vec![
        // The firewall plugin detects ufw/nftables/firewalld; a detected backend
        // satisfies "a firewall is installed".
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "3.4.1.1".to_string(),
            compliance_control_title: "Ensure firewall is installed".to_string(),
            compliance_section: Some("Network Configuration".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "3.4.1.2".to_string(),
            compliance_control_title: "Ensure firewall service is enabled and running".to_string(),
            compliance_section: Some("Network Configuration".to_string()),
        },
        // SSG: service_firewalld_enabled
        // refs: nist AC-4/CM-7(b)/CA-3(5)/SC-7(21)/CM-6(a), stigid@ol8
        // OL08-00-040101. SSG carries no pcidss ref; PCI-DSS v4.0 1.4.1 is the
        // network-security-controls requirement a host firewall satisfies (see
        // hardener-compliance/src/frameworks/pci.rs).
        ComplianceMapping {
            compliance_framework: ComplianceFramework::STIG,
            compliance_control_id: "RHEL-08-040101".to_string(),
            compliance_control_title: "A firewall must be enabled and active".to_string(),
            compliance_section: Some("DISA STIG".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "SC-7".to_string(),
            compliance_control_title: "Boundary Protection".to_string(),
            compliance_section: Some("System and Communications Protection".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::NIST,
            compliance_control_id: "CM-7".to_string(),
            compliance_control_title: "Least Functionality".to_string(),
            compliance_section: Some("Configuration Management".to_string()),
        },
        ComplianceMapping {
            compliance_framework: ComplianceFramework::PCIDSS,
            compliance_control_id: "1.4.1".to_string(),
            compliance_control_title: "NSCs are implemented between trusted and untrusted networks"
                .to_string(),
            compliance_section: Some("Network Security Controls".to_string()),
        },
        // Cross-framework: a host firewall enforces the network boundary that
        // protects data in transit and governs reachable network services.
        hipaa("164.312(e)(1)", "Transmission security"),
        gdpr("TM-SH", "System hardening of processing systems"),
        gdpr("TM-NW", "Network-level protection of processing systems"),
        iso("8.20", "Networks security", "Technological"),
        iso("8.21", "Security of network services", "Technological"),
        // SOC 2: CC6.6 mirrors the SC-7 boundary-protection intent of the host firewall.
        soc2(
            "CC6.6",
            "Protect against threats from sources outside system boundaries",
        ),
        // 800-171r3 3.13.1 ← 800-53 SC-7; 3.4.6 ← CM-7 (SP 800-171r3
        // source-control table).
        nist171("3.13.1", "Boundary Protection"),
        nist171("3.4.6", "Least Functionality"),
        // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 SC-7.
        fedramp("SC-7", "Boundary Protection"),
        // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 CM-7.
        fedramp("CM-7", "Least Functionality"),
    ]
}

/// Returns sensible default firewall rules for hardening.
///
/// These rules provide a secure baseline:
/// - Allow loopback traffic (localhost communication)
/// - Allow established and related connections (don't break existing sessions)
/// - Allow SSH (port 22) to prevent lockout
/// - Drop all other inbound traffic by default.
pub fn get_baseline_rules() -> Vec<Rule> {
    vec![
        Rule {
            rule_description: "Allow loopback traffic".to_string(),
            rule_protocol: "all".to_string(),
            rule_port: "any".to_string(),
            rule_source: "127.0.0.1/8".to_string(),
            rule_action: "accept".to_string(),
        },
        Rule {
            rule_description: "Allow established and related connections".to_string(),
            rule_protocol: "all".to_string(),
            rule_port: "any".to_string(),
            rule_source: "any".to_string(),
            rule_action: "accept".to_string(),
        },
        Rule {
            rule_description: "Allow SSH to prevent lockout".to_string(),
            rule_protocol: "tcp".to_string(),
            rule_port: "22".to_string(),
            rule_source: "any".to_string(),
            rule_action: "accept".to_string(),
        },
        Rule {
            rule_description: "Drop all other inbound traffic by default".to_string(),
            rule_protocol: "all".to_string(),
            rule_port: "any".to_string(),
            rule_source: "any".to_string(),
            rule_action: "drop".to_string(),
        },
    ]
}

/// Derives a short semantic identifier from a firewall rule.
///
/// Baseline rules get well-known ids; custom rules get a normalised slug.
/// The ids serve as keys for config directives and exceptions.
fn rule_id(rule: &Rule) -> String {
    match rule.rule_description.as_str() {
        "Allow loopback traffic" => "loopback".to_string(),
        "Allow established and related connections" => "established".to_string(),
        "Allow SSH to prevent lockout" => "ssh".to_string(),
        "Drop all other inbound traffic by default" => "drop_default".to_string(),
        other => other.to_lowercase().replace(' ', "_"),
    }
}

/// Applies directive overrides to a single firewall rule.
///
/// Directives use `<rule_id>.<field>` keys:
/// - `ssh.port` = "2222"
/// - `ssh.source` = "10.0.0.0/8"
fn apply_rule_directives(rule: &mut Rule, id: &str, config: &PluginConfig) {
    if let Some(port) = config.directives.get(&format!("{id}.port")) {
        rule.rule_port = port.clone();
    }
    if let Some(source) = config.directives.get(&format!("{id}.source")) {
        rule.rule_source = source.clone();
    }
    if let Some(protocol) = config.directives.get(&format!("{id}.protocol")) {
        rule.rule_protocol = protocol.clone();
    }
    if let Some(action) = config.directives.get(&format!("{id}.action")) {
        rule.rule_action = action.clone();
    }
}

/// Main firewall hardening plugin
///
/// This plugin automatically detects and uses the appropriate firewall
/// backend for the system (nftables, firewalld, or ufw).
pub struct FirewallHardeningPlugin {}

impl Default for FirewallHardeningPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Root-free unit-state probe. Judged by exit code only (locale-immune).
async fn systemd_unit_active(ctx: &Context, unit: &str) -> bool {
    ctx.executor()
        .execute_command("systemctl", &["is-active", unit])
        .await
        .map(|output| output.success())
        .unwrap_or(false)
}

/// Activity classification for one installed firewall backend.
enum BackendActivity {
    /// The backend's own probe confirmed it is managing traffic.
    Verified,
    /// The probe needs root, but the backend's systemd unit is active.
    UnitActiveUnverified,
    /// The probe needs root and the unit is not active either.
    Unknown,
    /// The probe ran and reported the backend inactive.
    Inactive,
}

/// Whether a backend is the one actively managing traffic, degrading to the
/// systemd unit hint when the backend's own probe is blocked by privileges.
/// Returns the probe outcome so the caller can distinguish "verified active"
/// from "unit active but ruleset unverifiable without root".
async fn backend_activity(ctx: &Context, backend: &dyn FirewallBackend) -> BackendActivity {
    match backend.is_enabled(ctx).await {
        Ok(()) => BackendActivity::Verified,
        Err(e) if hardener_common::error::message_indicates_permission_denied(&e.to_string()) => {
            if systemd_unit_active(ctx, backend.systemd_unit()).await {
                BackendActivity::UnitActiveUnverified
            } else {
                BackendActivity::Unknown
            }
        }
        Err(_) => BackendActivity::Inactive,
    }
}

impl FirewallHardeningPlugin {
    /// Create a new firewall plugin instance.
    ///
    /// The backend is detected lazily during the first operation.
    pub fn new() -> FirewallHardeningPlugin {
        FirewallHardeningPlugin {}
    }

    /// Detects and returns the appropriate firewall backend for this system.
    ///
    /// Detection order (used as an installed-order tie-breaker, see below):
    /// 1. firewalld (RHEL/Fedora/CentOS)
    /// 2. ufw (Ubuntu/Debian)
    /// 3. nftables (modern systems, direct control)
    ///
    /// A host can have more than one backend installed without all of them
    /// being the one actually managing traffic (e.g. ufw installed but
    /// never enabled on an Arch host that runs nftables directly). Among the
    /// backends actually present, the first one that reports itself as
    /// ACTIVE (`is_enabled`) wins, regardless of installed-order; this stops
    /// hardening from driving an inactive firewall while the real one goes
    /// untouched. If none of the installed backends are active, selection
    /// falls back to the installed-order above (first detected), matching
    /// prior behaviour.
    ///
    /// # Returns
    /// A boxed backend implementation, or an error if no backend is available.
    async fn detect_backend(&self, ctx: &Context) -> Result<Box<dyn FirewallBackend>> {
        let candidates: Vec<Box<dyn FirewallBackend>> = vec![
            Box::new(firewalld::FirewalldBackend::new()),
            Box::new(ufw::UfwBackend::new()),
            Box::new(nftables::NftablesBackend::new()),
        ];

        let mut installed = Vec::with_capacity(candidates.len());
        for backend in candidates {
            if backend.detect(ctx).await? {
                installed.push(backend);
            }
        }

        if installed.is_empty() {
            return Err(hardener_common::error::HardeningError::Plugin(
                "No supported firewall backend found (checked: firewalld, ufw, nftables)"
                    .to_string(),
            ));
        }

        let mut active_index = None;
        for (index, backend) in installed.iter().enumerate() {
            if matches!(
                backend_activity(ctx, backend.as_ref()).await,
                BackendActivity::Verified | BackendActivity::UnitActiveUnverified
            ) {
                active_index = Some(index);
                break;
            }
        }

        let winner_index = active_index.unwrap_or(0);
        let winner = installed.remove(winner_index);
        match active_index {
            Some(_) => info!(
                "Selected {} firewall backend (active among {} installed)",
                winner.backend_name(),
                installed.len() + 1
            ),
            None => info!(
                "No active firewall backend among {} installed; falling back to {} \
                 (first in installed-order)",
                installed.len() + 1,
                winner.backend_name()
            ),
        }
        Ok(winner)
    }
}

#[async_trait]
impl HardeningPlugin for FirewallHardeningPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_category: FindingCategory::Network,
            plugin_description:
                "Manages firewall configuration across nftables, firewalld, and ufw".to_string(),
            plugin_id: PluginId::new("firewall-hardening"),
            plugin_name: "Firewall Hardening".to_string(),
            plugin_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn dependencies(&self) -> Vec<PluginId> {
        // Firewall hardening has no dependencies
        vec![]
    }

    async fn scan(&self, ctx: &Context) -> Result<ScanResult> {
        let start_time = Instant::now();
        let plugin_id = PluginId::new("firewall-hardening");

        let mut findings = Vec::new();

        // Detect backend.
        let backend = match self.detect_backend(ctx).await {
            Ok(backend) => backend,
            Err(e) => {
                return Ok(ScanResult {
                    scan_plugin_id: plugin_id,
                    scan_success: false,
                    scan_findings: vec![],
                    scan_unchecked: vec![],
                    scan_duration_us: start_time.elapsed().as_micros() as u64,
                    scan_error: Some(format!("No firewall backend: {}", e)),
                });
            }
        };

        // Check if firewall is enabled, degrading to the root-free systemd
        // unit hint when the backend's own probe needs privileges.
        let mut unchecked = Vec::new();
        match backend_activity(ctx, backend.as_ref()).await {
            BackendActivity::Verified => {}
            BackendActivity::UnitActiveUnverified | BackendActivity::Unknown => {
                unchecked.push(UncheckedCheck {
                    unchecked_check_id: format!("{}-disabled", backend.backend_name()),
                    unchecked_title: "Active firewall ruleset".to_string(),
                    unchecked_category: FindingCategory::Network,
                    unchecked_reason: format!(
                        "verifying the active {} ruleset requires root",
                        backend.backend_name()
                    ),
                    unchecked_compliance: get_firewall_compliance_mappings(),
                });
            }
            BackendActivity::Inactive => {
                findings.push(Finding {
                    finding_category: FindingCategory::Network,
                    finding_current_value: "disabled".to_string(),
                    finding_description: format!(
                        "{} firewall is not enabled",
                        backend.backend_name()
                    ),
                    finding_explanation: "A firewall provides essential network protection"
                        .to_string(),
                    finding_id: format!("{}-disabled", backend.backend_name()),
                    finding_impact: "System exposed to network attacks".to_string(),
                    finding_recommended_value: "enabled".to_string(),
                    finding_remediation_steps: vec![format!(
                        "Enable {} firewall",
                        backend.backend_name()
                    )],
                    finding_severity: Severity::High,
                    finding_title: "Firewall disabled".to_string(),
                    finding_compliance: get_firewall_compliance_mappings(),
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
        use std::path::Path;

        let apply_plugin_id = PluginId::new("firewall-hardening");

        // Create checkpoint for firewall config files
        let firewall_paths: Vec<&Path> = vec![
            Path::new("/etc/nftables.conf"),
            Path::new("/etc/firewalld"),
            Path::new("/etc/ufw"),
        ];
        let checkpoint_id = crate::create_checkpoint_for_apply(
            ctx,
            "firewall-hardening-pre-apply",
            &firewall_paths,
        )
        .await?;

        // Detect backend.
        let backend = match self.detect_backend(ctx).await {
            Ok(b) => b,
            Err(e) => {
                return Ok(ApplyResult {
                    apply_plugin_id,
                    apply_success: false,
                    apply_changes: vec![],
                    apply_checkpoint_id: checkpoint_id,
                    apply_error: Some(format!("No firewall backend: {}", e)),
                });
            }
        };

        // Enable firewall if not already enabled.
        if backend.is_enabled(ctx).await.is_err() {
            backend.enable(ctx).await?;
        }

        // Build rule set with config filtering and directive overrides.
        let baseline_rules = backend.get_default_rules();
        let mut rules = Vec::with_capacity(baseline_rules.len());
        let mut apply_changes = Vec::new();

        if checkpoint_id.is_some() {
            apply_changes.push(Change {
                change_description: "Created checkpoint for rollback".to_string(),
                change_type: ChangeType::FirewallRule,
                change_success: true,
                change_error: None,
            });
        }

        for rule in baseline_rules {
            let id = rule_id(&rule);
            if let Some(exception) = config.has_valid_exception(&id) {
                info!(
                    "Skipping firewall rule '{}' (exception: {})",
                    id, exception.reason
                );
                apply_changes.push(Change {
                    change_description: format!(
                        "{}: skipped (exception: {})",
                        rule.rule_description, exception.reason
                    ),
                    change_type: ChangeType::FirewallRule,
                    change_success: true,
                    change_error: None,
                });
                continue;
            }
            let mut rule = rule;
            apply_rule_directives(&mut rule, &id, config);
            rules.push(rule);
        }

        let mut backend_changes = backend.apply_rules(ctx, &rules).await?;
        apply_changes.append(&mut backend_changes);

        Ok(ApplyResult {
            apply_plugin_id,
            apply_success: apply_changes.iter().all(|c| c.change_success),
            apply_changes,
            apply_checkpoint_id: checkpoint_id,
            apply_error: None,
        })
    }

    async fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()> {
        info!(
            "Rolling back firewall configuration to checkpoint: {}",
            checkpoint.checkpoint_id.as_str()
        );

        // Restore configuration files from checkpoint
        crate::rollback_files_from_checkpoint(ctx, checkpoint)?;

        info!("Firewall configuration files restored from checkpoint");

        // Re-enable firewall to reload rules based on detected backend
        match self.detect_backend(ctx).await {
            Ok(backend) => match backend.enable(ctx).await {
                Ok(_) => info!("Firewall re-enabled successfully"),
                Err(e) => warn!("Failed to re-enable firewall: {}", e),
            },
            Err(e) => {
                warn!("Could not detect firewall backend for reload: {}", e);
            }
        }

        Ok(())
    }

    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> {
        let validation_plugin_id = PluginId::new("firewall-hardening");
        let mut issues = Vec::new();
        let mut estimated_changes = Vec::new();

        // Detect backend.
        match self.detect_backend(ctx).await {
            Ok(backend) => {
                // Check if firewall is enabled.
                if let Err(e) = backend.is_enabled(ctx).await {
                    let error_msg = e.to_string();
                    if error_msg.contains("permission denied")
                        || error_msg.contains("Permission denied")
                    {
                        issues.push(hardener_core::ValidationIssue {
                            validation_issue_severity: Severity::Medium,
                            validation_issue_message:
                                "Cannot verify firewall status (permission denied)".to_string(),
                            validation_issue_config_key: None,
                        });
                    } else {
                        // Firewall is disabled - will be enabled.
                        estimated_changes
                            .push(format!("Enable {} firewall", backend.backend_name()));
                    }
                }

                // Count rules after config filtering.
                let rule_count = backend
                    .get_default_rules()
                    .iter()
                    .filter(|r| config.has_valid_exception(&rule_id(r)).is_none())
                    .count();
                if rule_count > 0 {
                    estimated_changes.push(format!("Apply {} baseline firewall rules", rule_count));
                }
            }
            Err(e) => {
                issues.push(hardener_core::ValidationIssue {
                    validation_issue_severity: Severity::Critical,
                    validation_issue_message: format!("No firewall backend available: {}", e),
                    validation_issue_config_key: None,
                });
            }
        }

        Ok(ValidationReport {
            validation_report_plugin_id: validation_plugin_id,
            validation_report_is_valid: issues
                .iter()
                .all(|i| i.validation_issue_severity != Severity::Critical),
            validation_report_issues: issues,
            validation_report_estimated_changes: estimated_changes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hardener_core::{CommandOutput, MockExecutor};

    /// Reproduces the maintainer's hardened-Arch scenario: nftables and ufw
    /// are both installed, the unprivileged `nft list ruleset` probe fails
    /// with permission denied, but the nftables systemd unit is active while
    /// ufw's is not. Selection must prefer nftables via the root-free unit
    /// hint, and the ruleset check must be reported unchecked rather than
    /// as a false "Firewall disabled" finding.
    #[tokio::test]
    async fn scan_prefers_systemd_active_backend_and_reports_unchecked_when_probe_needs_root() {
        let mock = MockExecutor::new()
            .with_command_exists("firewall-cmd", false)
            .with_command_exists("ufw", true)
            .with_command_exists("nft", true)
            .with_command(
                "nft",
                &["list", "ruleset"],
                CommandOutput {
                    stdout: String::new(),
                    stderr: "nft: Permission denied".to_string(),
                    exit_code: 1,
                },
            )
            .with_command(
                "systemctl",
                &["is-active", "nftables"],
                CommandOutput {
                    stdout: "active\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_command(
                "systemctl",
                &["is-active", "ufw"],
                CommandOutput {
                    stdout: "inactive\n".to_string(),
                    stderr: String::new(),
                    exit_code: 3,
                },
            );
        let ctx = Context::with_executor(std::sync::Arc::new(mock));
        let result = FirewallHardeningPlugin::new().scan(&ctx).await.unwrap();

        assert!(result.scan_findings.is_empty(), "no false disabled finding");
        assert_eq!(result.scan_unchecked.len(), 1);
        assert_eq!(
            result.scan_unchecked[0].unchecked_check_id,
            "nftables-disabled"
        );
    }

    #[test]
    fn coverage_includes_firewall_installed_control() {
        let ids: Vec<String> = coverage()
            .into_iter()
            .filter(|m| m.compliance_framework == ComplianceFramework::CIS)
            .map(|m| m.compliance_control_id)
            .collect();
        assert!(ids.contains(&"3.4.1.1".to_string()), "must map CIS 3.4.1.1");
        assert!(
            ids.contains(&"3.4.1.2".to_string()),
            "must retain CIS 3.4.1.2"
        );
    }

    /// Confirms the firewall finding now carries multi-framework mappings:
    /// CIS (existing) plus STIG and NIST sourced from SSG.
    #[test]
    fn firewall_maps_cis_stig_and_nist() {
        let mappings = get_firewall_compliance_mappings();

        let frameworks: Vec<ComplianceFramework> =
            mappings.iter().map(|m| m.compliance_framework).collect();

        assert!(
            frameworks.contains(&ComplianceFramework::CIS),
            "CIS mapping must be preserved"
        );
        assert!(
            frameworks.contains(&ComplianceFramework::STIG),
            "STIG mapping must be added"
        );
        assert!(
            frameworks.contains(&ComplianceFramework::NIST),
            "NIST mapping must be added"
        );
    }

    /// Confirms the firewall finding additionally carries the data-protection
    /// frameworks (HIPAA transmission security, GDPR network protection, ISO
    /// 27001) alongside the existing CIS/STIG/NIST/PCI-DSS mappings.
    #[test]
    fn firewall_maps_hipaa_gdpr_and_iso27001() {
        let mappings = get_firewall_compliance_mappings();

        let frameworks: Vec<ComplianceFramework> =
            mappings.iter().map(|m| m.compliance_framework).collect();

        assert!(
            frameworks.contains(&ComplianceFramework::HIPAA),
            "HIPAA mapping must be added"
        );
        assert!(
            frameworks.contains(&ComplianceFramework::GDPR),
            "GDPR mapping must be added"
        );
        assert!(
            frameworks.contains(&ComplianceFramework::ISO27001),
            "ISO 27001 mapping must be added"
        );

        // Networks-security control 8.20 must be present for a network boundary
        // control, and HIPAA maps to the transmission-security standard.
        assert!(
            mappings
                .iter()
                .any(|m| m.compliance_framework == ComplianceFramework::ISO27001
                    && m.compliance_control_id == "8.20"),
            "ISO 27001 clause 8.20 (Networks security) must be present"
        );
        let hipaa = mappings
            .iter()
            .find(|m| m.compliance_framework == ComplianceFramework::HIPAA)
            .expect("HIPAA mapping present");
        assert_eq!(hipaa.compliance_control_id, "164.312(e)(1)");
    }

    /// Confirms the host firewall carries the SOC 2 boundary-protection
    /// criterion CC6.6, filed under its Trust Services Criteria series.
    #[test]
    fn firewall_maps_soc2_boundary_criterion() {
        let soc2 = get_firewall_compliance_mappings()
            .into_iter()
            .find(|m| m.compliance_framework == ComplianceFramework::SOC2)
            .expect("firewall must carry a SOC 2 mapping");
        assert_eq!(soc2.compliance_control_id, "CC6.6");
        assert_eq!(
            soc2.compliance_section.as_deref(),
            Some("Logical and Physical Access Controls")
        );
    }

    /// Confirms the 800-171r3 crosswalk for the host firewall: SC-7 → 3.13.1
    /// and CM-7 → 3.4.6, each filed under its official family.
    #[test]
    fn firewall_maps_nist_800_171_requirements() {
        let mappings: Vec<_> = get_firewall_compliance_mappings()
            .into_iter()
            .filter(|m| m.compliance_framework == ComplianceFramework::NIST800171)
            .map(|m| (m.compliance_control_id, m.compliance_section))
            .collect();
        for (id, family) in [
            ("3.13.1", "System and Communications Protection"),
            ("3.4.6", "Configuration Management"),
        ] {
            assert!(
                mappings.contains(&(id.to_string(), Some(family.to_string()))),
                "firewall must carry 800-171 {id} under {family}"
            );
        }
    }

    /// Confirms the FedRAMP derivation for the host firewall: SC-7 and CM-7
    /// are both GSA rev5 Moderate baseline members, mirrored verbatim from
    /// the existing 800-53 entries under their official families.
    #[test]
    fn firewall_maps_fedramp_moderate_controls() {
        let mappings: Vec<_> = get_firewall_compliance_mappings()
            .into_iter()
            .filter(|m| m.compliance_framework == ComplianceFramework::FedRAMP)
            .map(|m| (m.compliance_control_id, m.compliance_section))
            .collect();
        for (id, family) in [
            ("SC-7", "System and Communications Protection"),
            ("CM-7", "Configuration Management"),
        ] {
            assert!(
                mappings.contains(&(id.to_string(), Some(family.to_string()))),
                "firewall must carry FedRAMP {id} under {family}"
            );
        }
    }
}
