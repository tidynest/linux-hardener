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

/// Every compliance mapping this plugin can emit. The firewall plugin raises a
/// single fixed mapping set, so coverage is exactly that set.
pub fn coverage() -> Vec<ComplianceMapping> {
    get_firewall_compliance_mappings()
}

/// Returns compliance mappings for firewall findings.
///
/// CIS is the project's existing benchmark mapping. STIG/NIST/PCI-DSS entries
/// are sourced from the matching ComplianceAsCode/SSG rule's `references:`
/// block; NIST titles/sections and the PCI-DSS v4.0 id/title are reconciled
/// with the project's framework definitions in
/// `hardener-compliance/src/frameworks/`. HIPAA/GDPR/ISO 27001 entries map the
/// host firewall to data-in-transit and network-security controls.
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

/// The error raised when none of the supported backends are installed.
fn no_backend_error() -> hardener_common::error::HardeningError {
    hardener_common::error::HardeningError::Plugin(
        "No supported firewall backend found (checked: firewalld, ufw, nftables)".to_string(),
    )
}

/// Detects installed backends and classifies each one's activity in a
/// single pass, so every backend's probe runs exactly once per scan or
/// apply operation. Order matches the detection order below, which both
/// `detect_backend` and `scan` rely on for installed-order fallback
/// semantics (firewalld, ufw, nftables tie-break).
async fn classify_installed(
    ctx: &Context,
) -> Result<Vec<(Box<dyn FirewallBackend>, BackendActivity)>> {
    let candidates: Vec<Box<dyn FirewallBackend>> = vec![
        Box::new(firewalld::FirewalldBackend::new()),
        Box::new(ufw::UfwBackend::new()),
        Box::new(nftables::NftablesBackend::new()),
    ];

    let mut classified = Vec::with_capacity(candidates.len());
    for backend in candidates {
        if backend.detect(ctx).await? {
            let activity = backend_activity(ctx, backend.as_ref()).await;
            classified.push((backend, activity));
        }
    }

    Ok(classified)
}

/// Index of the backend the apply path would drive: the first classified
/// Verified or UnitActiveUnverified, in installed order. None when no
/// backend's activity places it in charge. Shared by `detect_backend`
/// (selection) and `scan` (honesty gate) so the two can never disagree
/// about who the winner is.
fn find_winner(classified: &[(Box<dyn FirewallBackend>, BackendActivity)]) -> Option<usize> {
    classified.iter().position(|(_, activity)| {
        matches!(
            activity,
            BackendActivity::Verified | BackendActivity::UnitActiveUnverified
        )
    })
}

/// Appends the "Apply N baseline firewall rules" estimate for `backend`,
/// counting only rules not waived by a config exception, and records each
/// waived rule in `exceptions` as the documented deviation it is. Shared by the
/// verified-active and genuinely-disabled arms of `validate`.
///
/// One pass over the baseline, because the rule a count leaves out and the line
/// that names it are two halves of the same decision. Computing them apart is
/// how the count came to shrink with nothing anywhere saying why, and how it
/// came to vanish entirely once every rule was waived.
fn push_rule_estimate(
    backend: &dyn FirewallBackend,
    config: &PluginConfig,
    out: &mut Vec<String>,
    exceptions: &mut Vec<String>,
) {
    let mut rule_count = 0usize;
    for rule in backend.get_default_rules() {
        let id = rule_id(&rule);
        match config.has_valid_exception(&id) {
            // Named by the description apply prints when it skips this rule, so
            // the preview and the run it previews identify the rule the same
            // way. The config keys the exception on the id instead, which is a
            // real gap between what an operator reads here and what they typed;
            // closing it by naming the id here would only move the gap to
            // between the preview and the apply, which is worse.
            Some(exception) => exceptions.push(hardener_common::types::exception_preview_line(
                &rule.rule_description,
                "not applied",
                &exception.reason,
            )),
            None => rule_count += 1,
        }
    }
    if rule_count > 0 {
        out.push(format!("Apply {rule_count} baseline firewall rules"));
    }
}

/// The Critical validation issue raised when no firewall backend is
/// installed (or detection itself failed).
fn no_backend_issue(message: &str) -> hardener_core::ValidationIssue {
    hardener_core::ValidationIssue {
        validation_issue_severity: Severity::Critical,
        validation_issue_message: format!("No firewall backend available: {message}"),
        validation_issue_config_key: None,
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
        let mut classified = classify_installed(ctx).await?;

        if classified.is_empty() {
            return Err(no_backend_error());
        }

        let installed_count = classified.len();
        let active_index = find_winner(&classified);

        let winner_index = active_index.unwrap_or(0);
        let (winner, _) = classified.remove(winner_index);
        match active_index {
            Some(_) => info!(
                "Selected {} firewall backend (active among {} installed)",
                winner.backend_name(),
                installed_count
            ),
            None => info!(
                "No active firewall backend among {} installed; falling back to {} \
                 (first in installed-order)",
                installed_count,
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

    async fn scan(&self, ctx: &Context, _config: &PluginConfig) -> Result<ScanResult> {
        let start_time = Instant::now();
        let plugin_id = PluginId::new("firewall-hardening");

        // Classify every installed backend once; the honesty check below
        // and the red "disabled" finding both read from this single pass,
        // so no backend is ever probed twice.
        let classified = match classify_installed(ctx).await {
            Ok(classified) => classified,
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

        if classified.is_empty() {
            return Ok(ScanResult {
                scan_plugin_id: plugin_id,
                scan_success: false,
                scan_findings: vec![],
                scan_unchecked: vec![],
                scan_duration_us: start_time.elapsed().as_micros() as u64,
                scan_error: Some(format!("No firewall backend: {}", no_backend_error())),
            });
        }

        let mut findings = Vec::new();
        let mut unchecked = Vec::new();

        // Honesty gate, judged from the winner outwards. The winner is the
        // backend the apply path would drive (find_winner, shared with
        // detect_backend). A Verified winner settles the host-level
        // question - one confirmed active firewall - so sibling backends'
        // unknowability is irrelevant and the scan stays silent. A
        // UnitActiveUnverified winner is itself the backend whose ruleset
        // could not be seen, so the unchecked entry names the WINNER, not
        // whichever unverifiable backend comes first in installed order.
        // Only with no winner at all does the first Unknown backend (in
        // installed order) name the entry. The red "disabled" finding is
        // warranted only once every installed backend's probe ran and
        // confirmed inactive.
        let blocked = match find_winner(&classified).map(|index| &classified[index]) {
            Some((_, BackendActivity::Verified)) => None,
            Some((backend, _)) => Some(backend),
            None => classified
                .iter()
                .find(|(_, activity)| matches!(activity, BackendActivity::Unknown))
                .map(|(backend, _)| backend),
        };

        if let Some(backend) = blocked {
            unchecked.push(UncheckedCheck {
                unchecked_check_id: format!("{}-disabled", backend.backend_name()),
                unchecked_title: "Active firewall ruleset".to_string(),
                unchecked_category: FindingCategory::Network,
                unchecked_reason: format!(
                    "verifying the active {} ruleset requires root",
                    backend.backend_name()
                ),
                unchecked_needs_privilege: true,
                unchecked_compliance: get_firewall_compliance_mappings(),
            });
        } else if classified
            .iter()
            .all(|(_, activity)| matches!(activity, BackendActivity::Inactive))
        {
            let (backend, _) = &classified[0];
            findings.push(Finding {
                finding_category: FindingCategory::Network,
                finding_current_value: "disabled".to_string(),
                finding_description: format!("{} firewall is not enabled", backend.backend_name()),
                finding_explanation: "A firewall provides essential network protection".to_string(),
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

        apply_changes.extend(crate::checkpoint_change(&checkpoint_id));

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
                    change_type: ChangeType::Skipped,
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
        // Excepted rules are recorded rather than dropped: a preview that omits
        // them shows a documented deviation as nothing at all. Filled only
        // where the baseline is assessed at all, so the arm that cannot read
        // the live ruleset reports its own limitation instead and claims
        // nothing about the baseline either way.
        let mut exceptions: Vec<String> = Vec::new();

        // Classify every installed backend once, exactly as `scan` does, so
        // the dry-run preview cannot disagree with the scan about which
        // backend is in charge or whether the firewall is genuinely
        // disabled. Without this, an unprivileged preview on a host whose
        // real ruleset needs root would fall back to an inactive sibling
        // (e.g. ufw) and falsely report "Enable ufw firewall".
        match classify_installed(ctx).await {
            Ok(classified) if !classified.is_empty() => {
                // Select the same winner `detect_backend` (and the apply
                // path) would, so a suppressed or estimated change never
                // names a different backend than the apply drives.
                let winner_index = find_winner(&classified).unwrap_or(0);
                let (winner, winner_activity) = &classified[winner_index];
                let all_inactive = classified
                    .iter()
                    .all(|(_, activity)| matches!(activity, BackendActivity::Inactive));

                match winner_activity {
                    // Confirmed active: no enable needed. Report the
                    // rule-level pending changes as before.
                    BackendActivity::Verified => {
                        push_rule_estimate(
                            winner.as_ref(),
                            config,
                            &mut estimated_changes,
                            &mut exceptions,
                        );
                    }
                    // Every installed backend's probe ran and reported
                    // inactive: the firewall is genuinely disabled, so
                    // enabling it and applying the baseline rules are real
                    // pending changes.
                    BackendActivity::Inactive if all_inactive => {
                        estimated_changes
                            .push(format!("Enable {} firewall", winner.backend_name()));
                        push_rule_estimate(
                            winner.as_ref(),
                            config,
                            &mut estimated_changes,
                            &mut exceptions,
                        );
                    }
                    // Unverifiable without root (UnitActiveUnverified, an
                    // Unknown winner, or an inactive fallback shadowed by an
                    // Unknown sibling): the live ruleset could not be read,
                    // so claiming "Enable X" or a concrete rule count would
                    // be a guess. Report the honest limitation instead; the
                    // privileged apply re-classifies and does the right thing.
                    //
                    // An issue rather than an estimated change: the pending
                    // list is documented as genuinely pending changes and its
                    // length is what a renderer prints as the change count and
                    // what the fleet path sums into `would_change`, so a line
                    // saying nothing is known counted as one queued write.
                    // Medium, not High, because this is a limit on what an
                    // unprivileged run can see rather than a failure: the
                    // privileged apply reads the ruleset and succeeds, so
                    // failing the dry run would fail on every host whose
                    // firewall probe needs root.
                    _ => {
                        issues.push(hardener_core::ValidationIssue {
                            validation_issue_severity: Severity::Medium,
                            validation_issue_message:
                                "Firewall ruleset could not be verified without root - \
                                 run with sudo (or a deep scan) for an accurate preview"
                                    .to_string(),
                            validation_issue_config_key: None,
                        });
                    }
                }
            }
            Ok(_) => issues.push(no_backend_issue(&no_backend_error().to_string())),
            Err(e) => issues.push(no_backend_issue(&e.to_string())),
        }

        Ok(ValidationReport {
            validation_report_plugin_id: validation_plugin_id,
            validation_report_is_valid: issues
                .iter()
                .all(|i| i.validation_issue_severity != Severity::Critical),
            validation_report_issues: issues,
            validation_report_estimated_changes: estimated_changes,
            validation_report_compliant_count: 0,
            validation_report_exceptions: exceptions,
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
        let result = FirewallHardeningPlugin::new()
            .scan(&ctx, &PluginConfig::default())
            .await
            .unwrap();

        assert!(result.scan_findings.is_empty(), "no false disabled finding");
        assert_eq!(result.scan_unchecked.len(), 1);
        assert_eq!(
            result.scan_unchecked[0].unchecked_check_id,
            "nftables-disabled"
        );
    }

    /// Reproduces the maintainer-host acceptance gap: ufw and nftables are
    /// both installed, nftables' ruleset is loaded in-kernel but its unit is
    /// inactive (loaded outside the unit) and the probe is permission
    /// blocked, so nftables' true state is unknowable. ufw's own probe runs
    /// cleanly and reports disabled. Reporting the red finding here would be
    /// a false positive: nftables might well be the active firewall.
    #[tokio::test]
    async fn scan_reports_unchecked_when_blocked_backend_might_be_active() {
        // ufw + nftables installed; nft probe permission-blocked; BOTH units
        // inactive (ruleset loaded outside the unit). ufw's probe runs and says
        // disabled - but nftables' state is unknowable, so no red finding.
        let mock = MockExecutor::new()
            .with_command_exists("firewall-cmd", false)
            .with_command_exists("ufw", true)
            .with_command_exists("nft", true)
            .with_command(
                "nft",
                &["list", "ruleset"],
                CommandOutput {
                    stdout: String::new(),
                    stderr: "Operation not permitted (you must be root)".to_string(),
                    exit_code: 1,
                },
            )
            .with_command(
                "systemctl",
                &["is-active", "nftables"],
                CommandOutput {
                    stdout: "inactive\n".to_string(),
                    stderr: String::new(),
                    exit_code: 3,
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
        let result = FirewallHardeningPlugin::new()
            .scan(&ctx, &PluginConfig::default())
            .await
            .unwrap();

        assert!(
            result.scan_findings.is_empty(),
            "no red finding while nftables is unknowable"
        );
        assert_eq!(result.scan_unchecked.len(), 1);
        assert_eq!(
            result.scan_unchecked[0].unchecked_check_id,
            "nftables-disabled"
        );
    }

    /// Negative control for the above: nftables' probe genuinely succeeds
    /// (not permission-blocked) and finds no active input-hook chain, and
    /// ufw is genuinely inactive. Every installed backend's probe ran and
    /// reported inactive, so the red finding is warranted here.
    #[tokio::test]
    async fn scan_reports_disabled_when_every_backend_probe_confirms_inactive() {
        let mock = MockExecutor::new()
            .with_command_exists("firewall-cmd", false)
            .with_command_exists("ufw", true)
            .with_command_exists("nft", true)
            .with_command(
                "nft",
                &["list", "ruleset"],
                CommandOutput {
                    stdout: "table inet filter {\n}\n".to_string(),
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
        let result = FirewallHardeningPlugin::new()
            .scan(&ctx, &PluginConfig::default())
            .await
            .unwrap();

        assert!(
            result.scan_unchecked.is_empty(),
            "every backend probe ran; nothing is unverifiable"
        );
        assert_eq!(result.scan_findings.len(), 1);
        assert_eq!(result.scan_findings[0].finding_id, "ufw-disabled");
    }

    /// A verified-active winner settles the host-level question: nftables'
    /// probe confirms an input-hook chain (Verified), while ufw's state is
    /// unknowable (its systemctl hint errors and its status fallback is
    /// permission-blocked, classifying Unknown). The scan must stay silent -
    /// no finding AND no unchecked entry - because one confirmed active
    /// firewall makes the sibling's unknowability irrelevant.
    #[tokio::test]
    async fn scan_stays_silent_when_winner_is_verified_despite_unknown_sibling() {
        let mock = MockExecutor::new()
            .with_command_exists("firewall-cmd", false)
            .with_command_exists("ufw", true)
            .with_command_exists("nft", true)
            .with_command(
                "nft",
                &["list", "ruleset"],
                CommandOutput {
                    stdout: "table inet filter {\n  chain input {\n    \
                             type filter hook input priority 0;\n  }\n}\n"
                        .to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            // `systemctl is-active ufw` deliberately unregistered: the mock
            // errors, so ufw's is_enabled falls through to its `ufw status`
            // fallback and the unit hint reads inactive.
            .with_command(
                "ufw",
                &["status"],
                CommandOutput {
                    stdout: String::new(),
                    stderr: "ERROR: You need to be root to run this script".to_string(),
                    exit_code: 1,
                },
            );
        let ctx = Context::with_executor(std::sync::Arc::new(mock));
        let result = FirewallHardeningPlugin::new()
            .scan(&ctx, &PluginConfig::default())
            .await
            .unwrap();

        assert!(
            result.scan_findings.is_empty(),
            "a verified-active firewall must not raise a finding"
        );
        assert!(
            result.scan_unchecked.is_empty(),
            "a verified-active winner answers the check; no unchecked entry"
        );
    }

    /// The unchecked entry must name the WINNER when the winner classifies
    /// UnitActiveUnverified, not whichever unverifiable backend happens to
    /// come first in installed order. Here ufw (earlier in installed order)
    /// classifies Unknown, while nftables classifies UnitActiveUnverified
    /// and is therefore the winner the apply path would drive - so the
    /// entry must read "nftables-disabled", not "ufw-disabled".
    #[tokio::test]
    async fn scan_unchecked_names_the_winner_not_the_first_unknown_sibling() {
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
            // `systemctl is-active ufw` deliberately unregistered: the mock
            // errors, so ufw's is_enabled falls through to its `ufw status`
            // fallback and the unit hint reads inactive, classifying Unknown.
            .with_command(
                "ufw",
                &["status"],
                CommandOutput {
                    stdout: String::new(),
                    stderr: "ERROR: You need to be root to run this script".to_string(),
                    exit_code: 1,
                },
            );
        let ctx = Context::with_executor(std::sync::Arc::new(mock));
        let result = FirewallHardeningPlugin::new()
            .scan(&ctx, &PluginConfig::default())
            .await
            .unwrap();

        assert!(
            result.scan_findings.is_empty(),
            "nothing is confirmed inactive; no red finding"
        );
        assert_eq!(result.scan_unchecked.len(), 1);
        assert_eq!(
            result.scan_unchecked[0].unchecked_check_id, "nftables-disabled",
            "the unchecked entry must name the winner, not the first unknown sibling"
        );
    }

    /// Part A honesty gate for the dry-run preview, the same class of fix
    /// the scan gained in 62e8c14. On the maintainer's hardened host
    /// nftables' ruleset is live but its probe needs root and its oneshot
    /// unit reads inactive (classifies Unknown), while ufw is installed and
    /// genuinely inactive. Selection falls back to ufw (installed order), but
    /// validate must NOT claim "Enable ufw": the firewall's true state is
    /// unverifiable, so it reports the honest limitation instead of a false
    /// pending change, and never names ufw.
    #[tokio::test]
    async fn validate_reports_unverifiable_instead_of_false_enable_when_probe_needs_root() {
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
                    stdout: "inactive\n".to_string(),
                    stderr: String::new(),
                    exit_code: 3,
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
        let report = FirewallHardeningPlugin::new()
            .validate(&ctx, &PluginConfig::default())
            .await
            .unwrap();

        let changes = &report.validation_report_estimated_changes;
        assert!(
            changes.is_empty(),
            "a state this run could not read queues no writes, got {changes:?}"
        );
        let reported: Vec<&str> = report
            .validation_report_issues
            .iter()
            .map(|i| i.validation_issue_message.as_str())
            .collect();
        assert!(
            reported.iter().any(|m| m.contains("could not be verified")),
            "must report the honest unverifiable line, got {reported:?}"
        );
        assert!(
            !reported.iter().any(|m| m.contains("Enable")),
            "must NOT claim a false enable for an unverifiable ruleset, got {reported:?}"
        );
        assert!(
            !reported.iter().any(|m| m.to_lowercase().contains("ufw")),
            "must NOT name ufw when nftables is the live-but-unverifiable winner, got {reported:?}"
        );
        assert!(
            !report.has_blocking_issue(),
            "a privileged apply re-classifies and succeeds, so this must not fail the dry run"
        );
    }

    /// When the winning backend is active by its systemd unit but its ruleset
    /// probe needs root (UnitActiveUnverified), validate reports the honest
    /// limitation rather than guessing at an enable or a rule count.
    #[tokio::test]
    async fn validate_reports_unverifiable_when_winner_unit_active_but_probe_blocked() {
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
        let report = FirewallHardeningPlugin::new()
            .validate(&ctx, &PluginConfig::default())
            .await
            .unwrap();

        let changes = &report.validation_report_estimated_changes;
        assert!(
            changes.is_empty(),
            "a state this run could not read queues no writes, got {changes:?}"
        );
        let reported: Vec<&str> = report
            .validation_report_issues
            .iter()
            .map(|i| i.validation_issue_message.as_str())
            .collect();
        assert!(
            reported.iter().any(|m| m.contains("could not be verified")),
            "unit-active-but-unverifiable winner must report the honest line, got {reported:?}"
        );
        assert!(
            !reported.iter().any(|m| m.contains("Enable")),
            "must NOT claim an enable for a unit-active winner, got {reported:?}"
        );
    }

    /// Negative control: every installed backend's probe ran and reported
    /// inactive (nftables' ruleset has no input hook, ufw's unit is
    /// inactive), so the firewall is genuinely disabled. "Enable X" is then a
    /// real pending change and must be kept, naming the selected backend,
    /// alongside the baseline rule estimate.
    #[tokio::test]
    async fn validate_keeps_enable_when_every_backend_probe_confirms_inactive() {
        let mock = MockExecutor::new()
            .with_command_exists("firewall-cmd", false)
            .with_command_exists("ufw", true)
            .with_command_exists("nft", true)
            .with_command(
                "nft",
                &["list", "ruleset"],
                CommandOutput {
                    stdout: "table inet filter {\n}\n".to_string(),
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
        let report = FirewallHardeningPlugin::new()
            .validate(&ctx, &PluginConfig::default())
            .await
            .unwrap();

        let changes = &report.validation_report_estimated_changes;
        assert!(
            changes.iter().any(|c| c == "Enable ufw firewall"),
            "a genuinely disabled firewall keeps the enable line, got {changes:?}"
        );
        assert!(
            changes
                .iter()
                .any(|c| c.contains("baseline firewall rules")),
            "the baseline rule estimate is still reported, got {changes:?}"
        );
        assert!(
            !changes.iter().any(|c| c.contains("could not be verified")),
            "a positively inactive firewall is not unverifiable, got {changes:?}"
        );
    }

    /// Verified-active winner (nftables input-hook chain present): validate
    /// reports the rule-level pending changes exactly as before and emits
    /// neither an enable line nor the unverifiable notice.
    #[tokio::test]
    async fn validate_reports_rule_changes_when_backend_verified_active() {
        let mock = MockExecutor::new()
            .with_command_exists("firewall-cmd", false)
            .with_command_exists("ufw", false)
            .with_command_exists("nft", true)
            .with_command(
                "nft",
                &["list", "ruleset"],
                CommandOutput {
                    stdout: "table inet filter {\n  chain input {\n    \
                             type filter hook input priority 0;\n  }\n}\n"
                        .to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            );
        let ctx = Context::with_executor(std::sync::Arc::new(mock));
        let report = FirewallHardeningPlugin::new()
            .validate(&ctx, &PluginConfig::default())
            .await
            .unwrap();

        assert_eq!(
            report.validation_report_estimated_changes,
            vec!["Apply 4 baseline firewall rules".to_string()],
            "a verified-active firewall reports only the rule estimate"
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
