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
    error::{HardeningError, Result},
    types::{ComplianceFramework, ComplianceMapping, FindingCategory, PluginId, Severity},
};
use hardener_core::{
    ApplyResult, Change, ChangeType, Checkpoint, PluginConfig, ValidationIssue, ValidationReport,
    context::Context,
    plugin::{Finding, HardeningPlugin, PluginMetadata, ScanResult, UncheckedCheck},
};
use std::path::{Path, PathBuf};
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
/// default "Services" section, notably ISO/IEC 27001:2022, whose Annex A
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

/// SOC 2 mapping for service-minimisation controls.
///
/// CC6.8 mirrors the CM-7 least-functionality intent every disabled daemon
/// serves: unneeded software is kept off the system; the section is the
/// criterion's 2017 Trust Services Criteria series.
fn service_soc2_unauthorised_software() -> ComplianceMapping {
    service_mapping_in(
        ComplianceFramework::SOC2,
        "CC6.8",
        "Prevent or detect the introduction of unauthorized or malicious software",
        "Logical and Physical Access Controls",
    )
}

/// NIST SP 800-171 Revision 3 mapping for service-minimisation controls.
///
/// Requirement 3.4.6 (Least Functionality) is sourced from 800-53 CM-7 in the
/// r3 source-control table: the control every mapped daemon already cites.
/// Family: Configuration Management.
fn service_nist171_least_functionality() -> ComplianceMapping {
    service_mapping_in(
        ComplianceFramework::NIST800171,
        "3.4.6",
        "Least Functionality",
        "Configuration Management",
    )
}

/// NIST SP 800-171 Revision 3 mapping for the Bluetooth daemon check.
///
/// Requirement 3.1.16 (Wireless Access) is sourced from 800-53 AC-18 in the
/// r3 source-control table. Family: Access Control.
fn service_nist171_wireless_access() -> ComplianceMapping {
    service_mapping_in(
        ComplianceFramework::NIST800171,
        "3.1.16",
        "Wireless Access",
        "Access Control",
    )
}

/// FedRAMP mapping for service-minimisation controls.
///
/// FedRAMP's control set is NIST 800-53 at the Moderate (Rev 5) baseline;
/// CM-7 (the control every mapped daemon already cites) is a baseline
/// member (GSA rev5 baseline), so it mirrors across verbatim. Family:
/// Configuration Management.
fn service_fedramp_least_functionality() -> ComplianceMapping {
    service_mapping_in(
        ComplianceFramework::FedRAMP,
        "CM-7",
        "Least Functionality",
        "Configuration Management",
    )
}

/// FedRAMP mapping for the Bluetooth daemon check.
///
/// AC-18 is a FedRAMP Moderate (Rev 5) baseline member (GSA rev5 baseline),
/// mirroring the arm's existing 800-53 entry. Family: Access Control.
fn service_fedramp_wireless_access() -> ComplianceMapping {
    service_mapping_in(
        ComplianceFramework::FedRAMP,
        "AC-18",
        "Wireless Access",
        "Access Control",
    )
}

/// Every compliance mapping this plugin can emit, across all services it
/// assesses. Aggregated into the engine's automated-coverage set.
pub fn coverage() -> Vec<ComplianceMapping> {
    UNNECESSARY_SERVICES
        .iter()
        .flat_map(|s| get_service_compliance_mappings(s.service_name))
        .collect()
}

/// Every managed service reported as unchecked, for the case where the service
/// listing itself failed.
///
/// Ids and compliance mappings match the findings these checks would otherwise
/// produce, so the compliance report turns each control into ManualReview
/// rather than counting it as satisfied by an absent finding.
fn unchecked_all_services(reason: &str) -> Vec<UncheckedCheck> {
    UNNECESSARY_SERVICES
        .iter()
        .map(|directive| UncheckedCheck {
            unchecked_check_id: format!("service_{}", directive.service_name.replace('-', "_")),
            unchecked_title: format!("Unnecessary service {}", directive.service_name),
            unchecked_category: FindingCategory::Services,
            unchecked_reason: format!("could not list services: {reason}"),
            unchecked_needs_privilege: false,
            unchecked_compliance: get_service_compliance_mappings(directive.service_name),
        })
        .collect()
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
/// (Networks security). SOC 2 CC6.8 applies to every mapped daemon (the
/// unauthorised-software criterion mirrors the same minimisation intent).
/// NIST SP 800-171 3.4.6 likewise applies to every mapped daemon (sourced
/// from CM-7), with 3.1.16 added for Bluetooth (sourced from AC-18).
/// FedRAMP mirrors the same 800-53 entries verbatim: CM-7 for every mapped
/// daemon and AC-18 for Bluetooth, both FedRAMP Moderate (Rev 5) baseline
/// members.
/// HIPAA is omitted: none of these daemons map cleanly to a Security Rule
/// specification.
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
            // 800-171r3 3.4.6 ← 800-53 CM-7 (SP 800-171r3 source-control table).
            service_nist171_least_functionality(),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 CM-7.
            service_fedramp_least_functionality(),
            service_gdpr_hardening(),
            service_soc2_unauthorised_software(),
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
            // 800-171r3 3.4.6 ← 800-53 CM-7 (SP 800-171r3 source-control table).
            service_nist171_least_functionality(),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 CM-7.
            service_fedramp_least_functionality(),
            service_gdpr_hardening(),
            service_iso_networks(),
            service_soc2_unauthorised_software(),
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
            // 800-171r3 3.4.6 ← 800-53 CM-7 (SP 800-171r3 source-control table).
            service_nist171_least_functionality(),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 CM-7.
            service_fedramp_least_functionality(),
            service_gdpr_hardening(),
            service_soc2_unauthorised_software(),
        ]
        .into_iter()
        .chain(service_iso_minimisation())
        .collect(),
        // SSG: service_bluetooth_disabled (NIST AC-18 wireless access + CM-7).
        // Bluetooth is a wireless network interface, so ISO 8.20 (Networks
        // security) applies in addition to minimisation.
        "bluetooth" => [
            service_mapping(ComplianceFramework::NIST, "AC-18", "Wireless Access"),
            // 800-171r3 3.1.16 ← 800-53 AC-18 (SP 800-171r3 source-control table).
            service_nist171_wireless_access(),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AC-18.
            service_fedramp_wireless_access(),
            service_mapping(ComplianceFramework::NIST, "CM-7", "Least Functionality"),
            // 800-171r3 3.4.6 ← 800-53 CM-7 (SP 800-171r3 source-control table).
            service_nist171_least_functionality(),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 CM-7.
            service_fedramp_least_functionality(),
            service_gdpr_hardening(),
            service_iso_networks(),
            service_soc2_unauthorised_software(),
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
    ServiceDirective {
        service_description: "Legacy inetd super-server - obsolete, expands attack surface",
        service_name: "xinetd",
        service_severity: Severity::Medium,
    },
];

/// The unit directory systemd.unit(5) reserves for units created by the
/// administrator, and the only one this plugin's changes reach: `systemctl
/// disable` removes wants/ symlinks here, and `systemctl mask` adds a symlink
/// to /dev/null here.
const ADMIN_UNIT_DIR: &str = "/etc/systemd/system";

/// The unit `systemctl` resolves a bare service name to, and therefore the
/// basename a mask link takes under [`ADMIN_UNIT_DIR`].
///
/// One function rather than the `format!` repeated at each site, because the
/// suffix is a rule about how systemd reads a name, not a detail of any one
/// probe: `list-unit-files` matches patterns literally and needs the suffix
/// spelled out (an unsuffixed pattern matches nothing, which once made every
/// service look absent), and the mask link's basename has to agree with what
/// was probed or the checkpoint would declare a path nothing ever creates.
fn unit_name(service_name: &str) -> String {
    format!("{service_name}.service")
}

/// Paths a `systemctl mask` of each of `directives` would create, one apiece.
///
/// Deliberately derived from a caller-supplied slice rather than from
/// [`UNNECESSARY_SERVICES`] wholesale. A path a plugin declares to its
/// checkpoint and which is absent at capture time is stored with a zero mode,
/// which a rollback reads as "remove this" and acts on unconditionally, and
/// [`ADMIN_UNIT_DIR`] is a legitimate administrator override slot rather than a
/// hardener-owned filename like the drop-ins the kernel and ssh plugins
/// declare. Handing in only the units the host actually has installed keeps a
/// rollback from deleting an override for a service this tool never touched.
///
/// It narrows the window rather than closing it: a unit can be installed, then
/// skipped by a policy exception or by being neither enabled nor active, and
/// its path is declared all the same. Closing that would mean checkpointing
/// after the decision to act, which is after the mask link already exists.
fn mask_link_paths(directives: &[&ServiceDirective]) -> Vec<PathBuf> {
    directives
        .iter()
        .map(|directive| Path::new(ADMIN_UNIT_DIR).join(unit_name(directive.service_name)))
        .collect()
}

/// Unit-file states `systemctl is-enabled` reports success for.
const ENABLED_STATES: &[&str] = &[
    "enabled",
    "enabled-runtime",
    "alias",
    "static",
    "indirect",
    "generated",
    "transient",
];

/// Snapshot of systemd service state built from two `systemctl` listings.
///
/// The scan path used three spawns per assessed service; batching collapses
/// that to two spawns total, which matters most when each spawn is an SSH
/// round-trip. Apply/validate keep the per-service probes; they must observe
/// live state between mutations.
#[derive(Default)]
struct ServiceStates {
    /// `list-unit-files` STATE column, keyed by unit name.
    unit_files: std::collections::HashMap<String, String>,
    /// `list-units` ACTIVE column, keyed by unit name.
    active_units: std::collections::HashMap<String, String>,
}

impl ServiceStates {
    /// Loads both listings through the context's executor.
    ///
    /// The assessed unit names are passed as patterns: an unfiltered
    /// `list-unit-files` enumerates every unit file on disk, which measured
    /// two orders of magnitude slower than the pattern-filtered listing.
    async fn load(ctx: &Context) -> Result<Self> {
        let units: Vec<String> = UNNECESSARY_SERVICES
            .iter()
            .map(|directive| unit_name(directive.service_name))
            .collect();

        let mut unit_file_args = vec!["list-unit-files", "--type=service", "--no-legend"];
        unit_file_args.extend(units.iter().map(String::as_str));
        let unit_files = ctx
            .executor()
            .execute_command("systemctl", &unit_file_args)
            .await?;
        // `list-unit-files` exits 1 when none of the named units exist, which
        // is the ordinary answer on a host that simply has none of them
        // installed, and it says so with an empty stderr. A real failure
        // (unknown option, unusable systemd) also exits non-zero but writes to
        // stderr. Verified against systemd on this machine: no match gives
        // exit 1 with empty stderr, a bad option gives exit 1 with a message.
        // Checking `.success()` alone would turn a clean host into an error.
        if !unit_files.success() && !unit_files.stderr.trim().is_empty() {
            return Err(HardeningError::Plugin(format!(
                "systemctl list-unit-files failed with exit {}: {}",
                unit_files.exit_code,
                unit_files.stderr.trim(),
            )));
        }

        let mut unit_args = vec![
            "list-units",
            "--type=service",
            "--all",
            "--no-legend",
            "--plain",
        ];
        unit_args.extend(units.iter().map(String::as_str));
        let loaded_units = ctx
            .executor()
            .execute_command("systemctl", &unit_args)
            .await?;
        // `list-units` returns 0 even when nothing matches, so any non-zero
        // exit here is abnormal rather than an empty result.
        if !loaded_units.success() {
            return Err(HardeningError::Plugin(format!(
                "systemctl list-units failed with exit {}: {}",
                loaded_units.exit_code,
                loaded_units.stderr.trim(),
            )));
        }

        Ok(Self {
            unit_files: parse_unit_column(&unit_files.stdout, 1),
            active_units: parse_unit_column(&loaded_units.stdout, 2),
        })
    }

    fn exists(&self, service_name: &str) -> bool {
        self.unit_files.contains_key(&unit_name(service_name))
    }

    /// Mirrors the exit-code semantics of `systemctl is-enabled`.
    fn enabled(&self, service_name: &str) -> bool {
        self.unit_files
            .get(&unit_name(service_name))
            .is_some_and(|state| ENABLED_STATES.contains(&state.as_str()))
    }

    /// Mirrors the exit-code semantics of `systemctl is-active`.
    fn active(&self, service_name: &str) -> bool {
        self.active_units
            .get(&unit_name(service_name))
            .is_some_and(|state| state == "active" || state == "reloading")
    }
}

/// Parses a whitespace-separated `systemctl` listing into unit → column value.
fn parse_unit_column(stdout: &str, column: usize) -> std::collections::HashMap<String, String> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let unit = fields.next()?;
            let value = fields.nth(column - 1)?;
            Some((unit.to_string(), value.to_string()))
        })
        .collect()
}

/// Checks if a systemd service unit exists on the system.
///
/// The pattern needs the `.service` suffix; `list-unit-files` does not
/// mangle bare names the way `is-enabled`/`is-active` do, so an unsuffixed
/// pattern matches nothing and every service looked absent. See [`unit_name`],
/// which is where that suffix rule is now stated once.
async fn is_service_exists(ctx: &Context, service_name: &str) -> Result<bool> {
    let unit = unit_name(service_name);
    let output = ctx
        .executor()
        .execute_command("systemctl", &["list-unit-files", &unit])
        .await?;

    Ok(output.stdout.contains(&unit))
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

    async fn scan(&self, ctx: &Context, config: &PluginConfig) -> Result<ScanResult> {
        let start = Instant::now();
        let mut findings = Vec::new();

        // A failed listing used to degrade to "no findings", which is the same
        // output a fully compliant host produces: the one case where the tool
        // knows least looked exactly like the case where there is nothing to
        // report. Every service is now reported as unchecked instead, so the
        // compliance report renders ManualReview rather than a silent pass.
        let states = match ServiceStates::load(ctx).await {
            Ok(states) => states,
            Err(e) => {
                warn!("Could not list services: {e}");
                return Ok(ScanResult {
                    scan_duration_us: start.elapsed().as_micros() as u64,
                    scan_error: Some(e.to_string()),
                    scan_findings: vec![],
                    scan_unchecked: unchecked_all_services(&e.to_string()),
                    scan_plugin_id: self.metadata().plugin_id,
                    scan_success: false,
                });
            }
        };

        // Check each service in our list
        for directive in UNNECESSARY_SERVICES {
            // Skip if service doesn't exist on the system
            if !states.exists(directive.service_name) {
                continue;
            }

            let is_enabled = states.enabled(directive.service_name);
            let is_active = states.active(directive.service_name);

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
                    finding_policy_exception: config
                        .has_valid_exception(directive.service_name)
                        .map(|e| e.to_finding_exception()),
                });
            }
        }

        Ok(ScanResult {
            scan_duration_us: start.elapsed().as_micros() as u64,
            scan_error: None,
            scan_findings: findings,
            scan_unchecked: vec![],
            scan_plugin_id: self.metadata().plugin_id,
            scan_success: true,
        })
    }

    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> {
        let mut changes = Vec::new();

        // Asked once, up front, rather than inside the processing loop below,
        // because the checkpoint has to name the mask link of every unit this
        // apply might mask and the checkpoint is taken before any of them
        // exists. The loop then walks this narrowed list, so the number of
        // `systemctl list-unit-files` spawns is exactly what it always was.
        let mut installed = Vec::new();
        for directive in UNNECESSARY_SERVICES {
            if is_service_exists(ctx, directive.service_name)
                .await
                .unwrap_or(false)
            {
                installed.push(directive);
            }
        }

        // Checkpoint where this plugin's changes actually land. `systemctl
        // disable` removes wants/ symlinks here and `systemctl mask` adds a
        // symlink to /dev/null here; neither touches the package-owned
        // /usr/lib/systemd/system, which systemd.unit(5) reserves for units
        // installed by the distribution.
        //
        // That directory used to be captured too. It holds 700+ unit files on a
        // normal host, none of which this plugin can change, and because it sits
        // outside the rollback allowlist its presence made rollback abort in
        // Phase 1 before restoring anything at all.
        //
        // The directory alone was not enough. Capturing it emits a row for the
        // directory and one per child that is there at capture time, and a mask
        // link is by definition not there yet, so nothing carried it and the
        // rollback, which walks only the rows the checkpoint holds, had no way
        // to remove it: `systemctl mask` was simply not undoable. Naming each
        // link explicitly is the convention the kernel and ssh plugins already
        // follow for the files their applies create, and it costs a second row
        // for any of these paths that does happen to exist already, since the
        // recursion captures it too. `file_states` carries no uniqueness
        // constraint and a restore is idempotent, so that is waste, not
        // breakage. One narrower change in behaviour comes with it: an
        // explicitly declared path is captured under the strict content policy
        // where a recursed child is captured best-effort, so an existing but
        // unreadable override at one of these paths now aborts the capture
        // instead of being tolerated. That is the same bargain every declared
        // path already makes, and the reasoning is in `ContentPolicy`: a
        // checkpoint holding no content for a path offers no recovery for it.
        let mask_links = mask_link_paths(&installed);
        let mut service_paths: Vec<&Path> = vec![Path::new(ADMIN_UNIT_DIR)];
        service_paths.extend(mask_links.iter().map(PathBuf::as_path));
        // Name follows the `{plugin_id}-pre-apply` convention so `hardener batch
        // rollback` (which derives the name from the plugin id) can select it.
        let checkpoint_id = crate::create_checkpoint_for_apply(
            ctx,
            "service-minimisation-pre-apply",
            &service_paths,
        )
        .await?;

        changes.extend(crate::checkpoint_change(&checkpoint_id));

        // Process each service
        for directive in installed {
            // Check for a valid exception: skip this service if exempted
            if let Some(exception) = config.has_valid_exception(directive.service_name) {
                info!(
                    "Skipping {} (exception: {})",
                    directive.service_name, exception.reason
                );
                changes.push(Change {
                    change_description: format!(
                        "{}: skipped (exception: {})",
                        directive.service_name, exception.reason
                    ),
                    change_type: ChangeType::Skipped,
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
        // Excepted settings are recorded rather than dropped: a preview that
        // omits them shows a documented deviation as nothing at all.
        let mut exceptions: Vec<String> = Vec::new();
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
                    // A service left running because it is excepted is
                    // recorded, not dropped: a preview that omits it reports a
                    // documented deviation as nothing at all.
                    if let Some(exception) = config.has_valid_exception(directive.service_name) {
                        exceptions.push(hardener_common::types::exception_preview_line(
                            directive.service_name,
                            &exception.value,
                            &exception.reason,
                        ));
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
            validation_report_compliant_count: 0,
            validation_report_exceptions: exceptions,
            validation_report_is_valid: issues.is_empty(),
            validation_report_issues: issues,
            validation_report_plugin_id: self.metadata().plugin_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mask link's path is the administrator unit directory plus the unit
    /// name, and it is derived for the units handed in and no others.
    ///
    /// The narrowing is the load-bearing half. A declared path that is absent
    /// when the checkpoint is taken is deleted on rollback without further
    /// question, and `/etc/systemd/system` is also where an administrator's own
    /// unit overrides live, so deriving a path for a unit this host never had
    /// would put an unrelated override on the rollback's removal list. Kept
    /// pure and tested here rather than through the apply, because the probe
    /// that decides which units are installed is I/O and would prove nothing
    /// about the derivation itself.
    #[test]
    fn a_mask_link_path_is_derived_for_the_handed_in_units_only() {
        let bluetooth = UNNECESSARY_SERVICES
            .iter()
            .find(|directive| directive.service_name == "bluetooth")
            .expect("bluetooth is one of the assessed directives");

        assert_eq!(
            mask_link_paths(&[bluetooth]),
            vec![PathBuf::from("/etc/systemd/system/bluetooth.service")],
            "the mask link takes the unit name, suffix included, under the admin unit directory"
        );
        assert!(
            mask_link_paths(&[]).is_empty(),
            "a host with none of these units installed declares no override slot at all"
        );
    }

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
    /// "TM-SH". HIPAA is intentionally absent: no service maps cleanly to a
    /// HIPAA Security Rule specification.
    #[test]
    fn xinetd_is_in_the_coverage_set() {
        assert!(
            coverage()
                .iter()
                .any(|m| m.compliance_framework == ComplianceFramework::CIS
                    && m.compliance_control_id == "2.1.1"),
            "xinetd (CIS 2.1.1) must be in the assessed coverage set"
        );
    }

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

    /// Confirms every mapped daemon carries the SOC 2 unauthorised-software
    /// criterion CC6.8, filed under its Trust Services Criteria series.
    #[test]
    fn services_map_soc2_unauthorised_software() {
        for service in ["xinetd", "avahi-daemon", "cups", "bluetooth"] {
            let soc2 = get_service_compliance_mappings(service)
                .into_iter()
                .find(|m| m.compliance_framework == ComplianceFramework::SOC2)
                .unwrap_or_else(|| panic!("{service} must carry a SOC 2 mapping"));
            assert_eq!(soc2.compliance_control_id, "CC6.8");
            assert_eq!(
                soc2.compliance_section.as_deref(),
                Some("Logical and Physical Access Controls")
            );
        }
    }

    /// Confirms the 800-171r3 crosswalk: every mapped daemon translates CM-7
    /// to 3.4.6, and Bluetooth additionally translates AC-18 to 3.1.16.
    #[test]
    fn services_map_nist_800_171_requirements() {
        for service in ["xinetd", "avahi-daemon", "cups", "bluetooth"] {
            let ids: Vec<_> = get_service_compliance_mappings(service)
                .into_iter()
                .filter(|m| m.compliance_framework == ComplianceFramework::NIST800171)
                .map(|m| m.compliance_control_id)
                .collect();
            assert!(
                ids.contains(&"3.4.6".to_string()),
                "{service} must carry 800-171 3.4.6"
            );
            assert_eq!(
                ids.contains(&"3.1.16".to_string()),
                service == "bluetooth",
                "only bluetooth carries the wireless-access requirement"
            );
        }
    }

    /// Confirms the FedRAMP derivation: CM-7 and AC-18 are both GSA rev5
    /// Moderate baseline members, so every mapped daemon mirrors CM-7 and
    /// Bluetooth additionally mirrors AC-18, verbatim from the 800-53 entries.
    #[test]
    fn services_map_fedramp_moderate_controls() {
        for service in ["xinetd", "avahi-daemon", "cups", "bluetooth"] {
            let ids: Vec<_> = get_service_compliance_mappings(service)
                .into_iter()
                .filter(|m| m.compliance_framework == ComplianceFramework::FedRAMP)
                .map(|m| m.compliance_control_id)
                .collect();
            assert!(
                ids.contains(&"CM-7".to_string()),
                "{service} must carry FedRAMP CM-7"
            );
            assert_eq!(
                ids.contains(&"AC-18".to_string()),
                service == "bluetooth",
                "only bluetooth carries the wireless-access control"
            );
        }
    }
}
