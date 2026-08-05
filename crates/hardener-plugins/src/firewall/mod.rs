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
    ApplyResult, Change, ChangeType, PluginConfig, ValidationReport,
    context::Context,
    plugin::{
        Finding, HardeningPlugin, PluginMetadata, ScanResult, UncheckedBlocker, UncheckedCheck,
    },
};
use std::cmp::Ordering;
use std::path::Path;
use std::time::Instant;
use tracing::{info, warn};

/// Represents a single firewall rule in a backend-agnostic format.
#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    /// Rule description for logging and display.
    pub rule_description: String,
    /// Protocol (tcp, udp, icmp, all).
    pub rule_protocol: String,
    /// Port or port range (e.g. "22", "80-443", "any").
    ///
    /// **The dash is the canonical range separator**, and it is what
    /// `validate_firewall_value` accepts, so a range spelled any other way
    /// never reaches a backend through a config. nftables and firewalld take
    /// this form as it stands; ufw wants a colon and gets one from
    /// `ufw::ufw_port_syntax`. This doc comment said `"80:443"` until #85, an
    /// example its own validator refuses.
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

    /// Re-reads the backend's own configuration files from disk.
    ///
    /// Deliberately separate from [`Self::enable`], and the separation is the
    /// point. `enable` decides whether the firewall runs and whether it runs
    /// at the next boot; `reload` decides nothing, it only makes the running
    /// backend read the files it is configured from. A rollback needs the
    /// second and must never perform the first: restoring the configuration a
    /// host had before an apply, and then starting a firewall that host never
    /// ran, hardens a system during an undo.
    ///
    /// A backend that will not reload returns an error carrying its own
    /// stderr, so the caller can tell an operator that the files came back but
    /// the running firewall is still the one the apply installed.
    async fn reload(&self, ctx: &Context) -> Result<()>;

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

/// Whether an `action` override may replace `baseline`.
///
/// The one direction with an unambiguous answer, and the reason this exists:
/// `accept` admits traffic that `drop` and `reject` refuse, so a blocking rule
/// becoming an accepting one is a weakening whatever else changes. `drop` and
/// `reject` both block, so swapping one for the other is neither a loosening
/// nor a tightening and is left to the operator, and tightening an accepting
/// rule into a blocking one is exactly what an override is for.
///
/// Fail-closed on anything else. `hardener-core`'s config validation already
/// refuses an action outside these three, so an unrecognised value cannot
/// arrive through a validated config, and a value that reached here anyway is
/// not a tightening this function can vouch for.
fn action_override_is_allowed(baseline: &str, requested: &str) -> bool {
    match requested {
        "drop" | "reject" => true,
        "accept" => !matches!(baseline, "drop" | "reject"),
        _ => false,
    }
}

/// How much traffic one field value matches, which is the only question the
/// field clamp asks of it.
///
/// Deliberately **not** containment. Two ranges of the same width compare
/// `Equal` here even where they cover different addresses, so `127.0.0.1/8`
/// becoming `10.0.0.0/8` is admitted. That ceiling is #64's, decided rather
/// than overlooked: closing it needs CIDR containment across both address
/// families, and this plugin does not own an address comparator.
#[derive(PartialEq)]
enum FieldBreadth {
    /// Everything the field can express, however it was spelled: `any`, `all`,
    /// and any prefix of length zero in either family.
    Everything,
    /// A share of one address family's space, as a prefix length. Fewer bits
    /// is a broader match, so the ordering runs backwards from the number.
    Addresses { ipv6: bool, prefix_bits: u8 },
    /// A count of ports, which is what makes `1-65535` a widening of `22` and
    /// `2222` not one.
    Ports(u32),
    /// One named protocol. Every named protocol is the same width as any
    /// other, so `tcp` becoming `udp` moves rather than widens.
    OneProtocol,
}

/// Reads a field value as a breadth, or `None` where it cannot be read as one.
///
/// `None` is a refusal, never a default: a value this cannot measure is not a
/// tightening it can vouch for. The address itself is not validated, only its
/// prefix, because what a malformed address does is the backend's answer to
/// give and this function's question is width alone.
fn field_breadth(field: &str, value: &str) -> Option<FieldBreadth> {
    match field {
        "source" => {
            if value == "any" {
                return Some(FieldBreadth::Everything);
            }
            let ipv6 = value.contains(':');
            let family_bits = if ipv6 { 128 } else { 32 };
            let (address, prefix_bits) = match value.split_once('/') {
                Some((address, bits)) => (address, bits.parse::<u8>().ok()?),
                None => (value, family_bits),
            };
            if address.is_empty() || prefix_bits > family_bits {
                return None;
            }
            // A prefix of zero is the whole family, and the whole of either
            // family is the whole of what an accepting rule can admit. Ordered
            // as Everything rather than as a 0-bit prefix so that it compares
            // against `any` and across families instead of being refused as
            // incomparable with them.
            match prefix_bits {
                0 => Some(FieldBreadth::Everything),
                _ => Some(FieldBreadth::Addresses { ipv6, prefix_bits }),
            }
        }
        "protocol" => match value {
            // The baseline says `all` and the configuration layer accepts
            // `any`. Both name every protocol, so both are the same breadth.
            "any" | "all" => Some(FieldBreadth::Everything),
            "tcp" | "udp" => Some(FieldBreadth::OneProtocol),
            _ => None,
        },
        "port" => {
            if value == "any" {
                return Some(FieldBreadth::Everything);
            }
            let (low, high) = match value.split_once('-') {
                Some((low, high)) => (low.parse::<u16>().ok()?, high.parse::<u16>().ok()?),
                None => {
                    let single = value.parse::<u16>().ok()?;
                    (single, single)
                }
            };
            match high < low {
                true => None,
                false => Some(FieldBreadth::Ports(u32::from(high) - u32::from(low) + 1)),
            }
        }
        _ => None,
    }
}

/// How `requested` compares in breadth to `baseline`, or `None` where the two
/// cannot be compared at all.
///
/// Two address ranges in different families have no shared space to be measured
/// in, so they are incomparable rather than equal, and a caller reading `None`
/// refuses.
fn breadth_order(baseline: &FieldBreadth, requested: &FieldBreadth) -> Option<Ordering> {
    match (baseline, requested) {
        (FieldBreadth::Everything, FieldBreadth::Everything) => Some(Ordering::Equal),
        (FieldBreadth::Everything, _) => Some(Ordering::Less),
        (_, FieldBreadth::Everything) => Some(Ordering::Greater),
        (
            FieldBreadth::Addresses {
                ipv6: baseline_ipv6,
                prefix_bits: baseline_bits,
            },
            FieldBreadth::Addresses {
                ipv6: requested_ipv6,
                prefix_bits: requested_bits,
            },
        ) => match baseline_ipv6 == requested_ipv6 {
            // Fewer bits is a broader match, so the comparison runs the other
            // way round from the numbers.
            true => Some(baseline_bits.cmp(requested_bits)),
            false => None,
        },
        (FieldBreadth::Ports(baseline_ports), FieldBreadth::Ports(requested_ports)) => {
            Some(requested_ports.cmp(baseline_ports))
        }
        (FieldBreadth::OneProtocol, FieldBreadth::OneProtocol) => Some(Ordering::Equal),
        _ => None,
    }
}

/// Whether a `source`, `protocol` or `port` override may replace the baseline
/// on a rule carrying `action`.
///
/// The direction is the rule's, not the field's, and it is why #64 could not be
/// answered by clamping each field the way `action` is clamped. An **accepting**
/// rule admits what it matches, so it weakens as it matches MORE. A **blocking**
/// rule refuses what it matches, so it weakens as it matches LESS: narrowing the
/// catch-all drop to one subnet stops everything outside that subnet being
/// dropped at all, which is the sharpest of the four cases and the one an
/// operator is least likely to read as a loosening.
///
/// Equal breadth is admitted in both directions. That is what keeps
/// `ssh.port = 2222`, the configuration reference's own worked example, working,
/// and it is the same decision as the ceiling stated on [`FieldBreadth`].
///
/// Fail-closed on anything else, including an action this cannot reason about.
fn field_override_is_allowed(action: &str, field: &str, baseline: &str, requested: &str) -> bool {
    if baseline == requested {
        return true;
    }
    let (Some(baseline_breadth), Some(requested_breadth)) = (
        field_breadth(field, baseline),
        field_breadth(field, requested),
    ) else {
        return false;
    };
    let Some(order) = breadth_order(&baseline_breadth, &requested_breadth) else {
        return false;
    };
    match action {
        "drop" | "reject" => order != Ordering::Less,
        "accept" => order != Ordering::Greater,
        _ => false,
    }
}

/// Applies directive overrides to a single firewall rule.
///
/// Directives use `<rule_id>.<field>` keys:
/// - `ssh.port` = "2222"
/// - `ssh.source` = "10.0.0.0/8"
///
/// **All four fields are clamped**, `action` against the direction that holds
/// for any rule and the other three against the direction the rule's own action
/// gives them. See [`field_override_is_allowed`] for why those three could not
/// be clamped the way `action` is, and [`FieldBreadth`] for the one thing this
/// still admits: a value of the same width as the baseline but covering a
/// different range.
///
/// **`action` is applied first, and the order is load-bearing.** The other
/// three are judged against the action the rule ends up carrying, so an
/// operator tightening the SSH rule into a blocking one may widen its port in
/// the same config: on a blocking rule that is a tightening. Judged against the
/// accepting baseline it would have been refused, and the operator would have
/// been talked out of a stricter ruleset.
fn apply_rule_directives(rule: &mut Rule, id: &str, config: &PluginConfig) {
    match config.directives.get(&format!("{id}.action")) {
        Some(action) if action_override_is_allowed(&rule.rule_action, action) => {
            rule.rule_action = action.clone();
        }
        Some(action) => warn!(
            "Ignoring firewall directive '{id}.action = {action}': it would weaken \
             the '{}' rule from '{}'. Record a deliberate deviation as a policy \
             exception instead.",
            rule.rule_description, rule.rule_action
        ),
        None => {}
    }

    // One loop rather than three near-identical blocks, and the field name is
    // needed anyway: it is both half the directive key and what tells
    // `field_breadth` which value space it is reading.
    for (field, current) in [
        ("port", &mut rule.rule_port),
        ("source", &mut rule.rule_source),
        ("protocol", &mut rule.rule_protocol),
    ] {
        let Some(requested) = config.directives.get(&format!("{id}.{field}")) else {
            continue;
        };
        match field_override_is_allowed(&rule.rule_action, field, current, requested) {
            true => *current = requested.clone(),
            false => warn!(
                "Ignoring firewall directive '{id}.{field} = {requested}': on a \
                 '{}' rule it would weaken the '{}' rule from '{current}'. Record \
                 a deliberate deviation as a policy exception instead.",
                rule.rule_action, rule.rule_description
            ),
        }
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

/// The words `systemctl is-enabled` uses for a unit that will definitely not
/// be started at the next boot.
///
/// Judged by the word and never by the exit status, because the two disagree
/// by design: `enabled-runtime` and `static` both exit 0 while neither
/// survives a reboot, and `disabled` exits non-zero although `systemctl
/// enable` repairs it in one command. [`systemd_unit_active`] above can read
/// exit codes because `is-active` asks a question with one meaning; this one
/// does not.
///
/// `enabled-runtime` is on the list because it is enablement made in
/// `/run/systemd/system`, which the next boot discards. That is the very
/// failure this probe exists to catch, so reading its "enabled" prefix as
/// enabled would reintroduce the defect through the probe. `linked` units are
/// not enabled either, and `masked` ones cannot be started at all.
/// The exception key naming a host an operator has approved to run with no
/// firewall enforcing at all.
///
/// Named for the subsystem state rather than for a rule or for the finding's
/// own id, the way `[mac]` keys `selinux-enforcing`. `rule_id` covers the
/// baseline rules and none of its keys can say "there is no firewall": a rule
/// never applied is a different statement from a firewall never enabled. The
/// finding id would key it too, but the id carries the detected backend, so an
/// exception written on a ufw host would stop matching on a firewalld one, and
/// an approved deviation that silently stops being honoured is the defect this
/// key exists to close.
const FIREWALL_ENABLED_EXCEPTION: &str = "firewall-enabled";

/// The exception key for a firewall that enforces now and is gone after a
/// reboot. Kept apart from [`FIREWALL_ENABLED_EXCEPTION`] because accepting a
/// host with no firewall is a different decision from accepting one whose
/// firewall does not survive a restart, and an operator who approved the
/// second has not thereby approved the first.
const FIREWALL_AT_BOOT_EXCEPTION: &str = "firewall-at-boot";

const NOT_AT_BOOT_STATES: [&str; 6] = [
    "disabled",
    "enabled-runtime",
    "linked",
    "linked-runtime",
    "masked",
    "masked-runtime",
];

/// Whether a unit is started at boot, which is a different question from
/// whether it is running now and therefore needs a different answer.
///
/// Deliberately not folded into `FirewallBackend::is_enabled`, which means
/// "running now" in all three backends. "Not running" and "running but gone
/// after a reboot" are different states needing different words to the
/// operator, and one boolean standing for both is how an Arch host came to be
/// reported as having a firewall it was about to lose.
enum BootPersistence {
    /// `enabled`: a permanent `.wants/` or `.requires/` symlink under
    /// `/etc/systemd/system`, so the unit is started at boot.
    AtBoot,
    /// systemd answered with one of [`NOT_AT_BOOT_STATES`]. The word is
    /// carried so the operator is told which of the several ways of not
    /// starting at boot this host is in: a masked unit has to be unmasked
    /// before enabling it can work at all.
    NotAtBoot(String),
    /// The question was not answered. `systemctl` absent or erroring, an empty
    /// answer, and the states with no `[Install]` section (`static`,
    /// `indirect`, `generated`, `alias`, `transient`) all land here: those
    /// cannot be enabled, yet another unit may still pull them in, so neither
    /// "enabled" nor "not enabled" is true of them. Never a pass.
    ///
    /// `not-found` lands here too (systemd 261 prints it on stdout, exiting
    /// 4). A backend confirmed to be enforcing without the unit this project
    /// names for it is being started by something else, and this probe cannot
    /// say what that something does at boot.
    Undeterminable,
}

/// Asks systemd whether `unit` is started at boot.
///
/// Root-free, like [`systemd_unit_active`]: `is-enabled` reads unit files and
/// symlinks, so an unprivileged scan gets the same answer a privileged one
/// does. One free function rather than a trait method, because every backend
/// already states its unit through [`FirewallBackend::systemd_unit`] and none
/// of them would answer this differently.
async fn unit_boot_persistence(ctx: &Context, unit: &str) -> BootPersistence {
    let Ok(output) = ctx
        .executor()
        .execute_command("systemctl", &["is-enabled", unit])
        .await
    else {
        return BootPersistence::Undeterminable;
    };

    // systemd prints the state on its own line. An empty answer, which is what
    // a unit systemd cannot find gives, is not an answer this can read.
    match output.stdout.trim() {
        "enabled" => BootPersistence::AtBoot,
        state if NOT_AT_BOOT_STATES.contains(&state) => {
            BootPersistence::NotAtBoot(state.to_string())
        }
        _ => BootPersistence::Undeterminable,
    }
}

/// The stable id shared by the finding and by the unchecked entry that stands
/// in for it, kept apart from the `{backend}-disabled` id those two already
/// use: a firewall that is running is not disabled, and saying so would be
/// false about the host in front of the operator.
fn not_at_boot_id(backend: &dyn FirewallBackend) -> String {
    format!("{}-not-enabled-at-boot", backend.backend_name())
}

/// How the operator is told which way the unit fails to start at boot, and
/// what to do about it. Returns the clause naming the state and the steps that
/// repair it.
///
/// Split by state because the states are not interchangeable: systemd refuses
/// to start a masked unit at all, so unmasking has to come before enabling,
/// and a runtime-only enablement reads as enabled right up until the reboot
/// that discards it.
fn boot_state_wording(unit: &str, state: &str) -> (String, Vec<String>) {
    match state {
        "masked" | "masked-runtime" => (
            format!("the {unit} unit is masked ({state}), so systemd refuses to start it at all"),
            vec![
                format!("Run `systemctl unmask {unit}`"),
                format!("Run `systemctl enable {unit}`"),
            ],
        ),
        "enabled-runtime" => (
            format!(
                "the {unit} unit is enabled for this boot only ({state}), an enablement \
                 held in /run and discarded at the next boot"
            ),
            vec![format!(
                "Run `systemctl enable {unit}` to make the enablement permanent"
            )],
        ),
        other => (
            format!("the {unit} unit reads {other}, so nothing starts it at boot"),
            vec![format!("Run `systemctl enable {unit}`")],
        ),
    }
}

/// The finding raised for a firewall that is enforcing now and will not be
/// after a reboot.
fn not_at_boot_finding(
    backend: &dyn FirewallBackend,
    state: &str,
    config: &PluginConfig,
) -> Finding {
    let (clause, steps) = boot_state_wording(backend.systemd_unit(), state);
    Finding {
        finding_category: FindingCategory::Network,
        finding_current_value: state.to_string(),
        finding_description: format!(
            "The {} firewall is active now, but {clause}, so this host has no firewall \
             after a reboot",
            backend.backend_name()
        ),
        finding_explanation:
            "A firewall that is not started at boot protects the host only until it is \
             next restarted"
                .to_string(),
        finding_id: not_at_boot_id(backend),
        finding_impact: "System exposed to network attacks from the next reboot onwards"
            .to_string(),
        finding_recommended_value: "enabled".to_string(),
        finding_remediation_steps: steps,
        finding_severity: Severity::High,
        finding_title: "Firewall does not start at boot".to_string(),
        finding_compliance: get_firewall_compliance_mappings(),
        finding_policy_exception: config
            .has_valid_exception(FIREWALL_AT_BOOT_EXCEPTION)
            .map(|exception| exception.to_finding_exception()),
    }
}

/// The unchecked entry that stands in for [`not_at_boot_finding`] when systemd
/// gave no answer this scan can read. An unanswered question is reported as
/// unanswered, never as a pass.
fn not_at_boot_unchecked(backend: &dyn FirewallBackend) -> UncheckedCheck {
    UncheckedCheck {
        unchecked_check_id: not_at_boot_id(backend),
        unchecked_title: "Firewall starts at boot".to_string(),
        unchecked_category: FindingCategory::Network,
        unchecked_reason: format!(
            "`systemctl is-enabled {}` gave no answer this scan can read",
            backend.systemd_unit()
        ),
        // `is-enabled` needs no privilege, so a run with sudo would read
        // exactly the same thing and offering one would be a false promise.
        unchecked_blocker: UncheckedBlocker::Environment,
        unchecked_compliance: get_firewall_compliance_mappings(),
    }
}

/// Asks systemd to want `backend`'s unit at boot, and reports what that took.
///
/// A unit already wanted at boot is recorded as a skipped no-op rather than as
/// work done, which is what `docs/development/plugin-authoring.md` and
/// `docs/reference/cli.md` promise of a setting already at its target.
///
/// An undeterminable answer runs the enable anyway: `systemctl enable` is
/// idempotent, and doing the work is the safe direction when the state cannot
/// be read, the same fallback the ufw and firewalld backends already take for
/// the policy and the zone target they cannot read. A run that then fails is
/// recorded as a failed change carrying systemd's own words, rather than a
/// host quietly left to lose its firewall.
///
/// This enable writes a `.wants` symlink under `/etc/systemd/system`, and this
/// plugin's pre-apply checkpoint deliberately does not declare it, so a
/// rollback leaves the firewall wanted at boot. That is the decision rather
/// than an oversight, and it is written here because the question reaches this
/// site by a route that makes it look like one: sweeping the tree for "which
/// apply creates a path its own checkpoint does not declare" found two genuine
/// defects elsewhere, the `systemctl mask` link and the audit rules file, and
/// then found this, which is not one.
///
/// Undoing it would mean removing the symlink, which is to say disabling the
/// firewall at boot, on a host where the operator asked only to undo a
/// hardening run. That contradicts the settled rule that a hardening run never
/// leaves a host less secure than it found it, and it would sit oddly beside
/// this plugin's own `reload_after_rollback`, which re-reads the restored
/// configuration files and does not touch whether the unit starts or is
/// enabled at boot, in either direction. A rollback that left the running
/// firewall exactly as it found it while quietly disabling what starts it at
/// the next boot would be incoherent in a way no operator could be expected to
/// predict.
///
/// The decision is intended, and nothing about it turns on which command the
/// reload issues: `reload_after_rollback` never starts or enables a unit
/// either, so this symlink surviving a rollback is not an asymmetry it grants
/// on request, it is simply outside every action a rollback takes.
async fn ensure_unit_wanted_at_boot(ctx: &Context, backend: &dyn FirewallBackend) -> Change {
    let unit = backend.systemd_unit();
    if matches!(
        unit_boot_persistence(ctx, unit).await,
        BootPersistence::AtBoot
    ) {
        return Change {
            change_description: format!(
                "The {unit} unit was already enabled to start the firewall at boot"
            ),
            change_type: ChangeType::Skipped,
            change_success: true,
            change_error: None,
        };
    }

    let outcome = ctx
        .executor()
        .execute_command("systemctl", &["enable", unit])
        .await;
    let failure = match &outcome {
        Ok(output) if output.success() => None,
        Ok(output) => Some(output.stderr.trim().to_string()),
        Err(e) => Some(e.to_string()),
    };
    match failure {
        None => Change {
            change_description: format!("Enabled the {unit} unit to start the firewall at boot"),
            // A service state change rather than a rule, matching the enable
            // this stands beside.
            change_type: ChangeType::Service,
            change_success: true,
            change_error: None,
        },
        Some(reason) => Change {
            change_description: format!(
                "Failed to enable the {unit} unit to start the firewall at boot"
            ),
            change_type: ChangeType::Service,
            change_success: false,
            change_error: Some(reason),
        },
    }
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

    async fn scan(&self, ctx: &Context, config: &PluginConfig) -> Result<ScanResult> {
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
        let winner = find_winner(&classified).map(|index| &classified[index]);
        let blocked = match winner {
            Some((_, BackendActivity::Verified)) => None,
            Some((backend, _)) => Some(backend),
            None => classified
                .iter()
                .find(|(_, activity)| matches!(activity, BackendActivity::Unknown))
                .map(|(backend, _)| backend),
        };

        if let Some(backend) = blocked {
            let blocker = crate::refusal_blocker(ctx).await;
            unchecked.push(UncheckedCheck {
                unchecked_check_id: format!("{}-disabled", backend.backend_name()),
                unchecked_title: "Active firewall ruleset".to_string(),
                unchecked_category: FindingCategory::Network,
                unchecked_reason: format!(
                    "verifying the active {} ruleset requires root",
                    backend.backend_name()
                ),
                unchecked_blocker: blocker,
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
                finding_policy_exception: config
                    .has_valid_exception(FIREWALL_ENABLED_EXCEPTION)
                    .map(|exception| exception.to_finding_exception()),
            });
        }

        // A firewall enforcing now is not a firewall that comes back after a
        // reboot, and nothing above asks the second question: every backend's
        // `is_enabled` means "running now". Asked only of a verified-active
        // winner, because that is the one host state where the answer stands
        // on its own. A backend nothing could confirm as running already has
        // its unchecked entry, and one confirmed inactive is the disabled
        // finding's business rather than this one's.
        if let Some((backend, BackendActivity::Verified)) = winner {
            match unit_boot_persistence(ctx, backend.systemd_unit()).await {
                BootPersistence::AtBoot => {}
                BootPersistence::NotAtBoot(state) => {
                    findings.push(not_at_boot_finding(backend.as_ref(), &state, config));
                }
                BootPersistence::Undeterminable => {
                    unchecked.push(not_at_boot_unchecked(backend.as_ref()));
                }
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
            Path::new(nftables::NFTABLES_CONFIG_PATH),
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

        // Enable firewall if not already enabled. The outcome is held here and
        // recorded below, once `apply_changes` exists, rather than moving the
        // enable itself further down: this is a side effect the rules that
        // follow depend on, so its position must not change.
        // The failure is held rather than propagated for the same reason the
        // enable itself is held: `apply_changes` does not exist yet, and a `?`
        // here returned before it ever did, so a firewall that refused to start
        // left no result document at all. Every other plugin records the failed
        // change and returns its result; audit's `systemctl enable auditd` is
        // the closest match and pushes a failed `Change` in its `_` arm.
        let was_already_enabled = backend.is_enabled(ctx).await.is_ok();
        let enable_error = match was_already_enabled {
            true => None,
            false => backend.enable(ctx).await.err(),
        };

        // Build rule set with config filtering and directive overrides.
        let baseline_rules = backend.get_default_rules();
        let mut rules = Vec::with_capacity(baseline_rules.len());
        let mut apply_changes = Vec::new();

        apply_changes.extend(crate::checkpoint_change(&checkpoint_id));

        // Turning the firewall on is the most consequential thing this apply
        // can do, taking a host from no firewall to a firewall, and it used to
        // appear only in the log. The change list is the record apply leaves
        // behind, so an operator reading "N change(s) applied" was told about
        // the rules and not about the enable that made them mean anything.
        apply_changes.push(match (was_already_enabled, &enable_error) {
            (true, _) => Change {
                change_description: format!(
                    "The {} firewall was already enabled",
                    backend.backend_name()
                ),
                change_type: ChangeType::Skipped,
                change_success: true,
                change_error: None,
            },
            (false, None) => Change {
                change_description: format!("Enabled the {} firewall", backend.backend_name()),
                // A service state change rather than a rule: ufw's enable runs
                // `ufw --force enable` and firewalld's runs `systemctl start`
                // plus `systemctl enable`, which is what this variant is for.
                // Nothing counts it differently, but a renderer grouping by
                // type would otherwise file it under firewall rules, which it
                // is not.
                change_type: ChangeType::Service,
                change_success: true,
                change_error: None,
            },
            (false, Some(error)) => Change {
                change_description: format!(
                    "Failed to enable the {} firewall",
                    backend.backend_name()
                ),
                change_type: ChangeType::Service,
                change_success: false,
                // The backend's own words, not a summary. ufw, firewalld and
                // nftables each fail for reasons the operator has to act on.
                change_error: Some(error.to_string()),
            },
        });

        // The rules below genuinely depend on the firewall being up, so this
        // returns rather than attempting them.
        //
        // The result stops here rather than continuing with one recorded
        // failure per unattempted rule. That was the other honest option and it
        // reports one cause several times: the rules were not refused
        // individually, they were never reached, and a list of five failures
        // says the opposite of what happened. `restore_file_state` in
        // `hardener-state` makes the same call where a directory it could not
        // create is followed by a chmod that could only fail for the same
        // reason, and says so at the site.
        if let Some(error) = enable_error {
            return Ok(ApplyResult {
                apply_plugin_id,
                apply_success: false,
                apply_changes,
                apply_checkpoint_id: checkpoint_id,
                apply_error: Some(format!(
                    "The {} firewall could not be enabled, so no rule was applied: {error}",
                    backend.backend_name()
                )),
            });
        }

        // The other half of "enabled", which the enable above cannot reach on
        // this host: it is skipped entirely when the firewall is already
        // running, so a host running a firewall whose unit is not wanted at
        // boot was never repaired however often the tool was run.
        //
        // Where the enable did run it is skipped instead, and that is right for
        // two of the three backends and not the third. ufw's `--force enable`
        // and firewalld's `systemctl start` plus `systemctl enable` both leave
        // the unit wanted at boot, so asking again would only repeat them.
        // nftables' `enable` creates the inet filter table and its three chains
        // through `nft` and issues no `systemctl` call at all, so on that
        // backend a fresh enable leaves the unit unenabled and the ruleset only
        // in the kernel. That gap is #52, and closing it is a behaviour change
        // needing container evidence rather than a comment.
        if was_already_enabled {
            let boot_change = ensure_unit_wanted_at_boot(ctx, backend.as_ref()).await;
            apply_changes.push(boot_change);
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

        // The second place this abandoned a half-built result, and the costlier
        // of the two: by here `apply_changes` holds the checkpoint, the enable
        // and every exception the operator declared, and a `?` threw all of it
        // away. Only two backends can reach it, and neither fails per rule:
        // firewalld's `get_default_zone` fails before its per-rule loop runs,
        // and nftables writes and loads its whole ruleset in a single `nft -f`
        // transaction after the loop that only classifies rules as already
        // present or not, so either way this is a whole-backend failure and
        // one recorded change is the right count. ufw cannot reach it at all,
        // since its `apply_rules` records every per-rule failure and returns
        // `Ok`.
        let rules_error = match backend.apply_rules(ctx, &rules).await {
            Ok(mut backend_changes) => {
                apply_changes.append(&mut backend_changes);
                None
            }
            Err(error) => {
                apply_changes.push(Change {
                    change_description: format!(
                        "Failed to apply {} firewall rules",
                        backend.backend_name()
                    ),
                    change_type: ChangeType::FirewallRule,
                    change_success: false,
                    change_error: Some(error.to_string()),
                });
                Some(error.to_string())
            }
        };

        Ok(ApplyResult {
            apply_plugin_id,
            apply_success: apply_changes.iter().all(|c| c.change_success),
            apply_changes,
            apply_checkpoint_id: checkpoint_id,
            apply_error: rules_error,
        })
    }

    fn reloads_for_path(&self, path: &Path) -> bool {
        path == Path::new(nftables::NFTABLES_CONFIG_PATH)
            || path.starts_with("/etc/firewalld")
            || path.starts_with("/etc/ufw")
    }

    async fn reload_after_rollback(&self, ctx: &Context) -> Result<Option<String>> {
        let backend = self.detect_backend(ctx).await?;
        backend.reload(ctx).await?;
        let name = backend.backend_name();
        info!("{name} re-read its restored configuration");
        Ok(Some(format!("{name} configuration reloaded")))
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
                    // Confirmed active: no enable needed, but the boot question
                    // is still open, and apply asks it on exactly this host
                    // state. `ensure_unit_wanted_at_boot` runs only where the
                    // firewall was already enabled, which is this arm, so a
                    // preview that skipped it was one line short of the run it
                    // previews: fedora, rhel and openSUSE all took this arm in
                    // the container runs of 2026-07-30 and each carried a boot
                    // line no dry run had shown.
                    //
                    // Ahead of the rule estimate because apply pushes its boot
                    // change before it walks the baseline, and an operator
                    // comparing a dry run against the run it previews reads the
                    // two lists in order.
                    BackendActivity::Verified => {
                        let unit = winner.systemd_unit();
                        match unit_boot_persistence(ctx, unit).await {
                            // The sentence apply prints, in the tense a preview
                            // uses, so the two halves can be read against each
                            // other line by line.
                            BootPersistence::NotAtBoot(_) => estimated_changes.push(format!(
                                "Enable the {unit} unit to start the firewall at boot"
                            )),
                            // Nothing pending: apply records this as a skipped
                            // no-op, and a preview line standing for a no-op
                            // would be counted as a queued write.
                            BootPersistence::AtBoot => {}
                            // An issue rather than an estimated change, for the
                            // reason the arm below states at length: the length
                            // of the pending list is the change count. Medium
                            // for the same shape of reason, that this is a
                            // limit on what the run could read rather than a
                            // fault of the host, and `scan` reports the same
                            // answer as an unchecked entry rather than as a
                            // finding. Failing the dry run over it would fail
                            // it on every host whose unit has no [Install]
                            // section or whose systemd cannot be asked at all.
                            BootPersistence::Undeterminable => {
                                issues.push(hardener_core::ValidationIssue {
                                    validation_issue_severity: Severity::Medium,
                                    validation_issue_message: format!(
                                        "`systemctl is-enabled {unit}` gave no answer this \
                                         run can read, so whether the firewall starts at \
                                         boot is unknown"
                                    ),
                                    validation_issue_config_key: None,
                                });
                            }
                        }
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
mod tests;
