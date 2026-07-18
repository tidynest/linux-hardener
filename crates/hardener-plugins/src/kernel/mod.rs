//! Kernel hardening plugin for sysctl parameter management.
//!
//! This plugin scans, applies, and manages kernel security parameters via sysctl.
//! It focuses on critical security settings including:
//! - Address Space Layout Randomisation (ASLR)
//! - Kernel pointer restrictions
//! - dmesg access restriction
//! - Core dump restrictions
//!
//! The plugin reads current values, compares against secure baselines,
//! and can apply hardening configurations with automatic rollback support.

use async_trait::async_trait;
use hardener_common::{
    error::Result,
    types::{ComplianceFramework, ComplianceMapping, FindingCategory, PluginId, Severity},
};
use hardener_core::{
    Change, ChangeType, Checkpoint, PluginConfig, ValidationIssue, ValidationReport,
    context::Context,
    plugin::{ApplyResult, Finding, HardeningPlugin, PluginMetadata, ScanResult},
};
use std::{path::Path, time::Instant};
use tracing::{info, warn};

/// Kernel hardening plugin implementing sysctl parameter management.
pub struct KernelHardeningPlugin;

impl Default for KernelHardeningPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelHardeningPlugin {
    /// Creates a new instance of the kernel hardening plugin.
    pub fn new() -> KernelHardeningPlugin {
        Self
    }

    /// Reads a sysctl parameter value from /proc/sys.
    ///
    /// # Arguments
    /// * `param` - Parameter name in dot notation (e.g. "kernel.randomize_va_space")
    /// * `ctx` - Execution context providing the system executor
    ///
    /// # Returns
    /// The parameter values as a string, or an error if reading fails.
    async fn read_sysctl(&self, param: &str, ctx: &Context) -> Result<String> {
        let path = format!("/proc/sys/{}", param.replace('.', "/"));
        let content = ctx.executor().read_file(Path::new(&path)).await?;
        Ok(content.trim().to_string())
    }
}

/// Critical kernel security parameters with their secure values.
///
/// Each tuple contains:
/// - Parameter name in sysctl dot notation
/// - Recommended secure value
/// - Human-readable explanation
const KERNEL_PARAMS: &[(&str, &str, &str, Severity)] = &[
    (
        "kernel.randomize_va_space",
        "2",
        "Enable full address space layout randomisation (ASLR)",
        Severity::High,
    ),
    (
        "kernel.kptr_restrict",
        "2",
        "Hides kernel pointers from all users except root",
        Severity::Medium,
    ),
    (
        "kernel.dmesg_restrict",
        "1",
        "Restricts dmesg access to privileged users only",
        Severity::Medium,
    ),
    (
        "kernel.yama.ptrace_scope",
        "2",
        "Restricts ptrace usage to admin-only",
        Severity::High,
    ),
    (
        "fs.suid_dumpable",
        "0",
        "Prevents setuid processes from creating core dumps",
        Severity::Medium,
    ),
    (
        "fs.protected_hardlinks",
        "1",
        "Prevents hardlink creation to files user doesn't own",
        Severity::Medium,
    ),
    (
        "fs.protected_symlinks",
        "1",
        "Prevents symlink following in sticky world-writable directories",
        Severity::Medium,
    ),
    (
        "net.ipv4.conf.all.rp_filter",
        "1",
        "Enables reverse path filtering (anti-spoofing)",
        Severity::High,
    ),
    (
        "net.ipv4.conf.default.rp_filter",
        "1",
        "Enables reverse path filtering for new interfaces",
        Severity::High,
    ),
    (
        "net.ipv4.tcp_syncookies",
        "1",
        "Enables SYN flood protection",
        Severity::High,
    ),
    (
        "net.ipv4.conf.all.accept_source_route",
        "0",
        "Disables source routing (security risk)",
        Severity::Medium,
    ),
    (
        "net.ipv4.conf.default.accept_source_route",
        "0",
        "Disables source routing for new interfaces",
        Severity::Medium,
    ),
    (
        "net.ipv4.conf.all.accept_redirects",
        "0",
        "Disables acceptance of ICMP redirects (prevents route table poisoning)",
        Severity::Medium,
    ),
    (
        "net.ipv4.conf.default.accept_redirects",
        "0",
        "Disables ICMP redirect acceptance for new interfaces",
        Severity::Medium,
    ),
    (
        "net.ipv4.conf.all.secure_redirects",
        "0",
        "Disables acceptance of secure ICMP redirects",
        Severity::Medium,
    ),
    (
        "net.ipv4.conf.default.secure_redirects",
        "0",
        "Disables secure ICMP redirect acceptance for new interfaces",
        Severity::Medium,
    ),
    (
        "net.ipv4.conf.all.log_martians",
        "1",
        "Logs packets with impossible (martian) source addresses",
        Severity::Low,
    ),
    (
        "net.ipv4.conf.default.log_martians",
        "1",
        "Logs martian packets for new interfaces",
        Severity::Low,
    ),
];

/// Builds a NIST 800-53 Rev 5 mapping. Title/section follow the project's
/// authoritative definitions in `hardener-compliance/src/frameworks/nist.rs`.
fn nist(id: &str, title: &str, section: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: ComplianceFramework::NIST,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some(section.to_string()),
    }
}

/// Builds a DISA STIG mapping. `id` is the RHEL 8 STIG identifier, which shares
/// its numeric tail with the SSG `stigid@ol8` reference cited per check.
fn stig(id: &str, title: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: ComplianceFramework::STIG,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some("DISA STIG".to_string()),
    }
}

/// Builds a PCI-DSS v4.0 mapping. Control id/title/section follow the project's
/// authoritative definitions in `hardener-compliance/src/frameworks/pci.rs`.
fn pcidss(id: &str, title: &str, section: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: ComplianceFramework::PCIDSS,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some(section.to_string()),
    }
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
/// criterion (e.g. `CC6.1`); `title` tracks the published criterion text. The
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
/// number (e.g. `3.4.2`); `title` the published requirement name. The section
/// is the requirement's official family, derived from the id's family number.
/// Every id is translated from this plugin's 800-53 entries via the r3
/// source-control table, never invented.
fn nist171(id: &str, title: &str) -> ComplianceMapping {
    let family = match id.split('.').nth(1) {
        Some("1") => "Access Control",
        Some("4") => "Configuration Management",
        Some("13") => "System and Communications Protection",
        _ => "System and Information Integrity",
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
    let family = match id.split('-').next() {
        Some("AC") => "Access Control",
        Some("CM") => "Configuration Management",
        Some("SC") => "System and Communications Protection",
        _ => "System and Information Integrity",
    };
    ComplianceMapping {
        compliance_framework: ComplianceFramework::FedRAMP,
        compliance_control_id: id.to_string(),
        compliance_control_title: title.to_string(),
        compliance_section: Some(family.to_string()),
    }
}

/// Returns compliance mappings for a given kernel parameter.
///
/// CIS entries are the project's existing benchmark mappings. STIG/NIST/PCI-DSS
/// entries are sourced from the matching ComplianceAsCode/SSG rule's
/// `references:` block (rule id cited per check). NIST titles/sections and
/// PCI-DSS v4.0 ids/titles are reconciled with the project's own framework
/// definitions in `hardener-compliance/src/frameworks/`. A framework is omitted
/// for a check only when the SSG rule carries no reference for it.
/// Every compliance mapping this plugin can emit, across all kernel parameters
/// it assesses. Aggregated into the engine's automated-coverage set.
pub fn coverage() -> Vec<ComplianceMapping> {
    KERNEL_PARAMS
        .iter()
        .flat_map(|p| get_compliance_mappings(p.0))
        .collect()
}

fn get_compliance_mappings(param_name: &str) -> Vec<ComplianceMapping> {
    match param_name {
        "kernel.randomize_va_space" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "1.5.1".to_string(),
                compliance_control_title:
                    "Ensure address space layout randomisation (ASLR) is enabled".to_string(),
                compliance_section: Some("Initial Setup".to_string()),
            },
            // SSG: sysctl_kernel_randomize_va_space
            // refs: nist SC-30/CM-6(a) (SI-16 is the Rev 5 memory-protection
            // control for ASLR), pcidss Req-2.2.1, stigid@ol8 OL08-00-010430
            stig(
                "RHEL-08-010430",
                "Implement address space layout randomization",
            ),
            nist(
                "SI-16",
                "Memory Protection",
                "System and Information Integrity",
            ),
            nist("CM-6", "Configuration Settings", "Configuration Management"),
            pcidss(
                "2.2.6",
                "System security parameters are configured to prevent misuse",
                "Secure Configurations",
            ),
            // SSG maps this rule's hipaa to 164.312(a) (access control), not the
            // integrity standard: restricting memory layout guards access to the
            // operating environment processing protected data.
            hipaa("164.312(a)(1)", "Access control"),
            gdpr("TM-SH", "System hardening of processing systems"),
            iso("8.9", "Configuration management", "Technological"),
            // SOC 2: CC6.8 mirrors the SI-16 memory-protection (exploit mitigation) intent.
            soc2(
                "CC6.8",
                "Prevent or detect the introduction of unauthorized or malicious software",
            ),
            // 800-171r3 3.4.2 ← 800-53 CM-6 (SP 800-171r3 source-control table).
            // SI-16 carries no 800-171 requirement (tailored out as NCO), so
            // only the configuration-settings intent translates.
            nist171("3.4.2", "Configuration Settings"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 SI-16.
            fedramp("SI-16", "Memory Protection"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 CM-6.
            fedramp("CM-6", "Configuration Settings"),
        ],
        "kernel.kptr_restrict" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "1.5.4".to_string(),
                compliance_control_title: "Ensure kernel pointers are restricted".to_string(),
                compliance_section: Some("Initial Setup".to_string()),
            },
            // SSG: sysctl_kernel_kptr_restrict
            // refs: nist SC-30/CM-6(a), stigid@ol8 OL08-00-040283
            // (no pcidss; SSG carries no hipaa ref, so none is emitted)
            stig(
                "RHEL-08-040283",
                "Restrict exposed kernel pointer addresses access",
            ),
            nist("CM-6", "Configuration Settings", "Configuration Management"),
            gdpr("TM-SH", "System hardening of processing systems"),
            iso("8.9", "Configuration management", "Technological"),
            // SOC 2: CC6.1 mirrors the kernel-address access-restriction intent (SC-30/CM-6).
            soc2(
                "CC6.1",
                "Logical access security software, infrastructure, and architectures",
            ),
            // 800-171r3 3.4.2 ← 800-53 CM-6 (SP 800-171r3 source-control table).
            nist171("3.4.2", "Configuration Settings"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 CM-6.
            fedramp("CM-6", "Configuration Settings"),
        ],
        "kernel.dmesg_restrict" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "1.5.4".to_string(),
                compliance_control_title: "Ensure kernel pointers are restricted".to_string(),
                compliance_section: Some("Initial Setup".to_string()),
            },
            // SSG: sysctl_kernel_dmesg_restrict
            // refs: nist SI-11(a)/SI-11(b), stigid@ol8 OL08-00-010375 (no pcidss)
            stig(
                "RHEL-08-010375",
                "Restrict access to the kernel message buffer",
            ),
            nist(
                "SI-11",
                "Error Handling",
                "System and Information Integrity",
            ),
            // SSG hipaa cites 164.312(a) (access control) for this rule.
            hipaa("164.312(a)(1)", "Access control"),
            gdpr("TM-SH", "System hardening of processing systems"),
            iso("8.9", "Configuration management", "Technological"),
            // SOC 2: CC6.1 mirrors the access-control intent (SSG hipaa 164.312(a)).
            soc2(
                "CC6.1",
                "Logical access security software, infrastructure, and architectures",
            ),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 SI-11
            // (unlike 800-171r3, the Moderate baseline retains SI-11).
            fedramp("SI-11", "Error Handling"),
        ],
        "kernel.yama.ptrace_scope" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "1.5.2".to_string(),
                compliance_control_title: "Ensure ptrace_scope is restricted".to_string(),
                compliance_section: Some("Initial Setup".to_string()),
            },
            // SSG: sysctl_kernel_yama_ptrace_scope
            // refs: nist SC-7(10), stigid@ol8 OL08-00-040282
            // (no pcidss; SSG carries no hipaa ref, so none is emitted)
            stig(
                "RHEL-08-040282",
                "Restrict usage of ptrace to descendant processes",
            ),
            nist(
                "SC-7",
                "Boundary Protection",
                "System and Communications Protection",
            ),
            gdpr("TM-SH", "System hardening of processing systems"),
            iso("8.9", "Configuration management", "Technological"),
            // SOC 2: CC6.1 mirrors the process-access restriction intent (SC-7(10)).
            soc2(
                "CC6.1",
                "Logical access security software, infrastructure, and architectures",
            ),
            // 800-171r3 3.13.1 ← 800-53 SC-7 (SP 800-171r3 source-control table).
            nist171("3.13.1", "Boundary Protection"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 SC-7.
            fedramp("SC-7", "Boundary Protection"),
        ],
        "fs.suid_dumpable" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "1.5.3".to_string(),
                compliance_control_title: "Ensure core dumps are restricted".to_string(),
                compliance_section: Some("Initial Setup".to_string()),
            },
            // SSG: sysctl_fs_suid_dumpable
            // refs: nist SI-11(a)/SI-11(b) (no stigid@ol8, no pcidss);
            // SSG hipaa cites 164.312(a) (access control)
            nist(
                "SI-11",
                "Error Handling",
                "System and Information Integrity",
            ),
            hipaa("164.312(a)(1)", "Access control"),
            gdpr("TM-SH", "System hardening of processing systems"),
            iso("8.9", "Configuration management", "Technological"),
            // SOC 2: CC6.1 mirrors the access-control intent (SSG hipaa 164.312(a)).
            soc2(
                "CC6.1",
                "Logical access security software, infrastructure, and architectures",
            ),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 SI-11
            // (unlike 800-171r3, the Moderate baseline retains SI-11).
            fedramp("SI-11", "Error Handling"),
        ],
        "fs.protected_hardlinks" | "fs.protected_symlinks" => vec![
            // SSG: sysctl_fs_protected_hardlinks / sysctl_fs_protected_symlinks
            // refs: nist CM-6(a)/AC-6(1), stigid@ol8 OL08-00-010374 /
            // OL08-00-010373. SSG carries NO cis reference for these sysctls, so
            // no CIS mapping is emitted (a prior `1.6.1` here was unsourced and
            // collided with the curated MAC controls 1.6.1.1-.4).
            stig("RHEL-08-010374", "Enforce DAC on hardlinks and symlinks"),
            nist("CM-6", "Configuration Settings", "Configuration Management"),
            nist("AC-6", "Least Privilege", "Access Control"),
            // SSG carries no hipaa ref for these sysctls, so none is emitted.
            gdpr("TM-SH", "System hardening of processing systems"),
            iso("8.9", "Configuration management", "Technological"),
            // SOC 2: CC6.1 mirrors the AC-6 least-privilege / DAC-enforcement intent.
            soc2(
                "CC6.1",
                "Logical access security software, infrastructure, and architectures",
            ),
            // 800-171r3 3.4.2 ← 800-53 CM-6; 3.1.5 ← AC-6 (SP 800-171r3
            // source-control table).
            nist171("3.4.2", "Configuration Settings"),
            nist171("3.1.5", "Least Privilege"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 CM-6.
            fedramp("CM-6", "Configuration Settings"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 AC-6.
            fedramp("AC-6", "Least Privilege"),
        ],
        "net.ipv4.conf.all.rp_filter" | "net.ipv4.conf.default.rp_filter" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "3.2.7".to_string(),
                compliance_control_title: "Ensure reverse path filtering is enabled".to_string(),
                compliance_section: Some("Network Configuration".to_string()),
            },
            // SSG: sysctl_net_ipv4_conf_all_rp_filter (and _default_)
            // refs: nist CM-7(a)/CM-7(b)/CM-6(a)/SC-7(a), pcidss Req-1.4.3
            // (all-interfaces), stigid@ol8 OL08-00-040285 (all-interfaces only)
            stig(
                "RHEL-08-040285",
                "Use reverse path filtering on all IPv4 interfaces",
            ),
            nist("CM-7", "Least Functionality", "Configuration Management"),
            nist(
                "SC-7",
                "Boundary Protection",
                "System and Communications Protection",
            ),
            pcidss(
                "1.4.1",
                "NSCs are implemented between trusted and untrusted networks",
                "Network Security Controls",
            ),
            // Cross-framework: anti-spoofing protects integrity/security of data
            // in transit across the network boundary.
            hipaa("164.312(e)(1)", "Transmission security"),
            gdpr("TM-SH", "System hardening of processing systems"),
            gdpr("TM-NW", "Network-level protection of processing systems"),
            iso("8.20", "Networks security", "Technological"),
            // SOC 2: CC6.6 mirrors the SC-7 network-boundary (anti-spoofing) intent.
            soc2(
                "CC6.6",
                "Protect against threats from sources outside system boundaries",
            ),
            // 800-171r3 3.4.6 ← 800-53 CM-7; 3.13.1 ← SC-7 (SP 800-171r3
            // source-control table).
            nist171("3.4.6", "Least Functionality"),
            nist171("3.13.1", "Boundary Protection"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 CM-7.
            fedramp("CM-7", "Least Functionality"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 SC-7.
            fedramp("SC-7", "Boundary Protection"),
        ],
        "net.ipv4.tcp_syncookies" => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "3.2.8".to_string(),
                compliance_control_title: "Ensure TCP SYN cookies is enabled".to_string(),
                compliance_section: Some("Network Configuration".to_string()),
            },
            // SSG: sysctl_net_ipv4_tcp_syncookies
            // refs: nist SC-5(1)/SC-5(2)/SC-5(3)(a)/CM-7/CM-6(a), pcidss
            // Req-1.4.1 (no stigid@ol8)
            nist(
                "SC-5",
                "Denial-of-Service Protection",
                "System and Communications Protection",
            ),
            pcidss(
                "1.4.1",
                "NSCs are implemented between trusted and untrusted networks",
                "Network Security Controls",
            ),
            hipaa("164.312(e)(1)", "Transmission security"),
            gdpr("TM-SH", "System hardening of processing systems"),
            gdpr("TM-NW", "Network-level protection of processing systems"),
            iso("8.20", "Networks security", "Technological"),
            // SOC 2: CC6.6 mirrors the SC-5 boundary DoS-protection intent.
            soc2(
                "CC6.6",
                "Protect against threats from sources outside system boundaries",
            ),
            // No 800-171 mapping: SC-5 is tailored out of SP 800-171r3 (NCO).
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 SC-5
            // (the Moderate baseline retains SC-5 even though 800-171r3 does not).
            fedramp("SC-5", "Denial-of-Service Protection"),
        ],
        "net.ipv4.conf.all.accept_source_route" | "net.ipv4.conf.default.accept_source_route" => {
            vec![
                ComplianceMapping {
                    compliance_framework: ComplianceFramework::CIS,
                    compliance_control_id: "3.2.1".to_string(),
                    compliance_control_title: "Ensure source routed packets are not accepted"
                        .to_string(),
                    compliance_section: Some("Network Configuration".to_string()),
                },
                // SSG: sysctl_net_ipv4_conf_all_accept_source_route (and _default_)
                // refs: nist CM-7(a)/CM-7(b)/SC-5/SC-7(a), stigid@ol8
                // OL08-00-040239 (all) / OL08-00-040249 (default) (no pcidss)
                stig("RHEL-08-040239", "Do not accept source-routed IPv4 packets"),
                nist("CM-7", "Least Functionality", "Configuration Management"),
                nist(
                    "SC-7",
                    "Boundary Protection",
                    "System and Communications Protection",
                ),
                hipaa("164.312(e)(1)", "Transmission security"),
                gdpr("TM-SH", "System hardening of processing systems"),
                gdpr("TM-NW", "Network-level protection of processing systems"),
                iso("8.20", "Networks security", "Technological"),
                // SOC 2: CC6.6 mirrors the SC-7 network-boundary intent.
                soc2(
                    "CC6.6",
                    "Protect against threats from sources outside system boundaries",
                ),
                // 800-171r3 3.4.6 ← 800-53 CM-7; 3.13.1 ← SC-7 (SP 800-171r3
                // source-control table).
                nist171("3.4.6", "Least Functionality"),
                nist171("3.13.1", "Boundary Protection"),
                // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 CM-7.
                fedramp("CM-7", "Least Functionality"),
                // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 SC-7.
                fedramp("SC-7", "Boundary Protection"),
            ]
        }
        // CIS 3.2.2/3.2.3/3.2.4: one arm per control covers both the `.all`
        // and `.default` sysctls. SSG: sysctl_net_ipv4_conf_{all,default}_*
        n if n.contains("accept_redirects") => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "3.2.2".to_string(),
                compliance_control_title: "Ensure ICMP redirects are not accepted".to_string(),
                compliance_section: Some("Network Configuration".to_string()),
            },
            nist(
                "SI-4",
                "System Monitoring",
                "System and Information Integrity",
            ),
            iso("8.20", "Networks security", "Technological"),
            // SOC 2: CC6.6 mirrors the network-boundary hardening intent (CIS 3.2.2).
            soc2(
                "CC6.6",
                "Protect against threats from sources outside system boundaries",
            ),
            // 800-171r3 3.14.6 ← 800-53 SI-4 (SP 800-171r3 source-control table).
            nist171("3.14.6", "System Monitoring"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 SI-4.
            fedramp("SI-4", "System Monitoring"),
        ],
        n if n.contains("secure_redirects") => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "3.2.3".to_string(),
                compliance_control_title: "Ensure secure ICMP redirects are not accepted"
                    .to_string(),
                compliance_section: Some("Network Configuration".to_string()),
            },
            nist(
                "SI-4",
                "System Monitoring",
                "System and Information Integrity",
            ),
            iso("8.20", "Networks security", "Technological"),
            // SOC 2: CC6.6 mirrors the network-boundary hardening intent (CIS 3.2.3).
            soc2(
                "CC6.6",
                "Protect against threats from sources outside system boundaries",
            ),
            // 800-171r3 3.14.6 ← 800-53 SI-4 (SP 800-171r3 source-control table).
            nist171("3.14.6", "System Monitoring"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 SI-4.
            fedramp("SI-4", "System Monitoring"),
        ],
        n if n.contains("log_martians") => vec![
            ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: "3.2.4".to_string(),
                compliance_control_title: "Ensure suspicious packets are logged".to_string(),
                compliance_section: Some("Network Configuration".to_string()),
            },
            nist(
                "SI-4",
                "System Monitoring",
                "System and Information Integrity",
            ),
            iso("8.15", "Logging", "Technological"),
            // SOC 2: CC7.2 mirrors the SI-4 anomaly-logging intent (suspicious packets).
            soc2(
                "CC7.2",
                "Monitor system components for anomalies indicative of malicious acts or errors",
            ),
            // 800-171r3 3.14.6 ← 800-53 SI-4 (SP 800-171r3 source-control table).
            nist171("3.14.6", "System Monitoring"),
            // FedRAMP Moderate r5 baseline member (GSA rev5 baseline): 800-53 SI-4.
            fedramp("SI-4", "System Monitoring"),
        ],
        _ => vec![],
    }
}

#[async_trait]
impl HardeningPlugin for KernelHardeningPlugin {
    /// Returns metadata about the kernel hardening plugin.
    ///
    /// This provides the plugin system with identification and versioning
    /// information used for logging, UI display, and dependency management.
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            plugin_category: FindingCategory::Kernel,
            plugin_description: "Manages kernel security parameters via sysctl".to_string(),
            plugin_id: PluginId::new("kernel-hardening"),
            plugin_name: "Kernel Hardening".to_string(),
            plugin_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Returns plugin dependencies.
    ///
    /// The kernel hardening plugin has no dependencies as it operates
    /// independently on kernel parameters via sysctl.
    fn dependencies(&self) -> Vec<PluginId> {
        Vec::new()
    }

    async fn scan(&self, ctx: &Context) -> Result<ScanResult> {
        let start_time = Instant::now();
        let mut findings = Vec::new();

        for (param_name, expected_value, param_description, severity) in KERNEL_PARAMS {
            match self.read_sysctl(param_name, ctx).await {
                Ok(actual_value) => {
                    if actual_value != *expected_value {
                        findings.push(Finding {
                            finding_category: FindingCategory::Kernel,
                            finding_current_value: actual_value.clone(),
                            finding_description: param_description.to_string(),
                            finding_explanation: format!(
                                "This parameter should be set to '{}' for security hardening",
                                expected_value,
                            ),
                            finding_id: format!("kernel_{}", param_name.replace('.', "_")),
                            finding_impact: format!(
                                "Insecure {} weakens system defences against exploitation",
                                param_name,
                            ),

                            finding_recommended_value: expected_value.to_string(),
                            finding_remediation_steps: vec![format!(
                                "Set {} = {}",
                                param_name, expected_value
                            )],
                            finding_severity: *severity,
                            finding_title: format!("Insecure value for {}", param_name),
                            finding_compliance: get_compliance_mappings(param_name),
                            finding_policy_exception: None,
                        });
                    }
                }
                Err(e) => {
                    // Parameter doesn't exist on this kernel - log but don't fail
                    warn!("Cannot read {}: {}", param_name, e);
                }
            }
        }

        Ok(ScanResult {
            scan_plugin_id: self.metadata().plugin_id,
            scan_success: true,
            scan_findings: findings,
            scan_unchecked: vec![],
            scan_duration_us: start_time.elapsed().as_micros() as u64,
            scan_error: None,
        })
    }

    /// Applies kernel hardening by setting sysctl parameters.
    ///
    /// # Security Implications
    /// This writes to /proc/sys which requires root privileges.
    /// Changes take effect immediately but are not persistent across reboots
    /// unless also written to /etc/sysctl.conf or /etc/sysctl.d/
    ///
    /// # Arguments
    /// * `ctx`    - Execution context with checkpoint manager
    /// * `config` - Plugin configuration with directive overrides and policy exceptions
    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult> {
        let mut apply_changes = Vec::new();
        let hardener_sysctl_path = Path::new("/etc/sysctl.d/99-hardener.conf");

        // Create checkpoint to capture sysctl config files before changes.
        // Include our hardener file if it exists.
        let sysctl_paths: Vec<&Path> = vec![
            Path::new("/etc/sysctl.conf"),
            Path::new("/etc/sysctl.d"),
            hardener_sysctl_path,
        ];
        let checkpoint_id =
            crate::create_checkpoint_for_apply(ctx, "kernel-hardening-pre-apply", &sysctl_paths)
                .await?;

        if checkpoint_id.is_some() {
            apply_changes.push(Change {
                change_description: "Created checkpoint for rollback".to_string(),
                change_type: ChangeType::KernelParameter,
                change_success: true,
                change_error: None,
            });
        }

        // Build sysctl.d config file content for persistence.
        let mut sysctl_config_content = String::from(
            "# Kernel hardening settings applied by Linux Hardener\n\
             # This file is managed automatically - manual edits will be overwritten\n\n",
        );

        // Apply each parameter to runtime AND build config file content.
        for (param_name, expected_value, param_description, _severity) in KERNEL_PARAMS {
            // Check for a valid exception: skip this parameter if exempted
            if let Some(exception) = config.has_valid_exception(param_name) {
                info!("Skipping {} (exception: {})", param_name, exception.reason);
                sysctl_config_content.push_str(&format!(
                    "# {}: SKIPPED (exception: {})\n\n",
                    param_name, exception.reason
                ));
                apply_changes.push(Change {
                    change_description: format!(
                        "{}: skipped (exception: {})",
                        param_description, exception.reason
                    ),
                    change_type: ChangeType::KernelParameter,
                    change_success: true,
                    change_error: None,
                });
                continue;
            }

            // Determine target value: user directive override or hardcoded baseline
            let target_value = config
                .directives
                .get(*param_name)
                .map(|s| s.as_str())
                .unwrap_or(expected_value);

            let path = format!("/proc/sys/{}", param_name.replace('.', "/"));

            // Add to persistent config file.
            sysctl_config_content.push_str(&format!(
                "# {}\n{} = {}\n\n",
                param_description, param_name, target_value
            ));

            // Apply immediately to runtime.
            match ctx
                .executor()
                .write_file(Path::new(&path), target_value)
                .await
            {
                Ok(_) => {
                    apply_changes.push(Change {
                        change_description: format!(
                            "{}: set to {}",
                            param_description, target_value
                        ),
                        change_type: ChangeType::KernelParameter,
                        change_success: true,
                        change_error: None,
                    });
                    info!("Applied {}: {}", param_name, target_value);
                }
                Err(e) => {
                    apply_changes.push(Change {
                        change_description: format!("{}: failed to set", param_name),
                        change_type: ChangeType::KernelParameter,
                        change_success: false,
                        change_error: Some(e.to_string()),
                    });
                    warn!("Failed to apply {}: {}", param_name, e);
                }
            }
        }

        // Write persistent config file so changes survive reboot AND rollback works.
        match ctx
            .executor()
            .write_file(hardener_sysctl_path, &sysctl_config_content)
            .await
        {
            Ok(_) => {
                apply_changes.push(Change {
                    change_description: "Created persistent sysctl config".to_string(),
                    change_type: ChangeType::ConfigFile,
                    change_success: true,
                    change_error: None,
                });
                info!("Created {}", hardener_sysctl_path.display());
            }
            Err(e) => {
                apply_changes.push(Change {
                    change_description: "Failed to create persistent sysctl config".to_string(),
                    change_type: ChangeType::ConfigFile,
                    change_success: false,
                    change_error: Some(e.to_string()),
                });
                warn!("Failed to create {}: {}", hardener_sysctl_path.display(), e);
            }
        }

        let apply_success = apply_changes.iter().all(|c| c.change_success);

        Ok(ApplyResult {
            apply_plugin_id: self.metadata().plugin_id,
            apply_success,
            apply_changes,
            apply_checkpoint_id: checkpoint_id,
            apply_error: None,
        })
    }

    /// Rolls back kernel parameters to a previous checkpoint.
    ///
    /// Restores sysctl configuration files from the checkpoint and reloads
    /// the kernel parameters using `sysctl --system`.
    ///
    /// # Arguments
    /// * `ctx` - Execution context containing checkpoint manager
    /// * `checkpoint` - The checkpoint to restore to
    async fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()> {
        info!(
            "Rolling back kernel configuration to checkpoint: {}",
            checkpoint.checkpoint_id.as_str()
        );

        // Get the checkpoint manager from context
        let manager = ctx.checkpoint_manager().ok_or_else(|| {
            hardener_common::error::HardeningError::State(
                "CheckpointManager not available in context".to_string(),
            )
        })?;

        // Run async rollback to restore configuration files
        let checkpoint_id = checkpoint.checkpoint_id.clone();
        let manager = manager.clone();

        manager
            .rollback(ctx.executor().as_ref(), &checkpoint_id)
            .await?;

        info!("Kernel configuration files restored from checkpoint");

        // Reload sysctl settings from restored config files
        let reload_result = ctx
            .executor()
            .execute_command("sysctl", &["--system"])
            .await?;

        if reload_result.success() {
            info!("Kernel parameters reloaded successfully");
        } else {
            warn!(
                "sysctl --system returned non-zero: {}",
                reload_result.stderr
            );
        }

        Ok(())
    }

    /// Validates that kernel parameters can be applied (dry-run).
    ///
    /// Checks if sysctl parameters exist and are writable without
    /// actually modifying them.
    ///
    /// # Arguments
    /// * `config` - Plugin configuration with directive overrides and policy exceptions
    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> {
        let mut issues = Vec::new();
        let mut estimated_changes = Vec::new();

        for (param_name, expected_value, _expected_description, _severity) in KERNEL_PARAMS {
            // Skip parameters with valid exceptions
            if config.has_valid_exception(param_name).is_some() {
                continue;
            }

            // Determine target value for preview
            let target_value = config
                .directives
                .get(*param_name)
                .map(|s| s.as_str())
                .unwrap_or(expected_value);

            let path = format!("/proc/sys/{}", param_name.replace('.', "/"));

            // Check if parameter exists and is readable
            match ctx.executor().file_metadata(Path::new(&path)).await {
                Ok(metadata) => {
                    // Check if writeable (mode has write bit for owner)
                    if metadata.mode & 0o200 == 0 {
                        issues.push(ValidationIssue {
                            validation_issue_severity: Severity::High,
                            validation_issue_message: format!("{} is read-only", param_name),
                            validation_issue_config_key: Some(param_name.to_string()),
                        });
                    } else {
                        estimated_changes
                            .push(format!("{} will be set to {}", param_name, target_value));
                    }
                }
                Err(_) => {
                    issues.push(ValidationIssue {
                        validation_issue_severity: Severity::Low,
                        validation_issue_message: format!(
                            "{} does not exist on this kernel",
                            param_name
                        ),
                        validation_issue_config_key: Some(param_name.to_string()),
                    });
                }
            }
        }

        Ok(ValidationReport {
            validation_report_plugin_id: self.metadata().plugin_id,
            validation_report_is_valid: issues
                .iter()
                .all(|i| i.validation_issue_severity != Severity::High),
            validation_report_issues: issues,
            validation_report_estimated_changes: estimated_changes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirms a representative kernel check now carries multi-framework
    /// mappings: CIS (existing) plus STIG and NIST sourced from SSG.
    #[test]
    fn aslr_maps_cis_stig_and_nist() {
        let mappings = get_compliance_mappings("kernel.randomize_va_space");

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

    /// Confirms the memory-protection check additionally carries the data-
    /// protection frameworks (HIPAA access control, GDPR system hardening, ISO 27001)
    /// alongside the existing CIS/STIG/NIST/PCI-DSS mappings.
    #[test]
    fn aslr_maps_hipaa_gdpr_and_iso27001() {
        let mappings = get_compliance_mappings("kernel.randomize_va_space");

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

        // ISO 27001 control for sysctl hardening is clause 8.9 (Configuration
        // management); the HIPAA citation is the §164.312(a)(1) access-control
        // standard, matching the SSG reference for this rule.
        let iso = mappings
            .iter()
            .find(|m| m.compliance_framework == ComplianceFramework::ISO27001)
            .expect("ISO 27001 mapping present");
        assert_eq!(iso.compliance_control_id, "8.9");

        let hipaa = mappings
            .iter()
            .find(|m| m.compliance_framework == ComplianceFramework::HIPAA)
            .expect("HIPAA mapping present");
        assert_eq!(hipaa.compliance_control_id, "164.312(a)(1)");
    }

    /// Confirms the SOC 2 mappings across the three intents the kernel plugin
    /// mirrors: exploit mitigation (CC6.8), network boundary (CC6.6) and
    /// anomaly logging (CC7.2), each filed under its TSC series.
    #[test]
    fn kernel_params_map_soc2_criteria() {
        let soc2_for = |param: &str| {
            get_compliance_mappings(param)
                .into_iter()
                .find(|m| m.compliance_framework == ComplianceFramework::SOC2)
                .unwrap_or_else(|| panic!("{param} must carry a SOC 2 mapping"))
        };

        let aslr = soc2_for("kernel.randomize_va_space");
        assert_eq!(aslr.compliance_control_id, "CC6.8");
        assert_eq!(
            aslr.compliance_section.as_deref(),
            Some("Logical and Physical Access Controls")
        );

        let rp_filter = soc2_for("net.ipv4.conf.all.rp_filter");
        assert_eq!(rp_filter.compliance_control_id, "CC6.6");

        let martians = soc2_for("net.ipv4.conf.all.log_martians");
        assert_eq!(martians.compliance_control_id, "CC7.2");
        assert_eq!(
            martians.compliance_section.as_deref(),
            Some("System Operations")
        );
    }

    /// Confirms the 800-171r3 crosswalk: every requirement id is translated
    /// from the parameter's existing 800-53 entries via the r3 source-control
    /// table, and parameters whose only 800-53 controls are tailored out of
    /// 800-171 (SC-5, SI-11) honestly carry no mapping.
    #[test]
    fn kernel_params_map_nist_800_171_requirements() {
        let ids_for = |param: &str| -> Vec<String> {
            get_compliance_mappings(param)
                .into_iter()
                .filter(|m| m.compliance_framework == ComplianceFramework::NIST800171)
                .map(|m| m.compliance_control_id)
                .collect()
        };

        // CM-6 → 3.4.2; SI-16 is tailored out, so ASLR translates nothing else.
        assert_eq!(ids_for("kernel.randomize_va_space"), vec!["3.4.2"]);
        // CM-7 → 3.4.6 and SC-7 → 3.13.1.
        assert_eq!(
            ids_for("net.ipv4.conf.all.rp_filter"),
            vec!["3.4.6", "3.13.1"]
        );

        // SI-4 → 3.14.6, filed under its official family name.
        let monitoring = get_compliance_mappings("net.ipv4.conf.all.log_martians")
            .into_iter()
            .find(|m| m.compliance_framework == ComplianceFramework::NIST800171)
            .expect("log_martians must carry an 800-171 mapping");
        assert_eq!(monitoring.compliance_control_id, "3.14.6");
        assert_eq!(
            monitoring.compliance_section.as_deref(),
            Some("System and Information Integrity")
        );

        // SC-5 and SI-11 are tailored out of 800-171r3 (NCO): honest absence.
        for param in [
            "net.ipv4.tcp_syncookies",
            "kernel.dmesg_restrict",
            "fs.suid_dumpable",
        ] {
            assert!(
                ids_for(param).is_empty(),
                "{param} must not over-claim 800-171"
            );
        }
    }

    /// Confirms the FedRAMP derivation: every mapped id mirrors the
    /// parameter's existing 800-53 entries verbatim, filtered to the GSA
    /// rev5 Moderate baseline. Every 800-53 control this plugin cites is a
    /// baseline member (including SC-5 and SI-11, which 800-171r3 tailors
    /// out), so no parameter loses its mapping.
    #[test]
    fn kernel_params_map_fedramp_moderate_controls() {
        let ids_for = |param: &str| -> Vec<String> {
            get_compliance_mappings(param)
                .into_iter()
                .filter(|m| m.compliance_framework == ComplianceFramework::FedRAMP)
                .map(|m| m.compliance_control_id)
                .collect()
        };

        // Both SI-16 and CM-6 are Moderate baseline members: ASLR keeps both.
        assert_eq!(ids_for("kernel.randomize_va_space"), vec!["SI-16", "CM-6"]);
        assert_eq!(ids_for("net.ipv4.conf.all.rp_filter"), vec!["CM-7", "SC-7"]);
        // Unlike 800-171r3, the Moderate baseline retains SC-5 and SI-11.
        assert_eq!(ids_for("net.ipv4.tcp_syncookies"), vec!["SC-5"]);
        assert_eq!(ids_for("kernel.dmesg_restrict"), vec!["SI-11"]);

        // SI-4, filed under its official 800-53 family name.
        let monitoring = get_compliance_mappings("net.ipv4.conf.all.log_martians")
            .into_iter()
            .find(|m| m.compliance_framework == ComplianceFramework::FedRAMP)
            .expect("log_martians must carry a FedRAMP mapping");
        assert_eq!(monitoring.compliance_control_id, "SI-4");
        assert_eq!(
            monitoring.compliance_section.as_deref(),
            Some("System and Information Integrity")
        );
    }

    #[test]
    fn redirect_and_martian_params_map_cis() {
        for (param, id) in [
            ("net.ipv4.conf.all.accept_redirects", "3.2.2"),
            ("net.ipv4.conf.default.accept_redirects", "3.2.2"),
            ("net.ipv4.conf.all.secure_redirects", "3.2.3"),
            ("net.ipv4.conf.default.secure_redirects", "3.2.3"),
            ("net.ipv4.conf.all.log_martians", "3.2.4"),
            ("net.ipv4.conf.default.log_martians", "3.2.4"),
        ] {
            let cis = get_compliance_mappings(param)
                .into_iter()
                .find(|m| m.compliance_framework == ComplianceFramework::CIS)
                .unwrap_or_else(|| panic!("{param} must map a CIS control"));
            assert_eq!(cis.compliance_control_id, id, "{param}");
        }
    }
}
