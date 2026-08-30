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

use crate::strictness::Strictness;
use async_trait::async_trait;
use hardener_common::{
    error::{Result, message_indicates_permission_denied},
    types::{ComplianceFramework, ComplianceMapping, FindingCategory, PluginId, Severity},
};
use hardener_core::{
    Change, ChangeType, PluginConfig, ValidationIssue, ValidationReport,
    context::Context,
    plugin::{
        ApplyResult, Finding, HardeningPlugin, PluginMetadata, ScanResult, UncheckedBlocker,
        UncheckedCheck,
    },
};
use std::{path::Path, time::Instant};
use tracing::{info, warn};

mod divergence;
mod persistence;

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
        let path = format!("/proc/sys/{}", persistence::procfs_key(param));
        let content = ctx.executor().read_file(Path::new(&path)).await?;
        Ok(content.trim().to_string())
    }
}

/// The directory holding the persistent sysctl file this tool manages.
const SYSCTL_DROPIN_DIR: &str = "/etc/sysctl.d";

/// The persistent file this tool writes, which is what carries the settings
/// across a reboot. Named once because the apply writes it and the preview
/// predicts it, and a path spelled twice is a path that can come to mean two
/// files.
const SYSCTL_HARDENER_CONF: &str = "/etc/sysctl.d/99-hardener.conf";

/// The opening of [`SYSCTL_HARDENER_CONF`], ahead of the per-parameter blocks.
const SYSCTL_CONFIG_HEADER: &str = "# Kernel hardening settings applied by Linux Hardener\n\
     # This file is managed automatically - manual edits will be overwritten\n\n";

/// The strictness order of `fs.suid_dumpable`, weakest first. 1 dumps core
/// from every setuid process, 2 dumps a core only root can read, and 0 refuses
/// outright, so the safest value is the smallest and the middle one is neither
/// end. The integer carries none of that. This baseline is already the
/// strongest value, which makes the ranking indistinguishable from `AtMost`
/// today; it is written out because the reason `AtMost` happens to be right
/// here is an accident of the baseline rather than a property of the setting.
const SUID_DUMPABLE_ORDER: &[&[&str]] = &[&["1"], &["2"], &["0"]];

/// The strictness order of `rp_filter`, weakest first: 0 is off, 2 is loose
/// mode, which accepts a packet if its source is reachable through any
/// interface, and 1 is strict mode, which requires the interface it arrived
/// on. Loose mode is therefore weaker than strict mode while being the larger
/// number, and no numeric direction can express that.
const RP_FILTER_ORDER: &[&[&str]] = &[&["0"], &["2"], &["1"]];

/// A kernel security parameter, its secure value, and the direction in which
/// one of its values is stricter than another.
///
/// The comparison used to be equality, which has no direction, so a host safer
/// than this baseline counted as violating and both the runtime write and the
/// persistent file replaced its value with the baseline.
#[derive(Clone, Debug)]
struct KernelParameter {
    /// Parameter name in sysctl dot notation.
    kernel_parameter_name: &'static str,
    /// The value this tool targets.
    kernel_secure_value: &'static str,
    /// Human-readable explanation of what the parameter protects against.
    kernel_description: &'static str,
    /// Severity of a host that does not meet the target.
    kernel_severity: Severity,
    /// Which direction counts as stricter for this parameter's values.
    kernel_compare: Strictness,
}

/// Critical kernel security parameters with their secure values.
const KERNEL_PARAMS: &[KernelParameter] = &[
    KernelParameter {
        kernel_parameter_name: "kernel.randomize_va_space",
        kernel_secure_value: "2",
        kernel_description: "Enable full address space layout randomisation (ASLR)",
        kernel_severity: Severity::High,
        kernel_compare: Strictness::AtLeast,
    },
    KernelParameter {
        kernel_parameter_name: "kernel.kptr_restrict",
        kernel_secure_value: "2",
        kernel_description: "Hides kernel pointers from all users except root",
        kernel_severity: Severity::Medium,
        kernel_compare: Strictness::AtLeast,
    },
    KernelParameter {
        kernel_parameter_name: "kernel.dmesg_restrict",
        kernel_secure_value: "1",
        kernel_description: "Restricts dmesg access to privileged users only",
        kernel_severity: Severity::Medium,
        kernel_compare: Strictness::AtLeast,
    },
    KernelParameter {
        kernel_parameter_name: "kernel.yama.ptrace_scope",
        kernel_secure_value: "2",
        kernel_description: "Restricts ptrace usage to admin-only",
        kernel_severity: Severity::High,
        // 3 forbids ptrace outright and is stricter than this baseline, so a
        // host at 3 is compliant and is never written down to 2.
        kernel_compare: Strictness::AtLeast,
    },
    KernelParameter {
        kernel_parameter_name: "fs.suid_dumpable",
        kernel_secure_value: "0",
        kernel_description: "Prevents setuid processes from creating core dumps",
        kernel_severity: Severity::Medium,
        kernel_compare: Strictness::Ranked(SUID_DUMPABLE_ORDER),
    },
    KernelParameter {
        kernel_parameter_name: "fs.protected_hardlinks",
        kernel_secure_value: "1",
        kernel_description: "Prevents hardlink creation to files user doesn't own",
        kernel_severity: Severity::Medium,
        kernel_compare: Strictness::AtLeast,
    },
    KernelParameter {
        kernel_parameter_name: "fs.protected_symlinks",
        kernel_secure_value: "1",
        kernel_description: "Prevents symlink following in sticky world-writable directories",
        kernel_severity: Severity::Medium,
        kernel_compare: Strictness::AtLeast,
    },
    KernelParameter {
        kernel_parameter_name: "net.ipv4.conf.all.rp_filter",
        kernel_secure_value: "1",
        kernel_description: "Enables reverse path filtering (anti-spoofing)",
        kernel_severity: Severity::High,
        kernel_compare: Strictness::Ranked(RP_FILTER_ORDER),
    },
    KernelParameter {
        kernel_parameter_name: "net.ipv4.conf.default.rp_filter",
        kernel_secure_value: "1",
        kernel_description: "Enables reverse path filtering for new interfaces",
        kernel_severity: Severity::High,
        kernel_compare: Strictness::Ranked(RP_FILTER_ORDER),
    },
    KernelParameter {
        kernel_parameter_name: "net.ipv4.tcp_syncookies",
        kernel_secure_value: "1",
        kernel_description: "Enables SYN flood protection",
        kernel_severity: Severity::High,
        // 2 sends SYN cookies unconditionally rather than under pressure, which
        // is not weaker, so a host at 2 keeps it.
        kernel_compare: Strictness::AtLeast,
    },
    KernelParameter {
        kernel_parameter_name: "net.ipv4.conf.all.accept_source_route",
        kernel_secure_value: "0",
        kernel_description: "Disables source routing (security risk)",
        kernel_severity: Severity::Medium,
        kernel_compare: Strictness::AtMost,
    },
    KernelParameter {
        kernel_parameter_name: "net.ipv4.conf.default.accept_source_route",
        kernel_secure_value: "0",
        kernel_description: "Disables source routing for new interfaces",
        kernel_severity: Severity::Medium,
        kernel_compare: Strictness::AtMost,
    },
    KernelParameter {
        kernel_parameter_name: "net.ipv4.conf.all.accept_redirects",
        kernel_secure_value: "0",
        kernel_description: "Disables acceptance of ICMP redirects (prevents route table poisoning)",
        kernel_severity: Severity::Medium,
        kernel_compare: Strictness::AtMost,
    },
    KernelParameter {
        kernel_parameter_name: "net.ipv4.conf.default.accept_redirects",
        kernel_secure_value: "0",
        kernel_description: "Disables ICMP redirect acceptance for new interfaces",
        kernel_severity: Severity::Medium,
        kernel_compare: Strictness::AtMost,
    },
    KernelParameter {
        kernel_parameter_name: "net.ipv4.conf.all.secure_redirects",
        kernel_secure_value: "0",
        kernel_description: "Disables acceptance of secure ICMP redirects",
        kernel_severity: Severity::Medium,
        kernel_compare: Strictness::AtMost,
    },
    KernelParameter {
        kernel_parameter_name: "net.ipv4.conf.default.secure_redirects",
        kernel_secure_value: "0",
        kernel_description: "Disables secure ICMP redirect acceptance for new interfaces",
        kernel_severity: Severity::Medium,
        kernel_compare: Strictness::AtMost,
    },
    KernelParameter {
        kernel_parameter_name: "net.ipv4.conf.all.log_martians",
        kernel_secure_value: "1",
        kernel_description: "Logs packets with impossible (martian) source addresses",
        kernel_severity: Severity::Low,
        kernel_compare: Strictness::AtLeast,
    },
    KernelParameter {
        kernel_parameter_name: "net.ipv4.conf.default.log_martians",
        kernel_secure_value: "1",
        kernel_description: "Logs martian packets for new interfaces",
        kernel_severity: Severity::Low,
        kernel_compare: Strictness::AtLeast,
    },
];

/// The target for `parameter`: its secure value, tightened by an operator's
/// directive override where the config sets one that tightens it.
///
/// Scan, apply and validate all resolve it here. An override that would relax
/// a parameter below this tool's own baseline is not honoured; a deliberate
/// deviation belongs in an exception, which the report labels.
fn resolved_target(parameter: &KernelParameter, config: &PluginConfig) -> String {
    parameter.kernel_compare.resolved_target(
        config,
        parameter.kernel_parameter_name,
        parameter.kernel_secure_value,
    )
}

/// Whether the mount carrying `path` is read-only, or `None` when the probe
/// could not tell.
///
/// The inode cannot answer this. Every file under `/proc/sys` is 0644 whether
/// or not the mount allows writing, because read-only is a property of the
/// mount, so a dry run previewed writes an apply could not perform and said
/// nothing about it.
///
/// **`-T` is the whole point and its absence is why the obvious version of this
/// does not work.** `/proc/sys` is not a mount point, it is a directory inside
/// the `/proc` mount, and `findmnt` given a path that is not a mount point
/// matches nothing and exits 1. Measured: `findmnt -no OPTIONS /proc/sys` is
/// empty while `findmnt -T /proc/sys -no VFS-OPTIONS` reports the mount.
/// `-T` resolves a path to the mount covering it, which is the question.
///
/// Asked per parameter rather than once for `/proc/sys`, because the answer
/// genuinely differs within that tree: `systemd-nspawn` mounts `/proc/sys`
/// read-only and `/proc/sys/net` read-write for the container's own network
/// namespace, so one reading for the whole subtree would be wrong for both
/// halves on the hosts where this matters most.
///
/// `None` on any probe failure, and the caller must not treat that as a
/// blocker. This is not an exception to the rule that an undeterminable value
/// is a failure rather than a skip: that rule exists so a probe cannot SUPPRESS
/// a finding, and this probe can only ADD one. Failing closed here would block
/// every dry run on every host without util-linux. The permissions plugin's
/// filesystem probe reaches the same answer from the other side, where its
/// probe can only suppress and therefore keeps the finding when it cannot tell.
async fn mount_is_read_only(ctx: &Context, path: &str) -> Option<bool> {
    let output = ctx
        .executor()
        .execute_command("findmnt", &["-T", path, "-no", "VFS-OPTIONS"])
        .await
        .ok()?;
    let options = output.stdout.trim();
    if !output.success() || options.is_empty() {
        return None;
    }
    // Exact token, and the option list is full of traps for a substring test.
    // `errors=remount-ro` is the one that matters: it is what a read-WRITE
    // ext4 root commonly carries, so `contains("ro")` would report a perfectly
    // writable host as read-only and block its dry run. Reporting every mount
    // read-only is the failure mode that looks like a product defect on every
    // host at once, which is why the test pins this with a fixture carrying
    // that option rather than with the bare `rw` list that cannot tell the two
    // implementations apart.
    Some(options.split(',').any(|option| option.trim() == "ro"))
}

/// What a run intends for one parameter, decided once from the value the host
/// was observed to hold.
///
/// The runtime write and the persistent file are two halves of the same
/// decision, and the preview has to reach the same one. Apply gates its write
/// to [`SYSCTL_HARDENER_CONF`] on the file's content differing from what it is
/// about to write, so a preview that cannot compute that content cannot say
/// whether the write is pending. That is the gap the container run of
/// 2026-07-31 found on rhel, the one fixture where every parameter arrives
/// compliant: the preview was empty and the apply still created the file.
enum PlannedParameter<'a> {
    /// A documented exception covers the value the host actually holds, so the
    /// parameter is left alone and recorded rather than hardened.
    Excepted {
        /// The value the exception documents, which is the one observed.
        observed: &'a str,
        /// Why the deviation is accepted.
        reason: &'a str,
    },
    /// The value this run writes: into the persistent file always, and into
    /// /proc/sys where the host is weaker than it.
    Setting {
        /// The resolved target, already clamped against the host's own value.
        target_value: String,
    },
}

/// What this run intends for `parameter` on a host observed to hold `observed`.
///
/// Both halves of a run decide here: the apply so that its runtime write and
/// its persistent file agree, and the preview so that it predicts the file the
/// apply will write. The no-loosen clamp is spelled once, in this function,
/// because the file carries the clamped value; a preview computing the
/// unclamped one would predict different content on every host already
/// stricter than the baseline and report a rewrite that never arrives.
fn plan_parameter<'a>(
    parameter: &KernelParameter,
    config: &'a PluginConfig,
    observed: Option<&'a str>,
) -> PlannedParameter<'a> {
    // The exception is honoured only when it documents the value the host
    // actually has. An unreadable value cannot confirm one, so it is not
    // honoured and the parameter is hardened (fail closed).
    if let Some(value) = observed
        && let Some(exception) = config.matching_exception(parameter.kernel_parameter_name, value)
    {
        return PlannedParameter::Excepted {
            observed: value,
            reason: &exception.reason,
        };
    }

    // Never loosen: the value written is the stricter of this tool's target and
    // what the host already runs. The persistent file is written for every
    // parameter whatever the runtime gate decides, so clamping only the runtime
    // write would still hand a stricter host the baseline back at its next boot.
    PlannedParameter::Setting {
        target_value: parameter
            .kernel_compare
            .clamp_target(&resolved_target(parameter, config), observed),
    }
}

impl PlannedParameter<'_> {
    /// Appends this parameter's block to the persistent file's content.
    ///
    /// An excepted parameter is written as a comment rather than as a setting,
    /// so the file does not re-impose at the next boot what the run
    /// deliberately left alone. Apply builds the file it writes through here
    /// and validate builds the file it predicts through here, which is what
    /// stops the two computing different content for the same host.
    fn push_config_section(&self, parameter: &KernelParameter, content: &mut String) {
        let name = parameter.kernel_parameter_name;
        match self {
            PlannedParameter::Excepted { reason, .. } => {
                content.push_str(&format!("# {name}: SKIPPED (exception: {reason})\n\n"));
            }
            PlannedParameter::Setting { target_value } => content.push_str(&format!(
                "# {}\n{name} = {target_value}\n\n",
                parameter.kernel_description
            )),
        }
    }
}

/// Builds a NIST 800-53 Rev 5 mapping.
///
/// There is no curated NIST catalogue to follow, and there is not meant to be:
/// `frameworks::curated_controls` returns `Some` only for CIS and ISO 27001,
/// and every other framework's catalogue is derived from plugin coverage at
/// report time. **The mapping written here is therefore the source**, not a
/// copy of one. This comment used to name a nist module in the compliance
/// crate's frameworks directory as the authority; no such module exists, and
/// pointing at one inverts which way the definition flows.
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

/// Builds a PCI-DSS v4.0 mapping.
///
/// Same as `nist` above: PCI-DSS ships no curated catalogue, so the id, title
/// and section written here are the definition rather than a restatement of
/// one. The pci module this used to cite does not exist either.
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

/// Every compliance mapping this plugin can emit, across all kernel parameters
/// it assesses. Aggregated into the engine's automated-coverage set.
pub fn coverage() -> Vec<ComplianceMapping> {
    KERNEL_PARAMS
        .iter()
        .flat_map(|p| get_compliance_mappings(p.kernel_parameter_name))
        .collect()
}

/// A parameter whose runtime value this scan could not read.
///
/// Carries [`get_compliance_mappings`] for that parameter alone, which is what
/// `ReportGenerator` reads to hold its controls at ManualReview instead of
/// passing them on an absent finding. `unchecked_persistence` in the sibling
/// module carries the whole plugin's [`coverage`] instead, and the difference is
/// deliberate: a `sysctl.d` file that cannot be read says nothing about any
/// parameter, while an unreadable `/proc/sys` entry says nothing about one.
///
/// Whether a privileged re-run would reach it is derived from the failure
/// rather than asserted. A read an LSM or DAC refused is exactly what root
/// fixes; a parameter this kernel does not carry is not, and telling an
/// operator to try again with sudo would send them after a fix that cannot
/// work.
fn unchecked_parameter(param_name: &str, reason: String, needs_privilege: bool) -> UncheckedCheck {
    // `needs_privilege` is derived from the failure rather than asserted, so
    // the two answers this plugin can give map cleanly onto the two the type
    // records. A read DAC or an LSM refused is exactly what root fixes; a
    // parameter this kernel does not carry is not, and no privilege will make
    // it appear.
    let blocker = match needs_privilege {
        true => UncheckedBlocker::Privilege,
        false => UncheckedBlocker::Environment,
    };
    UncheckedCheck {
        unchecked_check_id: format!("kernel_{}", param_name.replace('.', "_")),
        unchecked_title: format!("Kernel parameter {param_name}"),
        unchecked_category: FindingCategory::Kernel,
        unchecked_reason: reason,
        unchecked_blocker: blocker,
        unchecked_compliance: get_compliance_mappings(param_name),
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

    async fn scan(&self, ctx: &Context, config: &PluginConfig) -> Result<ScanResult> {
        let start_time = Instant::now();
        let mut findings = Vec::new();
        // Declared beside the findings rather than taken from the persistence
        // pass below, because a parameter this loop could not read has to reach
        // the same list: the report treats an unchecked control and a control
        // with no finding as opposite outcomes.
        let mut unchecked: Vec<UncheckedCheck> = Vec::new();

        for parameter in KERNEL_PARAMS {
            let param_name = parameter.kernel_parameter_name;
            let param_description = parameter.kernel_description;
            let severity = &parameter.kernel_severity;
            match self.read_sysctl(param_name, ctx).await {
                Ok(actual_value) => {
                    let target = resolved_target(parameter, config);
                    // Threshold, not equality: a host stricter than the
                    // baseline is already compliant. Comparing for equality
                    // flagged a host forbidding ptrace outright against a
                    // baseline of admin-only, and apply then wrote the
                    // baseline over it, at runtime and in the file that
                    // restores it at the next boot.
                    if parameter
                        .kernel_compare
                        .violated_by(&target, Some(&actual_value))
                    {
                        let policy_exception = config.exception_outcome(param_name, &actual_value);
                        findings.push(Finding {
                            finding_category: FindingCategory::Kernel,
                            finding_current_value: actual_value.clone(),
                            finding_description: param_description.to_string(),
                            finding_explanation: format!(
                                "This parameter should be set to '{}' for security hardening",
                                target,
                            ),
                            finding_id: format!("kernel_{}", param_name.replace('.', "_")),
                            finding_impact: format!(
                                "Insecure {} weakens system defences against exploitation",
                                param_name,
                            ),

                            finding_recommended_value: target.to_string(),
                            finding_remediation_steps: vec![format!(
                                "Set {} = {}",
                                param_name, target
                            )],
                            finding_severity: *severity,
                            finding_title: format!("Insecure value for {}", param_name),
                            finding_compliance: get_compliance_mappings(param_name),
                            finding_exception: policy_exception,
                            finding_exception_key: Some(param_name.to_string()),
                        });
                    }
                }
                Err(e) => {
                    // A value that was not read is not a value that was found
                    // compliant. This arm used to warn and move on, under a
                    // comment asserting the one cause it could not establish:
                    // `read_sysctl` is a `read_file` of /proc/sys, which fails
                    // for a kernel that does not carry the parameter, for a
                    // read an LSM refuses, for a /proc mounted `subset=pid` or
                    // not at all, and over SSH for any failed command or
                    // dropped channel. The parameter then left no finding and
                    // no unchecked entry, and `coverage()` below declares all
                    // eighteen assessed, so `ReportGenerator` passed the
                    // control on the absence of a finding. Its own comment
                    // states the invariant that broke: only a control the
                    // engine both assesses and could evaluate this run may
                    // pass on an absent finding.
                    //
                    // The entry carries this parameter's own mappings rather
                    // than the plugin's whole coverage, so one unreadable
                    // parameter moves its own controls to ManualReview and
                    // leaves the seventeen that were read alone. The sibling
                    // module does the same for a file it cannot read, with the
                    // whole coverage set, because a failure there is a failure
                    // for every parameter at once.
                    warn!("Cannot read {}: {}", param_name, e);
                    unchecked.push(unchecked_parameter(
                        param_name,
                        format!(
                            "could not read /proc/sys/{}: {e}",
                            persistence::procfs_key(param_name)
                        ),
                        message_indicates_permission_denied(&e.to_string()),
                    ));
                }
            }
        }

        // A value read out of /proc/sys says what the host runs now, not what
        // it will run after the next restart, and this plugin's whole claim to
        // persistence is one file that another package's can land on top of.
        // Measured on the debian container 2026-07-31: SYSCTL_HARDENER_CONF
        // holds `log_martians = 1` and the running kernel reads 0, because ufw
        // applies /etc/ufw/sysctl.conf from a unit ordered after
        // systemd-sysctl.service. Report-only, for the reason the module gives.
        let (overridden, boot_unchecked) = persistence::boot_persistence(ctx, config).await;
        findings.extend(overridden);
        unchecked.extend(boot_unchecked);

        Ok(ScanResult {
            scan_plugin_id: self.metadata().plugin_id,
            scan_success: true,
            scan_findings: findings,
            scan_unchecked: unchecked,
            scan_duration_us: start_time.elapsed().as_micros() as u64,
            scan_error: None,
            scan_skipped: None,
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
        let hardener_sysctl_path = Path::new(SYSCTL_HARDENER_CONF);

        // Nearly every distribution ships /etc/sysctl.d, but on the RHEL family
        // it belongs to systemd-udev, and a minimal install that never pulled
        // that package in has no such directory, which cost those hosts the
        // persistence half of every apply.
        //
        // Ahead of the checkpoint rather than next to the write it exists for.
        // The checkpoint captures SYSCTL_DROPIN_DIR, and an absent path is
        // stored with a zero mode, which a rollback reads as "remove this". A
        // directory created after that capture would turn a clean rollback into
        // a refusal. Created first, the checkpoint records it present and a
        // rollback restores it, leaving behind an empty standard directory.
        // The reason travels to the write site, which is where a failure to
        // create it is reported and where it stops the write.
        let sysctl_dir_error = crate::ensure_directory(ctx, SYSCTL_DROPIN_DIR).await;

        // Create checkpoint to capture sysctl config files before changes.
        // Include our hardener file if it exists.
        let sysctl_paths: Vec<&Path> = vec![
            Path::new("/etc/sysctl.conf"),
            Path::new(SYSCTL_DROPIN_DIR),
            hardener_sysctl_path,
        ];
        let checkpoint_id =
            crate::create_checkpoint_for_apply(ctx, "kernel-hardening-pre-apply", &sysctl_paths)
                .await?;

        apply_changes.extend(crate::checkpoint_change(&checkpoint_id));

        // Build sysctl.d config file content for persistence.
        let mut sysctl_config_content = String::from(SYSCTL_CONFIG_HEADER);

        // Apply each parameter to runtime AND build config file content.
        // State-aware: a parameter already at its target is left untouched
        // and counted, so re-running apply on a compliant host is a no-op.
        let mut runtime_changed = false;
        let mut compliant_count = 0usize;

        for parameter in KERNEL_PARAMS {
            let param_name = parameter.kernel_parameter_name;
            let param_description = parameter.kernel_description;
            // Read once, decide once. The exception check, the clamp, the block
            // written into the persistent file and the runtime write all rest
            // on this single observation, because two reads of the same
            // parameter can disagree and the file would then be built from a
            // different reading than the one this run acted on.
            let observed = self.read_sysctl(param_name, ctx).await.ok();
            let planned = plan_parameter(parameter, config, observed.as_deref());
            planned.push_config_section(parameter, &mut sysctl_config_content);

            let target_value = match planned {
                PlannedParameter::Excepted { reason, .. } => {
                    info!("Skipping {} (exception: {})", param_name, reason);
                    apply_changes.push(Change {
                        change_description: format!(
                            "{}: skipped (exception: {})",
                            param_description, reason
                        ),
                        change_type: ChangeType::Skipped,
                        change_success: true,
                        change_error: None,
                    });
                    continue;
                }
                PlannedParameter::Setting { target_value } => target_value,
            };

            let path = format!("/proc/sys/{}", persistence::procfs_key(param_name));

            // Already at least as strict as the target: no runtime write.
            if !parameter
                .kernel_compare
                .violated_by(&target_value, observed.as_deref())
            {
                compliant_count += 1;
                continue;
            }

            // Apply immediately to runtime.
            match ctx
                .executor()
                .write_file(Path::new(&path), &target_value)
                .await
            {
                Ok(_) => {
                    runtime_changed = true;
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

        if compliant_count > 0 {
            apply_changes.push(Change {
                change_description: format!(
                    "{} sysctl(s) already compliant - unchanged",
                    compliant_count
                ),
                change_type: ChangeType::Skipped,
                change_success: true,
                change_error: None,
            });
        }

        // Write persistent config file so changes survive reboot AND rollback
        // works. The file is the boot-persistence guarantee: rewrite it only
        // when a parameter actually changed or its content no longer matches
        // the desired settings.
        let existing_config = ctx.executor().read_file(hardener_sysctl_path).await.ok();
        if runtime_changed || existing_config.as_deref() != Some(sysctl_config_content.as_str()) {
            // A parent that could not be created is reported with its own
            // reason rather than left to surface as an unexplained write
            // failure.
            let write_outcome = match sysctl_dir_error {
                Some(reason) => Err(reason),
                None => ctx
                    .executor()
                    .write_file(hardener_sysctl_path, &sysctl_config_content)
                    .await
                    .map_err(|e| e.to_string()),
            };
            match write_outcome {
                Ok(()) => {
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
                        change_error: Some(e.clone()),
                    });
                    warn!("Failed to create {}: {}", hardener_sysctl_path.display(), e);
                }
            }
        } else {
            apply_changes.push(Change {
                change_description: "Persistent sysctl config already up to date".to_string(),
                change_type: ChangeType::Skipped,
                change_success: true,
                change_error: None,
            });
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

    fn reloads_for_path(&self, path: &Path) -> bool {
        path == Path::new("/etc/sysctl.conf") || path.starts_with(SYSCTL_DROPIN_DIR)
    }

    async fn reload_after_rollback(&self, ctx: &Context) -> Result<Option<String>> {
        let reload_result = ctx
            .executor()
            .execute_command("sysctl", &["--system"])
            .await?;

        // Deliberately not turned into an Err on a non-zero exit, unlike
        // services' daemon-reload. A read-only parameter under a container
        // runtime's namespacing makes `sysctl --system` exit non-zero on an
        // otherwise unremarkable host, so failing rollback on it would turn
        // "the rollback worked" into "the rollback exited 1" almost
        // everywhere this runs. The warning below is the honest report of
        // that routine case; an outright failure to reload would need a
        // sharper signal than this exit code gives.
        if reload_result.success() {
            info!("Kernel parameters reloaded successfully");
        } else {
            warn!(
                "sysctl --system returned non-zero: {}",
                reload_result.stderr
            );
        }

        Ok(Some("sysctl --system".to_string()))
    }

    async fn divergences_after_rollback(
        &self,
        ctx: &Context,
        restored: &[std::path::PathBuf],
    ) -> Vec<hardener_types::RollbackDivergence> {
        // The gate this replaces used to live in the dispatch (#142). Same
        // predicate, one level down, so behaviour is unchanged: without it a
        // rollback that restored only sshd_config would run the sysctl probe
        // and report every hardened parameter as diverged, which is a false
        // alarm rather than a missing one.
        if !restored.iter().any(|path| self.reloads_for_path(path)) {
            return Vec::new();
        }
        divergence::sysctl_divergences(ctx).await
    }

    /// Validates that kernel parameters can be applied (dry-run).
    ///
    /// Checks if sysctl parameters exist and are writable without actually
    /// modifying them. State-aware: only parameters whose current value
    /// differs from the target are listed as pending; parameters already at
    /// their target are tallied in `validation_report_compliant_count` rather
    /// than listed, so the estimated-change list holds only real pending
    /// changes and a host needing nothing reports zero.
    ///
    /// The persistent file is the other half of what apply does, and it is
    /// previewed on the same condition apply writes it on. A host with every
    /// parameter compliant is not therefore a host with nothing pending: if
    /// the file is absent or holds something else, writing it is the whole of
    /// what the run will do.
    ///
    /// # Arguments
    /// * `config` - Plugin configuration with directive overrides and policy exceptions
    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport> {
        let mut issues = Vec::new();
        let mut estimated_changes = Vec::new();
        // Excepted settings are recorded rather than dropped: a preview that
        // omits them shows a documented deviation as nothing at all.
        let mut exceptions: Vec<String> = Vec::new();
        let mut compliant_count = 0usize;
        // The persistent file as this run would write it, built through the
        // same planner the apply builds it with, so the two cannot compute
        // different content for the same host.
        let mut desired_config = String::from(SYSCTL_CONFIG_HEADER);
        let mut runtime_will_change = false;

        for parameter in KERNEL_PARAMS {
            let param_name = parameter.kernel_parameter_name;
            let observed = self.read_sysctl(param_name, ctx).await.ok();
            let planned = plan_parameter(parameter, config, observed.as_deref());
            // Ahead of every branch below, because apply writes a block for
            // every parameter and consults none of the metadata this reads.
            planned.push_config_section(parameter, &mut desired_config);

            let target_value = match planned {
                PlannedParameter::Excepted {
                    observed: value,
                    reason,
                } => {
                    exceptions.push(hardener_common::types::exception_preview_line(
                        param_name, value, reason,
                    ));
                    continue;
                }
                PlannedParameter::Setting { target_value } => target_value,
            };

            let path = format!("/proc/sys/{}", persistence::procfs_key(param_name));

            // Check if parameter exists, is writable, and differs from target.
            //
            // The three answers were wired to the wrong two messages. A
            // positively confirmed absence arrives as `Ok(exists: false)` with a
            // zero mode, and a zero mode has no write bit, so it fell into the
            // read-only arm and a parameter this kernel does not carry was
            // announced "is read-only" at High, which blocks the dry run.
            // Meanwhile `Err`, which the trait contract defines as "could not be
            // determined" and explicitly forbids reading as absence, announced
            // "does not exist on this kernel" at Low, which does not block. The
            // missing parameter failed the run for the wrong reason and the
            // unreadable one passed it.
            //
            // Absence is therefore answered first, before the mode is consulted
            // at all.
            match ctx.executor().file_metadata(Path::new(&path)).await {
                Ok(metadata) if !metadata.exists => {
                    issues.push(ValidationIssue {
                        validation_issue_severity: Severity::Low,
                        validation_issue_message: format!(
                            "{} does not exist on this kernel",
                            param_name
                        ),
                        validation_issue_config_key: Some(param_name.to_string()),
                    });
                }
                // Reachable now only for a parameter that is present and whose
                // inode carries no write bit. It still cannot see a read-only
                // MOUNT, which is 4.1 item 3: every file under /proc/sys is 0644
                // whether or not the mount allows writing.
                Ok(metadata) if metadata.mode & 0o200 == 0 => {
                    issues.push(ValidationIssue {
                        validation_issue_severity: Severity::High,
                        validation_issue_message: format!("{} is read-only", param_name),
                        validation_issue_config_key: Some(param_name.to_string()),
                    });
                }
                // Unset never reaches here: a value the comparison cannot read
                // counts as violating, which is the arm below.
                Ok(_)
                    if !parameter
                        .kernel_compare
                        .violated_by(&target_value, observed.as_deref()) =>
                {
                    compliant_count += 1
                }
                // The mount is asked about only here, at the one point where
                // this preview is about to promise a write. A compliant
                // parameter needs no write and an absent one has nowhere to
                // put it, so probing those would spend a subprocess to learn
                // something nothing acts on.
                Ok(_) if mount_is_read_only(ctx, &path).await == Some(true) => {
                    issues.push(ValidationIssue {
                        validation_issue_severity: Severity::High,
                        validation_issue_message: format!(
                            "{param_name} cannot be set: {path} is on a read-only mount, so \
                             apply would fail here however it is run"
                        ),
                        validation_issue_config_key: Some(param_name.to_string()),
                    });
                }
                Ok(_) => {
                    runtime_will_change = true;
                    estimated_changes.push(match observed.as_deref() {
                        Some(current) => {
                            format!("{param_name} will change: {current} -> {target_value}")
                        }
                        None => format!("{param_name} will be set to {target_value}"),
                    });
                }
                Err(e) => {
                    // Fail closed, as the contract requires: the probe said
                    // nothing either way, so this preview cannot describe what
                    // the apply would do here, and High is what
                    // `has_blocking_issue` counts.
                    issues.push(ValidationIssue {
                        validation_issue_severity: Severity::High,
                        validation_issue_message: format!(
                            "{param_name}: could not determine whether the parameter exists \
                             ({e}), so this preview cannot say what apply would do to it"
                        ),
                        validation_issue_config_key: Some(param_name.to_string()),
                    });
                }
            }
        }

        // Apply writes the persistent file when a parameter changed at runtime
        // OR when the file does not already hold what this run would write, so
        // the preview has to answer the same question or it is a line short of
        // the run it previews. rhel's containers reach the second half alone:
        // every parameter arrives compliant, nothing changes at runtime, and
        // the file is absent, which is how the write went unpreviewed until the
        // differential suite gained its preview/apply oracle.
        let existing_config = ctx
            .executor()
            .read_file(Path::new(SYSCTL_HARDENER_CONF))
            .await
            .ok();
        if runtime_will_change || existing_config.as_deref() != Some(desired_config.as_str()) {
            // The sentence apply prints, in the tense a preview uses. Apply
            // names creating the file and updating it alike, so neither does
            // this draw a distinction it does not make.
            estimated_changes.push("Create persistent sysctl config".to_string());
        }

        Ok(ValidationReport {
            validation_report_plugin_id: self.metadata().plugin_id,
            validation_report_is_valid: issues
                .iter()
                .all(|i| i.validation_issue_severity != Severity::High),
            validation_report_issues: issues,
            validation_report_estimated_changes: estimated_changes,
            validation_report_compliant_count: compliant_count,
            validation_report_exceptions: exceptions,
        })
    }
}

#[cfg(test)]
mod tests;
