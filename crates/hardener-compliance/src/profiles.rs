//! Report-time compliance-profile identifier translation.
//!
//! Plugins always emit canonical control identifiers (RHEL 8 baseline for
//! STIG, distribution-independent numbering for CIS) — that scheme is the
//! project's internal source of truth. When a non-generic profile is active
//! the report generator passes coverage, curated catalogue, and every
//! finding's mapping list through [`translate`], so both sides of each match
//! render the profile's own identifiers. A canonical identifier without a
//! sourced counterpart drops from the profiled report — honest absence, never
//! a guessed ID.

use hardener_common::types::{ComplianceFramework, ComplianceMapping, ComplianceProfile};
use hardener_distro::{Distribution, DistroFamily};

/// One sourced translation row: canonical id → (target id, target title,
/// section override). `None` keeps the canonical mapping's section. Repeat a
/// canonical id across rows to expand one control into many.
type Row = (
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
);

/// DISA RHEL 10 STIG V1R1 counterparts, keyed by canonical RHEL 8 rule id.
/// Every row cites its verified public source; unsourced rules get no row.
///
/// Where one code arm checks two sysctls the canonical id expands to both
/// RHEL 10 twin rules — a Fail on either fails both, erring only towards
/// false-fail. The ssh rows cover the sshd server rules alone; the client
/// twins (RHEL-10-300030/300050) are out of scope because the plugin checks
/// sshd only. Every row was additionally verified on its stigviewer.com
/// per-finding page (stigs/red_hat_enterprise_linux_10/2026-05-14/finding/<V-ID>).
const RHEL10_STIG: &[Row] = &[
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281315.
    (
        "RHEL-08-010430",
        "RHEL-10-701130",
        "RHEL 10 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281308.
    (
        "RHEL-08-040283",
        "RHEL-10-701060",
        "RHEL 10 must restrict exposed kernel pointer address access.",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281305.
    (
        "RHEL-08-010375",
        "RHEL-10-701030",
        "RHEL 10 must restrict access to the kernel message buffer.",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281316.
    (
        "RHEL-08-040282",
        "RHEL-10-701140",
        "RHEL 10 must restrict usage of ptrace to descendant processes.",
        None,
    ),
    // Twin pair: the canonical arm checks fs.protected_hardlinks AND
    // fs.protected_symlinks; RHEL 10 keeps them as separate rules.
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281309.
    (
        "RHEL-08-010374",
        "RHEL-10-701070",
        "RHEL 10 must enable kernel parameters to enforce discretionary access control (DAC) on hardlinks.",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281310.
    (
        "RHEL-08-010374",
        "RHEL-10-701080",
        "RHEL 10 must enable kernel parameters to enforce discretionary access control (DAC) on symlinks.",
        None,
    ),
    // Twin pair: the canonical arm checks net.ipv4.conf.all.rp_filter AND .default.
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281345.
    (
        "RHEL-08-040285",
        "RHEL-10-800130",
        "RHEL 10 must use reverse path filtering on all Internet Protocol version 4 (IPv4) interfaces.",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281348.
    (
        "RHEL-08-040285",
        "RHEL-10-800160",
        "RHEL 10 must use a reverse-path filter for Internet Protocol version 4 (IPv4) network traffic when possible by default.",
        None,
    ),
    // Twin pair: the canonical arm checks net.ipv4.conf.all.accept_source_route AND .default.
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281342.
    (
        "RHEL-08-040239",
        "RHEL-10-800100",
        "RHEL 10 must not forward Internet Protocol version 4 (IPv4) source-routed packets.",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281347.
    (
        "RHEL-08-040239",
        "RHEL-10-800150",
        "RHEL 10 must not forward Internet Protocol version 4 (IPv4) source-routed packets by default.",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281181.
    (
        "RHEL-08-020230",
        "RHEL-10-600220",
        "RHEL 10 must enforce that passwords be created with a minimum of 15 characters.",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281190.
    (
        "RHEL-08-020130",
        "RHEL-10-600310",
        "RHEL 10 must enforce password complexity by requiring that at least one numeric character be used.",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281184.
    (
        "RHEL-08-020110",
        "RHEL-10-600250",
        "RHEL 10 must enforce password complexity by requiring that at least one uppercase character be used.",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281183.
    (
        "RHEL-08-020120",
        "RHEL-10-600240",
        "RHEL 10 must enforce password complexity by requiring that at least one lowercase character be used.",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281182.
    (
        "RHEL-08-020280",
        "RHEL-10-600230",
        "RHEL 10 must enforce password complexity by requiring at least one special character to be used.",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281188.
    (
        "RHEL-08-020150",
        "RHEL-10-600290",
        "RHEL 10 must require that the maximum number of repeating characters be limited to three when passwords are changed.",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281194.
    (
        "RHEL-08-020011",
        "RHEL-10-600410",
        "RHEL 10 must automatically lock an account when three unsuccessful login attempts occur.",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281169.
    (
        "RHEL-08-020200",
        "RHEL-10-600100",
        "RHEL 10 must, for new users or password changes, have a 60-day maximum password lifetime restriction for user account passwords in \"/etc/login.defs\".",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281180.
    (
        "RHEL-08-020190",
        "RHEL-10-600210",
        "RHEL 10 must enforce a 24-hours minimum password lifetime restriction for passwords for new users or password changes in \"/etc/login.defs\".",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-280956.
    (
        "RHEL-08-040101",
        "RHEL-10-200531",
        "RHEL 10 must have the \"firewalld\" service set to active.",
        None,
    ),
    // sshd server crypto rules, keyed on the corrected RHEL 8 V2R7 canonicals.
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281011.
    (
        "RHEL-08-010291",
        "RHEL-10-300040",
        "RHEL 10 must be configured so that Secure Shell (SSH) servers use only DOD-approved encryption ciphers employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281013.
    (
        "RHEL-08-010290",
        "RHEL-10-300060",
        "RHEL 10 must be configured so that Secure Shell (SSH) servers use only DOD-approved Message Authentication Codes (MACs) employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.",
        None,
    ),
    // Audit and MAC rows keep their OL08-00-* canonicals exactly as the
    // plugins emit them (the SSG references supplied those spellings).
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-280993.
    (
        "OL08-00-030180",
        "RHEL-10-200660",
        "RHEL 10 must have the \"audit\" package installed.",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-280994.
    (
        "OL08-00-030181",
        "RHEL-10-200661",
        "RHEL 10 must enable the audit service.",
        None,
    ),
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281251.
    (
        "OL08-00-010170",
        "RHEL-10-700420",
        "RHEL 10 must use a Linux Security Module configured to enforce limits on system services.",
        None,
    ),
    // sshd KexAlgorithms: documented drop, no row. KexAlgorithms is verifiably
    // absent from all 434 V1R1 rules — subsumed by RHEL-10-300010 (FIPS
    // systemwide cryptographic policy), whose check target differs from what
    // the plugin checks, so no mapping is claimed. Since the RHEL 8 V2R7 V-ID
    // fix the Kex check emits no canonical STIG id at all.
];

/// CIS RHEL 10 Benchmark v1.0.1 renumbering, keyed by canonical CIS section.
/// Every row cites its verified public source; unsourced sections get no row.
///
/// Source for every row: ComplianceAsCode
/// products/rhel10/controls/cis_rhel10.yml @ db939fa (declares v1.0.1;
/// authoritative-secondary — the CIS PDF sits behind WorkBench login).
/// Sections are reused across schemes with unrelated meanings, so this is a
/// keyed lookup, never an in-place renumber. Verified drops (2.1.1 xinetd,
/// 5.2.4 SSH Protocol 2) are documented inline and get no row.
const RHEL10_CIS: &[Row] = &[
    (
        "1.5.1",
        "1.5.8",
        "Ensure kernel.randomize_va_space is configured",
        None,
    ),
    (
        "1.5.2",
        "1.5.7",
        "Ensure kernel.yama.ptrace_scope is configured",
        None,
    ),
    // Old umbrella "core dumps restricted" control split in v1.0.1; 1.5.4
    // (fs.suid_dumpable) matches what the plugin actually checks.
    (
        "1.5.3",
        "1.5.4",
        "Ensure fs.suid_dumpable is configured",
        None,
    ),
    // The old benchmark reused 1.5.4 for BOTH kptr_restrict and
    // dmesg_restrict checks; v1.0.1 gives each sysctl its own control, so the
    // single canonical id expands to both.
    (
        "1.5.4",
        "1.5.5",
        "Ensure kernel.dmesg_restrict is configured",
        None,
    ),
    (
        "1.5.4",
        "1.5.6",
        "Ensure kernel.kptr_restrict is configured",
        None,
    ),
    ("1.6.1.1", "1.3.1.1", "Ensure SELinux is installed", None),
    (
        "1.6.1.2",
        "1.3.1.2",
        "Ensure SELinux is not disabled in bootloader configuration",
        None,
    ),
    (
        "1.6.1.3",
        "1.3.1.3",
        "Ensure SELinux policy is configured",
        None,
    ),
    // 1.3.1.5 (enforcing) is the L2 variant; sibling 1.3.1.4 (not disabled)
    // is L1 and does not match the plugin's enforcing check.
    (
        "1.6.1.4",
        "1.3.1.5",
        "Ensure the SELinux mode is enforcing",
        None,
    ),
    // 2.1.1 (xinetd not installed): documented drop, no row — xinetd no
    // longer exists as a CIS RHEL 10 control (zero matches in the
    // 329-control v1.0.1 tree).
    (
        "2.2.2",
        "2.1.20",
        "Ensure X window server services are not in use",
        None,
    ),
    (
        "2.2.3",
        "2.1.2",
        "Ensure avahi daemon services are not in use",
        None,
    ),
    (
        "2.2.4",
        "2.1.10",
        "Ensure print server services are not in use",
        None,
    ),
    // Network sysctl pairs: v1.0.1 keeps one control per sysctl (.all and
    // .default), so each canonical expands to both members.
    (
        "3.2.1",
        "3.3.1.14",
        "Ensure net.ipv4.conf.all.accept_source_route is configured",
        None,
    ),
    (
        "3.2.1",
        "3.3.1.15",
        "Ensure net.ipv4.conf.default.accept_source_route is configured",
        None,
    ),
    (
        "3.2.2",
        "3.3.1.8",
        "Ensure net.ipv4.conf.all.accept_redirects is configured",
        None,
    ),
    (
        "3.2.2",
        "3.3.1.9",
        "Ensure net.ipv4.conf.default.accept_redirects is configured",
        None,
    ),
    (
        "3.2.3",
        "3.3.1.10",
        "Ensure net.ipv4.conf.all.secure_redirects is configured",
        None,
    ),
    (
        "3.2.3",
        "3.3.1.11",
        "Ensure net.ipv4.conf.default.secure_redirects is configured",
        None,
    ),
    (
        "3.2.4",
        "3.3.1.16",
        "Ensure net.ipv4.conf.all.log_martians is configured",
        None,
    ),
    (
        "3.2.4",
        "3.3.1.17",
        "Ensure net.ipv4.conf.default.log_martians is configured",
        None,
    ),
    (
        "3.2.7",
        "3.3.1.12",
        "Ensure net.ipv4.conf.all.rp_filter is configured",
        None,
    ),
    (
        "3.2.7",
        "3.3.1.13",
        "Ensure net.ipv4.conf.default.rp_filter is configured",
        None,
    ),
    (
        "3.2.8",
        "3.3.1.18",
        "Ensure net.ipv4.tcp_syncookies is configured",
        None,
    ),
    ("3.4.1.1", "4.1.1", "Ensure firewalld is installed", None),
    (
        "3.4.1.2",
        "4.1.3",
        "Ensure firewalld.service is configured",
        None,
    ),
    (
        "4.1.1.1",
        "6.3.1.1",
        "Ensure auditd packages are installed",
        None,
    ),
    (
        "4.1.1.2",
        "6.3.1.4",
        "Ensure auditd service is enabled and active",
        None,
    ),
    (
        "4.1.2.1",
        "6.3.2.1",
        "Ensure audit log storage size is configured",
        None,
    ),
    // Old-scheme 5.1.8 is cron; job schedulers moved to chapter 2 in v1.0.1.
    // Unrelated to new-scheme 5.1.8 (sshd DisableForwarding, target of 5.2.6
    // below) — the collision is inert because lookup is keyed on the
    // canonical id, never an in-place renumber.
    (
        "5.1.8",
        "2.4.1.9",
        "Ensure access to crontab is configured",
        None,
    ),
    (
        "5.2.1",
        "5.1.1",
        "Ensure access to /etc/ssh/sshd_config is configured",
        None,
    ),
    // 5.2.4 (SSH Protocol 2): documented drop, no row — the Protocol
    // directive is gone from OpenSSH >= 7.6 and the control does not exist
    // in CIS RHEL 10 (zero matches in the v1.0.1 tree).
    (
        "5.2.6",
        "5.1.8",
        "Ensure sshd DisableForwarding is enabled",
        None,
    ),
    (
        "5.2.7",
        "5.1.16",
        "Ensure sshd MaxAuthTries is configured",
        None,
    ),
    (
        "5.2.10",
        "5.1.20",
        "Ensure sshd PermitRootLogin is disabled",
        None,
    ),
    (
        "5.2.11",
        "5.1.19",
        "Ensure sshd PermitEmptyPasswords is disabled",
        None,
    ),
    (
        "5.2.13",
        "5.1.7",
        "Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured",
        None,
    ),
    (
        "5.2.14",
        "5.1.12",
        "Ensure sshd KexAlgorithms is configured",
        None,
    ),
    (
        "5.2.15",
        "5.1.6",
        "Ensure sshd Ciphers are configured",
        None,
    ),
    ("5.2.16", "5.1.15", "Ensure sshd MACs are configured", None),
    // pwquality split three ways in v1.0.1: length, complexity, repeats.
    (
        "5.3.1",
        "5.3.2.2.2",
        "Ensure password length is configured",
        None,
    ),
    // 5.3.2.2.3 is status Manual in CIS v1.0.1 — the benchmark treats the
    // credit settings as one manual complexity control; the per-credit
    // plugin checks all map here.
    (
        "5.3.1",
        "5.3.2.2.3",
        "Ensure password complexity is configured",
        None,
    ),
    (
        "5.3.1",
        "5.3.2.2.4",
        "Ensure password same consecutive characters is configured",
        None,
    ),
    // faillock split: deny → 5.3.2.1.1, unlock_time → 5.3.2.1.2.
    (
        "5.3.2",
        "5.3.2.1.1",
        "Ensure password failed attempts lockout is configured",
        None,
    ),
    (
        "5.3.2",
        "5.3.2.1.2",
        "Ensure password unlock time is configured",
        None,
    ),
    (
        "5.3.3",
        "5.3.2.3.1",
        "Ensure password history remember is configured",
        None,
    ),
    // The 5.4.1.x password-ageing block keeps its numbers in v1.0.1 — the rows
    // must exist anyway, or the keyed lookup would wrongly DROP them. 5.4.1.3
    // tied by SSG rule identity (accounts_password_warn_age_login_defs appears
    // in that section and nowhere else among the 329 controls).
    (
        "5.4.1.1",
        "5.4.1.1",
        "Ensure password expiration is configured",
        None,
    ),
    (
        "5.4.1.2",
        "5.4.1.2",
        "Ensure minimum password days is configured",
        None,
    ),
    (
        "5.4.1.3",
        "5.4.1.3",
        "Ensure password expiration warning days is configured",
        None,
    ),
    (
        "6.1.2",
        "7.1.1",
        "Ensure access to /etc/passwd is configured",
        None,
    ),
    (
        "6.1.3",
        "7.1.5",
        "Ensure access to /etc/shadow is configured",
        None,
    ),
    (
        "6.1.4",
        "7.1.3",
        "Ensure access to /etc/group is configured",
        None,
    ),
    (
        "6.1.5",
        "7.1.7",
        "Ensure access to /etc/gshadow is configured",
        None,
    ),
];

/// Translates one canonical mapping into the active profile's identifiers.
///
/// Returns zero, one, or many mappings: identity under `Generic` and for
/// profile-invariant frameworks; a sourced rewrite for STIG/CIS under
/// `Rhel10`; empty when the profile's benchmark has no counterpart.
pub fn translate(
    profile: ComplianceProfile,
    mapping: &ComplianceMapping,
) -> Vec<ComplianceMapping> {
    let rows = match (profile, mapping.compliance_framework) {
        (ComplianceProfile::Rhel10, ComplianceFramework::STIG) => RHEL10_STIG,
        (ComplianceProfile::Rhel10, ComplianceFramework::CIS) => RHEL10_CIS,
        _ => return vec![mapping.clone()],
    };
    rows.iter()
        .filter(|(canonical, ..)| *canonical == mapping.compliance_control_id)
        .map(|(_, id, title, section)| ComplianceMapping {
            compliance_framework: mapping.compliance_framework,
            compliance_control_id: (*id).to_string(),
            compliance_control_title: (*title).to_string(),
            compliance_section: section
                .map(str::to_string)
                .or_else(|| mapping.compliance_section.clone()),
        })
        .collect()
}

/// Translates a whole mapping list, flattening drops and expansions.
pub fn translate_all(
    profile: ComplianceProfile,
    mappings: &[ComplianceMapping],
) -> Vec<ComplianceMapping> {
    mappings
        .iter()
        .flat_map(|mapping| translate(profile, mapping))
        .collect()
}

/// Human-readable identifier-scheme label for a report heading, when the
/// (profile, framework) pair warrants one. The generic STIG label names its
/// RHEL 8 baseline honestly instead of implying universality.
pub fn profile_label(
    profile: ComplianceProfile,
    framework: ComplianceFramework,
) -> Option<&'static str> {
    match (profile, framework) {
        (ComplianceProfile::Rhel10, ComplianceFramework::STIG) => Some("DISA RHEL 10 STIG V1R1"),
        (ComplianceProfile::Rhel10, ComplianceFramework::CIS) => {
            Some("CIS RHEL 10 Benchmark v1.0.1")
        }
        (ComplianceProfile::Generic, ComplianceFramework::STIG) => Some("RHEL 8 baseline IDs"),
        _ => None,
    }
}

/// Resolves the report profile for a detected distribution.
///
/// Only RHEL-family major 10 gets [`ComplianceProfile::Rhel10`]; every other
/// family, major, or unparseable version stays [`ComplianceProfile::Generic`],
/// so resolution can never fail.
pub fn resolve_profile(distribution: &Distribution) -> ComplianceProfile {
    if distribution.distro_family == DistroFamily::RedHat
        && distribution.version_major() == Some(10)
    {
        ComplianceProfile::Rhel10
    } else {
        ComplianceProfile::Generic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(framework: ComplianceFramework, id: &str) -> ComplianceMapping {
        ComplianceMapping {
            compliance_framework: framework,
            compliance_control_id: id.to_string(),
            compliance_control_title: format!("Control {id}"),
            compliance_section: Some("Test Section".to_string()),
        }
    }

    fn distro(family: DistroFamily, name: &str, version: &str) -> Distribution {
        Distribution {
            distro_family: family,
            distro_name: name.to_string(),
            distro_version: version.to_string(),
            distro_codename: None,
        }
    }

    #[test]
    fn resolve_profile_matrix() {
        let cases = [
            (
                DistroFamily::RedHat,
                "rocky",
                "10",
                ComplianceProfile::Rhel10,
            ),
            (
                DistroFamily::RedHat,
                "rhel",
                "10.1",
                ComplianceProfile::Rhel10,
            ),
            (
                DistroFamily::RedHat,
                "rhel",
                "9.4",
                ComplianceProfile::Generic,
            ),
            (
                DistroFamily::Debian,
                "ubuntu",
                "24.04",
                ComplianceProfile::Generic,
            ),
            (
                DistroFamily::Arch,
                "arch",
                "rolling",
                ComplianceProfile::Generic,
            ),
        ];
        for (family, name, version, expected) in cases {
            assert_eq!(
                resolve_profile(&distro(family, name, version)),
                expected,
                "{name} {version}"
            );
        }
    }

    #[test]
    fn generic_profile_is_identity() {
        let stig = mapping(ComplianceFramework::STIG, "RHEL-08-010430");
        assert_eq!(
            translate(ComplianceProfile::Generic, &stig),
            vec![stig.clone()]
        );
    }

    #[test]
    fn profile_invariant_framework_is_identity_under_rhel10() {
        let nist = mapping(ComplianceFramework::NIST, "SI-16");
        assert_eq!(
            translate(ComplianceProfile::Rhel10, &nist),
            vec![nist.clone()]
        );
    }

    #[test]
    fn soc2_is_profile_invariant_under_rhel10() {
        // SOC 2 criteria are OS-independent: no profile may ever rewrite them.
        let soc2 = mapping(ComplianceFramework::SOC2, "CC6.1");
        assert_eq!(
            translate(ComplianceProfile::Rhel10, &soc2),
            vec![soc2.clone()]
        );
    }

    #[test]
    fn unsourced_stig_id_drops_under_rhel10() {
        let unknown = mapping(ComplianceFramework::STIG, "RHEL-08-999999");
        assert!(translate(ComplianceProfile::Rhel10, &unknown).is_empty());
    }

    #[test]
    fn seeded_stig_row_translates_id_and_title() {
        let aslr = mapping(ComplianceFramework::STIG, "RHEL-08-010430");
        let translated = translate(ComplianceProfile::Rhel10, &aslr);

        assert_eq!(translated.len(), 1);
        assert_eq!(translated[0].compliance_control_id, "RHEL-10-701130");
        assert!(
            translated[0]
                .compliance_control_title
                .contains("address space layout randomization")
        );
        assert_eq!(
            translated[0].compliance_framework,
            ComplianceFramework::STIG
        );
        // No section override in this row: the canonical section rides along.
        assert_eq!(translated[0].compliance_section, aslr.compliance_section);
    }

    #[test]
    fn seeded_cis_row_renumbers() {
        let aslr = mapping(ComplianceFramework::CIS, "1.5.1");
        let translated = translate(ComplianceProfile::Rhel10, &aslr);

        assert_eq!(translated.len(), 1);
        assert_eq!(translated[0].compliance_control_id, "1.5.8");
        assert_eq!(
            translated[0].compliance_control_title,
            "Ensure kernel.randomize_va_space is configured"
        );
    }

    /// Under `Rhel10` the curated CIS catalogue must come out entirely in the
    /// v1.0.1 numbering: every translated id is some table row's target. Ids
    /// such as 1.5.4, 5.1.8, 5.4.1.1 and 5.4.1.2 exist in both schemes and
    /// are legitimate output precisely because they are targets; anything
    /// else old-scheme is a leftover. The two documented drops must vanish
    /// rather than leak through untranslated.
    #[test]
    fn rhel10_curated_cis_catalogue_translates_onto_the_new_scheme_only() {
        let targets: std::collections::HashSet<&str> =
            RHEL10_CIS.iter().map(|(_, target, ..)| *target).collect();
        let translated = translate_all(
            ComplianceProfile::Rhel10,
            &crate::frameworks::cis::get_controls(),
        );

        assert!(!translated.is_empty());
        for mapping in &translated {
            assert!(
                targets.contains(mapping.compliance_control_id.as_str()),
                "old-scheme leftover in the translated catalogue: {}",
                mapping.compliance_control_id
            );
        }
        assert!(
            translated
                .iter()
                .any(|m| m.compliance_control_id == "1.5.8")
        );
        for dropped in ["2.1.1", "5.2.4"] {
            assert!(
                translated
                    .iter()
                    .all(|m| m.compliance_control_id != dropped),
                "dropped control {dropped} must not survive translation"
            );
        }
    }

    /// Canonical ids plugins emit that are allowed to translate to nothing.
    ///
    /// - CIS 2.1.1 (xinetd): verified absent from the 329-control v1.0.1
    ///   tree; the services plugin still emits it, so it may drop.
    ///
    /// CIS 5.2.4 (SSH Protocol 2) is verified gone too but lives only in the
    /// curated catalogue — no plugin emits it, so it needs no entry. STIG
    /// needs none either: the sshd KexAlgorithms check lost its STIG mapping
    /// with the RHEL 8 V2R7 V-ID fix, so every plugin-emitted STIG id has a
    /// sourced row.
    const DOCUMENTED_DROPS: &[(ComplianceFramework, &str)] = &[(ComplianceFramework::CIS, "2.1.1")];

    /// Pins the tables against the live plugin surface: every STIG or CIS
    /// mapping any plugin can emit either translates under `Rhel10` or is an
    /// explicitly documented drop — never a silent disappearance.
    #[test]
    fn every_plugin_stig_or_cis_mapping_translates_or_is_a_documented_drop() {
        let coverage = hardener_plugins::compliance_coverage();
        assert!(!coverage.is_empty(), "plugin coverage must not be empty");

        for mapping in coverage.iter().filter(|m| {
            matches!(
                m.compliance_framework,
                ComplianceFramework::STIG | ComplianceFramework::CIS
            )
        }) {
            let translated = translate(ComplianceProfile::Rhel10, mapping);
            let documented = DOCUMENTED_DROPS.contains(&(
                mapping.compliance_framework,
                mapping.compliance_control_id.as_str(),
            ));
            assert!(
                !translated.is_empty() || documented,
                "{:?} {} translates to nothing and is not a documented drop",
                mapping.compliance_framework,
                mapping.compliance_control_id
            );
            assert!(
                !documented || translated.is_empty(),
                "{:?} {} is listed as a documented drop yet has a table row",
                mapping.compliance_framework,
                mapping.compliance_control_id
            );
        }
    }

    #[test]
    fn stig_rows_are_well_formed() {
        for (canonical, target, title, _) in RHEL10_STIG {
            let digits = target
                .strip_prefix("RHEL-10-")
                .unwrap_or_else(|| panic!("{target} lacks the RHEL-10- prefix"));
            assert!(
                digits.len() == 6 && digits.bytes().all(|b| b.is_ascii_digit()),
                "{target} must match RHEL-10- followed by six digits"
            );
            assert!(!canonical.is_empty(), "empty canonical id for {target}");
            assert!(!title.is_empty(), "empty title for {target}");
        }
    }

    #[test]
    fn cis_rows_are_well_formed() {
        for (canonical, target, title, _) in RHEL10_CIS {
            let parts: Vec<&str> = target.split('.').collect();
            assert!(
                parts.len() >= 2
                    && parts
                        .iter()
                        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
                "{target} must be a dotted numeric CIS section"
            );
            assert!(!canonical.is_empty(), "empty canonical id for {target}");
            assert!(!title.is_empty(), "empty title for {target}");
        }
    }

    /// The research shows every RHEL 10 target owned by exactly one canonical
    /// id in both tables (splits fan out; nothing fans in), so target
    /// uniqueness is asserted strictly alongside row uniqueness.
    #[test]
    fn rows_are_unique_and_targets_never_collide() {
        for table in [RHEL10_STIG, RHEL10_CIS] {
            let rows: std::collections::HashSet<_> = table
                .iter()
                .map(|(canonical, target, ..)| (*canonical, *target))
                .collect();
            assert_eq!(rows.len(), table.len(), "duplicate canonical→target row");

            let targets: std::collections::HashSet<_> =
                table.iter().map(|(_, target, ..)| *target).collect();
            assert_eq!(targets.len(), table.len(), "two canonicals share a target");
        }
    }

    #[test]
    fn labels_match_profile_and_framework() {
        assert_eq!(
            profile_label(ComplianceProfile::Rhel10, ComplianceFramework::STIG),
            Some("DISA RHEL 10 STIG V1R1")
        );
        assert_eq!(
            profile_label(ComplianceProfile::Rhel10, ComplianceFramework::CIS),
            Some("CIS RHEL 10 Benchmark v1.0.1")
        );
        assert_eq!(
            profile_label(ComplianceProfile::Generic, ComplianceFramework::STIG),
            Some("RHEL 8 baseline IDs")
        );
        assert_eq!(
            profile_label(ComplianceProfile::Generic, ComplianceFramework::CIS),
            None
        );
        assert_eq!(
            profile_label(ComplianceProfile::Rhel10, ComplianceFramework::NIST),
            None
        );
    }
}
