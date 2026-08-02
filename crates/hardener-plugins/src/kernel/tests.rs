#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`kernel`].
//!
//! Split out of `kernel.rs`. This file sits in the `kernel/` directory
//! beside it, so `super` still resolves to `crate::kernel` and every
//! import carried across unchanged, private items included.

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

/// Names only kernel's own paths, so a failure here cannot come from another
/// plugin's entry in a shared list.
#[test]
fn kernel_reloads_for_its_own_paths_and_no_others() {
    let plugin = KernelHardeningPlugin::new();
    assert!(plugin.reloads_for_path(Path::new("/etc/sysctl.conf")));
    assert!(plugin.reloads_for_path(Path::new("/etc/sysctl.d/99-hardener.conf")));
    assert!(!plugin.reloads_for_path(Path::new("/etc/ssh/sshd_config")));
}

/// Ties the predicate to the literals `apply` actually checkpoints, so the
/// two cannot drift apart unnoticed.
#[test]
fn every_path_kernel_checkpoints_is_one_it_reloads_for() {
    let plugin = KernelHardeningPlugin::new();
    for path in ["/etc/sysctl.conf", SYSCTL_DROPIN_DIR, SYSCTL_HARDENER_CONF] {
        assert!(
            plugin.reloads_for_path(Path::new(path)),
            "kernel checkpoints {path} but would not reload for it"
        );
    }
}
