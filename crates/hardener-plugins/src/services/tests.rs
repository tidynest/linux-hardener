#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`services`].
//!
//! Split out of `services.rs`. This file sits in the `services/` directory
//! beside it, so `super` still resolves to `crate::services` and every
//! import carried across unchanged, private items included.

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
        m.compliance_framework == ComplianceFramework::ISO27001 && m.compliance_control_id == "8.20"
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

/// Names only services' own paths, so a failure here cannot come from
/// another plugin's entry in a shared list.
#[test]
fn services_reloads_for_its_own_paths_and_no_others() {
    let plugin = ServicesHardeningPlugin::new();
    assert!(plugin.reloads_for_path(Path::new("/etc/systemd/system/telnet.socket")));
    assert!(!plugin.reloads_for_path(Path::new("/etc/ssh/sshd_config")));
}

/// Ties the predicate to the literal `apply` actually checkpoints, so the
/// two cannot drift apart unnoticed.
#[test]
fn every_path_services_checkpoints_is_one_it_reloads_for() {
    let plugin = ServicesHardeningPlugin::new();
    assert!(
        plugin.reloads_for_path(Path::new(ADMIN_UNIT_DIR)),
        "services checkpoints {ADMIN_UNIT_DIR} but would not reload for it"
    );
}
