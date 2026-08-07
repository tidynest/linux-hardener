#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`profiles`](super).
//!
//! Split out of `profiles.rs`. This file sits in the `profiles/` directory
//! beside it, which the 2018 path rules allow with no `mod.rs` and no
//! `#[path]`, so `super` still resolves to `crate::profiles` and every import
//! carried across unchanged, private items included.

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
fn nist_800_171_is_profile_invariant_under_rhel10() {
    // 800-171 requirements are OS-independent: no profile may rewrite them.
    let nist171 = mapping(ComplianceFramework::NIST800171, "3.4.2");
    assert_eq!(
        translate(ComplianceProfile::Rhel10, &nist171),
        vec![nist171.clone()]
    );
}

#[test]
fn fedramp_is_profile_invariant_under_rhel10() {
    // FedRAMP renders baseline-filtered 800-53 ids, which are
    // OS-independent: no profile may rewrite them.
    let fedramp = mapping(ComplianceFramework::FedRAMP, "SC-7");
    assert_eq!(
        translate(ComplianceProfile::Rhel10, &fedramp),
        vec![fedramp.clone()]
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
/// curated catalogue; no plugin emits it, so it needs no entry. STIG
/// needs none either: the sshd KexAlgorithms check lost its STIG mapping
/// with the RHEL 8 V2R7 V-ID fix, so every plugin-emitted STIG id has a
/// sourced row.
const DOCUMENTED_DROPS: &[(ComplianceFramework, &str)] = &[(ComplianceFramework::CIS, "2.1.1")];

/// Pins the tables against the live plugin surface: every STIG or CIS
/// mapping any plugin can emit either translates under `Rhel10` or is an
/// explicitly documented drop, never a silent disappearance.
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
    assert!(
        !RHEL10_STIG.is_empty(),
        "an emptied table would leave the loop below proving nothing"
    );
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
    assert!(
        !RHEL10_CIS.is_empty(),
        "an emptied table would leave the loop below proving nothing"
    );
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
