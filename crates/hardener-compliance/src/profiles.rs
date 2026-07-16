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
const RHEL10_STIG: &[Row] = &[
    // DISA RHEL 10 STIG V1R1 XCCDF (dl.dod.cyber.mil U_RHEL_10_V1R1_STIG.zip), V-281315;
    // verified stigviewer.com/stigs/red_hat_enterprise_linux_10/2026-05-14/finding/V-281315.
    (
        "RHEL-08-010430",
        "RHEL-10-701130",
        "RHEL 10 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.",
        None,
    ),
];

/// CIS RHEL 10 Benchmark v1.0.1 renumbering, keyed by canonical CIS section.
/// Every row cites its verified public source; unsourced sections get no row.
const RHEL10_CIS: &[Row] = &[
    // ComplianceAsCode products/rhel10/controls/cis_rhel10.yml @ db939fa (CIS RHEL 10
    // Benchmark v1.0.1).
    (
        "1.5.1",
        "1.5.8",
        "Ensure kernel.randomize_va_space is configured",
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

    #[test]
    fn rhel10_curated_cis_catalogue_renumbers_aslr() {
        let translated = translate_all(
            ComplianceProfile::Rhel10,
            &crate::frameworks::cis::get_controls(),
        );

        assert!(
            translated
                .iter()
                .any(|m| m.compliance_control_id == "1.5.8")
        );
        assert!(
            translated
                .iter()
                .all(|m| m.compliance_control_id != "1.5.1")
        );
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
