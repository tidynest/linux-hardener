//! Integration tests for compliance framework control definitions.
//!
//! Only CIS and ISO/IEC 27001:2022 ship a hand-curated catalogue; every other
//! framework's catalogue is derived from plugin coverage at report time (see
//! `assessment_honesty.rs`), so there is no static catalogue to assert here.

use hardener_common::types::ComplianceFramework;
use hardener_compliance::frameworks;

#[test]
fn test_cis_controls_not_empty() {
    let controls = frameworks::cis::get_controls();
    assert!(!controls.is_empty(), "CIS controls should not be empty");

    for control in &controls {
        assert_eq!(control.compliance_framework, ComplianceFramework::CIS);
    }
}

#[test]
fn test_cis_controls_have_required_fields() {
    let controls = frameworks::cis::get_controls();

    for control in &controls {
        assert!(
            !control.compliance_control_id.is_empty(),
            "Control ID should not be empty"
        );
        assert!(
            !control.compliance_control_title.is_empty(),
            "Control title should not be empty"
        );
        assert!(
            control.compliance_section.is_some(),
            "CIS controls should have sections"
        );
    }
}

#[test]
fn test_cis_ssh_crypto_controls_are_curated() {
    // 5.2.14-16 (strong Kex/Ciphers/MACs) are real consecutive CIS controls the
    // SSH plugin assesses; the curated SSH block must list them so the standard
    // is complete rather than relying on the coverage-merge to surface them.
    let ids: std::collections::HashSet<_> = frameworks::cis::get_controls()
        .into_iter()
        .map(|c| c.compliance_control_id)
        .collect();
    for id in ["5.2.14", "5.2.15", "5.2.16"] {
        assert!(ids.contains(id), "curated CIS catalogue must include {id}");
    }
}

#[test]
fn test_iso27001_controls_not_empty() {
    let controls = frameworks::iso27001::get_controls();
    assert!(
        !controls.is_empty(),
        "ISO 27001 controls should not be empty"
    );

    for control in &controls {
        assert_eq!(control.compliance_framework, ComplianceFramework::ISO27001);
        assert!(
            !control.compliance_control_id.is_empty(),
            "Control ID should not be empty"
        );
        assert!(
            !control.compliance_control_title.is_empty(),
            "Control title should not be empty"
        );
    }
}

#[test]
fn test_control_ids_are_unique_within_curated_catalogues() {
    for controls in [
        frameworks::cis::get_controls(),
        frameworks::iso27001::get_controls(),
    ] {
        let ids: std::collections::HashSet<_> =
            controls.iter().map(|c| &c.compliance_control_id).collect();
        assert_eq!(
            ids.len(),
            controls.len(),
            "curated control IDs should be unique within a framework"
        );
    }
}

#[test]
fn test_curated_catalogues_are_sized() {
    assert!(
        frameworks::cis::get_controls().len() >= 30,
        "CIS should have at least 30 controls"
    );
    assert!(
        frameworks::iso27001::get_controls().len() >= 90,
        "ISO 27001 Annex A should have ~93 controls"
    );
}

#[test]
fn test_only_cis_and_iso_are_curated() {
    // Curated catalogues exist for CIS and ISO 27001; all other frameworks are
    // derived from coverage and so return None here.
    assert!(frameworks::curated_controls(&ComplianceFramework::CIS).is_some());
    assert!(frameworks::curated_controls(&ComplianceFramework::ISO27001).is_some());
    for framework in [
        ComplianceFramework::STIG,
        ComplianceFramework::NIST,
        ComplianceFramework::PCIDSS,
        ComplianceFramework::HIPAA,
        ComplianceFramework::GDPR,
        ComplianceFramework::SOC2,
    ] {
        assert!(
            frameworks::curated_controls(&framework).is_none(),
            "{framework:?} must be derived from coverage, not curated"
        );
    }
}
