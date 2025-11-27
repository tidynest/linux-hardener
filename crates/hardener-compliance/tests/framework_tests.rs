//! Integration tests for compliance framework control definitions.

use hardener_common::types::ComplianceFramework;
use hardener_compliance::frameworks;

#[test]
fn test_cis_controls_not_empty() {
    let controls = frameworks::cis::get_controls();
    assert!(!controls.is_empty(), "CIS controls should not be empty");

    // All controls should have CIS framework
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
fn test_stig_controls_not_empty() {
    let controls = frameworks::stig::get_controls();
    assert!(!controls.is_empty(), "STIG controls should not be empty");

    for control in &controls {
        assert_eq!(control.compliance_framework, ComplianceFramework::STIG);
    }
}

#[test]
fn test_stig_controls_have_required_fields() {
    let controls = frameworks::stig::get_controls();

    for control in &controls {
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
fn test_nist_controls_not_empty() {
    let controls = frameworks::nist::get_controls();
    assert!(!controls.is_empty(), "NIST controls should not be empty");

    for control in &controls {
        assert_eq!(control.compliance_framework, ComplianceFramework::NIST);
    }
}

#[test]
fn test_nist_controls_have_required_fields() {
    let controls = frameworks::nist::get_controls();

    for control in &controls {
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
fn test_hipaa_controls_not_empty() {
    let controls = frameworks::hipaa::get_controls();
    assert!(!controls.is_empty(), "HIPAA controls should not be empty");

    for control in &controls {
        assert_eq!(control.compliance_framework, ComplianceFramework::HIPAA);
    }
}

#[test]
fn test_hipaa_controls_have_required_fields() {
    let controls = frameworks::hipaa::get_controls();

    for control in &controls {
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
fn test_pci_controls_not_empty() {
    let controls = frameworks::pci::get_controls();
    assert!(!controls.is_empty(), "PCI-DSS controls should not be empty");

    for control in &controls {
        assert_eq!(control.compliance_framework, ComplianceFramework::PCIDSS);
    }
}

#[test]
fn test_pci_controls_have_required_fields() {
    let controls = frameworks::pci::get_controls();

    for control in &controls {
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
fn test_gdpr_controls_not_empty() {
    let controls = frameworks::gdpr::get_controls();
    assert!(!controls.is_empty(), "GDPR controls should not be empty");

    for control in &controls {
        assert_eq!(control.compliance_framework, ComplianceFramework::GDPR);
    }
}

#[test]
fn test_gdpr_controls_have_required_fields() {
    let controls = frameworks::gdpr::get_controls();

    for control in &controls {
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
fn test_control_ids_are_unique_within_framework() {
    // CIS
    let cis_controls = frameworks::cis::get_controls();
    let cis_ids: std::collections::HashSet<_> = cis_controls
        .iter()
        .map(|c| &c.compliance_control_id)
        .collect();
    assert_eq!(
        cis_ids.len(),
        cis_controls.len(),
        "CIS control IDs should be unique"
    );

    // STIG
    let stig_controls = frameworks::stig::get_controls();
    let stig_ids: std::collections::HashSet<_> = stig_controls
        .iter()
        .map(|c| &c.compliance_control_id)
        .collect();
    assert_eq!(
        stig_ids.len(),
        stig_controls.len(),
        "STIG control IDs should be unique"
    );

    // NIST
    let nist_controls = frameworks::nist::get_controls();
    let nist_ids: std::collections::HashSet<_> = nist_controls
        .iter()
        .map(|c| &c.compliance_control_id)
        .collect();
    assert_eq!(
        nist_ids.len(),
        nist_controls.len(),
        "NIST control IDs should be unique"
    );
}

#[test]
fn test_all_frameworks_have_controls() {
    // Verify the get_controls function returns controls for each framework
    assert!(
        frameworks::cis::get_controls().len() >= 30,
        "CIS should have at least 30 controls"
    );
    assert!(
        frameworks::stig::get_controls().len() >= 15,
        "STIG should have at least 15 controls"
    );
    assert!(
        frameworks::nist::get_controls().len() >= 15,
        "NIST should have at least 15 controls"
    );
    assert!(
        frameworks::hipaa::get_controls().len() >= 10,
        "HIPAA should have at least 10 controls"
    );
    assert!(
        frameworks::pci::get_controls().len() >= 15,
        "PCI-DSS should have at least 15 controls"
    );
    assert!(
        frameworks::gdpr::get_controls().len() >= 10,
        "GDPR should have at least 10 controls"
    );
}
