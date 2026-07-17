//! Integration tests for common types.

use hardener_common::types::*;
use std::collections::HashMap;

#[test]
fn test_plugin_id_creation() {
    let id1 = PluginId::new("test_plugin");
    let id2 = PluginId::from("test_plugin");
    let id3: PluginId = "test_plugin".into();

    assert_eq!(id1.as_str(), "test_plugin");
    assert_eq!(id1, id2);
    assert_eq!(id2, id3);
}

#[test]
fn test_plugin_id_display() {
    let id = PluginId::new("ssh_hardening");
    assert_eq!(format!("{}", id), "ssh_hardening");
}

#[test]
fn test_plugin_id_hash() {
    let mut map = HashMap::new();
    let id = PluginId::new("kernel");
    map.insert(id.clone(), "Kernel hardening");

    assert_eq!(map.get(&id), Some(&"Kernel hardening"));
}

#[test]
fn test_severity_ordering() {
    assert!(
        Severity::Info < Severity::Low,
        "Info should be less than Low"
    );
    assert!(
        Severity::Low < Severity::Medium,
        "Low should be less than Medium"
    );
    assert!(
        Severity::Medium < Severity::High,
        "Medium should be less than High"
    );
    assert!(
        Severity::High < Severity::Critical,
        "High should be less than Critical"
    );

    // Test that ordering works correctly
    let mut severities = vec![
        Severity::Critical,
        Severity::Info,
        Severity::Medium,
        Severity::Low,
        Severity::High,
    ];
    severities.sort();

    assert_eq!(
        severities,
        vec![
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ]
    );
}

#[test]
fn test_severity_display() {
    assert_eq!(format!("{}", Severity::Info), "INFO");
    assert_eq!(format!("{}", Severity::Low), "LOW");
    assert_eq!(format!("{}", Severity::Medium), "MEDIUM");
    assert_eq!(format!("{}", Severity::High), "HIGH");
    assert_eq!(format!("{}", Severity::Critical), "CRITICAL");
}

#[test]
fn test_finding_category_display() {
    assert_eq!(format!("{}", FindingCategory::Audit), "Audit");
    assert_eq!(
        format!("{}", FindingCategory::Authentication),
        "Authentication"
    );
    assert_eq!(format!("{}", FindingCategory::Cryptography), "Cryptography");
    assert_eq!(format!("{}", FindingCategory::FileSystem), "File System");
    assert_eq!(format!("{}", FindingCategory::Kernel), "Kernel");
    assert_eq!(
        format!("{}", FindingCategory::MandatoryAccessControl),
        "MAC"
    );
    assert_eq!(format!("{}", FindingCategory::Network), "Network");
    assert_eq!(format!("{}", FindingCategory::Services), "Services");
}

#[test]
fn test_compliance_framework_display() {
    assert_eq!(format!("{}", ComplianceFramework::CIS), "CIS");
    assert_eq!(format!("{}", ComplianceFramework::HIPAA), "HIPAA");
    assert_eq!(format!("{}", ComplianceFramework::ISO27001), "ISO27001");
    assert_eq!(format!("{}", ComplianceFramework::NIST), "NIST");
    assert_eq!(format!("{}", ComplianceFramework::STIG), "STIG");
    assert_eq!(format!("{}", ComplianceFramework::PCIDSS), "PCIDSS");
    assert_eq!(format!("{}", ComplianceFramework::SOC2), "SOC 2");
    assert_eq!(
        format!("{}", ComplianceFramework::NIST800171),
        "NIST 800-171"
    );
}

#[test]
fn test_compliance_framework_full_name() {
    assert_eq!(ComplianceFramework::CIS.full_name(), "CIS Benchmark");
    assert_eq!(
        ComplianceFramework::HIPAA.full_name(),
        "HIPAA Security Rule"
    );
    assert_eq!(ComplianceFramework::ISO27001.full_name(), "ISO/IEC 27001");
    assert_eq!(ComplianceFramework::NIST.full_name(), "NIST 800-53");
    assert_eq!(ComplianceFramework::PCIDSS.full_name(), "PCI-DSS v4.0");
    assert_eq!(ComplianceFramework::STIG.full_name(), "DISA STIG");
    assert_eq!(ComplianceFramework::GDPR.full_name(), "GDPR Article 32");
    assert_eq!(
        ComplianceFramework::SOC2.full_name(),
        "SOC 2 Trust Services Criteria"
    );
    assert_eq!(
        ComplianceFramework::NIST800171.full_name(),
        "NIST SP 800-171"
    );
}

#[test]
fn test_compliance_framework_description() {
    assert!(
        ComplianceFramework::CIS
            .description()
            .contains("Center for Internet Security"),
        "CIS description should mention Center for Internet Security, got: {}",
        ComplianceFramework::CIS.description()
    );
    assert!(
        ComplianceFramework::HIPAA
            .description()
            .contains("Health Insurance"),
        "HIPAA description should mention Health Insurance, got: {}",
        ComplianceFramework::HIPAA.description()
    );
    assert!(
        ComplianceFramework::ISO27001
            .description()
            .contains("International Organisation"),
        "ISO27001 description should mention International Organisation, got: {}",
        ComplianceFramework::ISO27001.description()
    );
    assert!(
        ComplianceFramework::NIST
            .description()
            .contains("National Institute"),
        "NIST description should mention National Institute, got: {}",
        ComplianceFramework::NIST.description()
    );
    assert!(
        ComplianceFramework::PCIDSS
            .description()
            .contains("Payment Card"),
        "PCIDSS description should mention Payment Card, got: {}",
        ComplianceFramework::PCIDSS.description()
    );
    assert!(
        ComplianceFramework::STIG
            .description()
            .contains("Defense Information"),
        "STIG description should mention Defense Information, got: {}",
        ComplianceFramework::STIG.description()
    );
    assert!(
        ComplianceFramework::GDPR
            .description()
            .contains("General Data Protection"),
        "GDPR description should mention General Data Protection, got: {}",
        ComplianceFramework::GDPR.description()
    );
    assert!(
        ComplianceFramework::SOC2
            .description()
            .contains("Trust Services Criteria"),
        "SOC2 description should mention Trust Services Criteria, got: {}",
        ComplianceFramework::SOC2.description()
    );
    assert!(
        ComplianceFramework::NIST800171
            .description()
            .contains("Controlled Unclassified Information"),
        "NIST800171 description should mention Controlled Unclassified Information, got: {}",
        ComplianceFramework::NIST800171.description()
    );
}

#[test]
fn test_types_are_serializable() {
    // Test that types can be serialised to JSON
    let id = PluginId::new("test");
    let json = serde_json::to_string(&id).unwrap();
    assert!(
        json.contains("test"),
        "PluginId JSON should contain 'test', got: {json}"
    );

    let category = FindingCategory::Kernel;
    let json = serde_json::to_string(&category).unwrap();
    assert!(
        json.contains("Kernel"),
        "FindingCategory JSON should contain 'Kernel', got: {json}"
    );

    let framework = ComplianceFramework::CIS;
    let json = serde_json::to_string(&framework).unwrap();
    assert!(
        json.contains("CIS"),
        "ComplianceFramework JSON should contain 'CIS', got: {json}"
    );

    let severity = Severity::High;
    let json = serde_json::to_string(&severity).unwrap();
    assert!(
        json.contains("High"),
        "Severity JSON should contain 'High', got: {json}"
    );
}
