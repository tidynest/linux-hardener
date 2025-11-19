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
    assert!(Severity::Info < Severity::Low);
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);

    // Test that ordering works correctly
    let mut severities = vec![
        Severity::Critical,
        Severity::Info,
        Severity::Medium,
        Severity::Low,
        Severity::High,
    ];
    severities.sort();

    assert_eq!(severities, vec![
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ]);
}

#[test]
fn test_severity_display() {
    assert_eq!(format!("{}", Severity::Info),     "INFO");
    assert_eq!(format!("{}", Severity::Low),      "LOW");
    assert_eq!(format!("{}", Severity::Medium),   "MEDIUM");
    assert_eq!(format!("{}", Severity::High),     "HIGH");
    assert_eq!(format!("{}", Severity::Critical), "CRITICAL");
}

#[test]
fn test_finding_category_display() {
    assert_eq!(format!("{}", FindingCategory::Audit),                  "Audit");
    assert_eq!(format!("{}", FindingCategory::Authentication),         "Authentication");
    assert_eq!(format!("{}", FindingCategory::Cryptography),           "Cryptography");
    assert_eq!(format!("{}", FindingCategory::FileSystem),             "File System");
    assert_eq!(format!("{}", FindingCategory::Kernel),                 "Kernel");
    assert_eq!(format!("{}", FindingCategory::MandatoryAccessControl), "MAC");
    assert_eq!(format!("{}", FindingCategory::Network),                "Network");
    assert_eq!(format!("{}", FindingCategory::Services),               "Services");
}

#[test]
fn test_compliance_framework_display() {
    assert_eq!(format!("{}", ComplianceFramework::CIS),      "CIS");
    assert_eq!(format!("{}", ComplianceFramework::HIPAA),    "HIPAA");
    assert_eq!(format!("{}", ComplianceFramework::ISO27001), "ISO27001");
    assert_eq!(format!("{}", ComplianceFramework::NIST),     "NIST");
    assert_eq!(format!("{}", ComplianceFramework::STIG),     "STIG");
    assert_eq!(format!("{}", ComplianceFramework::PCIDSS),   "PCIDSS");
}

#[test]
fn test_types_are_serializable() {
    // Test that types can be serialised to JSON
    let id = PluginId::new("test");
    let json = serde_json::to_string(&id).unwrap();
    assert!(json.contains("test"));

    let category = FindingCategory::Kernel;
    let json = serde_json::to_string(&category).unwrap();
    assert!(json.contains("Kernel"));

    let framework = ComplianceFramework::CIS;
    let json = serde_json::to_string(&framework).unwrap();
    assert!(json.contains("CIS"));

    let severity = Severity::High;
    let json = serde_json::to_string(&severity).unwrap();
    assert!(json.contains("High"));
}
