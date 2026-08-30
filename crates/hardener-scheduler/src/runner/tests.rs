#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`runner`](super).
//!
//! Split out of `runner.rs`. This file sits in the `runner/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::runner` and every import carried
//! across unchanged, private items included.

use super::*;
use hardener_common::types::FindingCategory;
use hardener_core::{ExceptionOutcome, Finding};
use tempfile::tempdir;

/// The session row naming which plugins a scan covers is written before any
/// plugin runs, so it has to be derived from the same rule the scan itself
/// obeys. Derived from dependency order alone, it filed a history row
/// claiming plugins the config had disabled, and every consumer of that
/// row (trends, regressions, the fleet view) read the absent findings as a
/// clean result for a plugin that never ran.
#[test]
fn the_recorded_plugin_list_covers_only_what_the_config_enables() {
    let mut config = HardenerConfig::default();
    config.kernel.enabled = Some(false);

    let recorded = scannable_plugins(
        vec!["ssh-hardening".to_string(), "kernel-hardening".to_string()],
        &config,
        &registered(),
    )
    .unwrap();

    assert_eq!(recorded, vec!["ssh-hardening".to_string()]);
}

/// The ids a real registry answers to, which is what an explicit schedule is
/// checked against.
fn registered() -> Vec<String> {
    [
        "kernel-hardening",
        "ssh-hardening",
        "firewall-hardening",
        "pam-hardening",
        "service-minimisation",
        "audit-hardening",
        "permissions-hardening",
        "mac-hardening",
    ]
    .iter()
    .map(|id| (*id).to_string())
    .collect()
}

/// `is_plugin_enabled` answers `true` for an id no plugin declares, so an
/// unknown id used to pass the filter, reach the history row as covered, and
/// then match no plugin when the scan ran. Refused rather than dropped: a
/// dropped id turns a stale schedule into a scan of nothing that reads exactly
/// like a scan of everything.
#[test]
fn an_unregistered_plugin_id_is_refused_rather_than_dropped() {
    let config = HardenerConfig::default();

    let err = scannable_plugins(vec!["kernel".to_string()], &config, &registered())
        .expect_err("an id no plugin declares must not pass silently");

    let message = err.to_string();
    assert!(message.contains("kernel"), "got {message}");
    assert!(message.contains("kernel-hardening"), "got {message}");
}

/// An explicitly scheduled plugin list is narrowed by the same rule: naming
/// a plugin in the schedule does not outrank the config disabling it, or
/// the two ways of selecting plugins would disagree.
#[test]
fn an_explicit_schedule_list_is_narrowed_by_the_config_too() {
    let mut config = HardenerConfig::default();
    config.global.disabled_plugins = vec!["ssh-hardening".to_string()];

    let recorded =
        scannable_plugins(vec!["ssh-hardening".to_string()], &config, &registered()).unwrap();

    assert!(recorded.is_empty(), "got {recorded:?}");
}

/// Creates a test finding with specified severity.
fn make_finding(id: &str, severity: Severity) -> Finding {
    Finding {
        finding_id: id.to_string(),
        finding_title: format!("Test finding {}", id),
        finding_description: "Test description".to_string(),
        finding_explanation: "Test explanation".to_string(),
        finding_severity: severity,
        finding_category: FindingCategory::Kernel,
        finding_current_value: "insecure".to_string(),
        finding_recommended_value: "secure".to_string(),
        finding_remediation_steps: vec!["Step 1".to_string()],
        finding_impact: "Test impact".to_string(),
        finding_compliance: vec![],
        finding_exception: ExceptionOutcome::NotConfigured,
        finding_exception_key: None,
    }
}

/// Creates a ScanResult with specified findings.
fn make_scan_result(plugin_id: &str, findings: Vec<Finding>, success: bool) -> ScanResult {
    ScanResult {
        scan_plugin_id: plugin_id.into(),
        scan_success: success,
        scan_findings: findings,
        scan_duration_us: 1000,
        scan_error: if success {
            None
        } else {
            Some("Test error".to_string())
        },
        scan_unchecked: vec![],
        scan_skipped: None,
    }
}

#[test]
fn trigger_type_as_str() {
    assert_eq!(TriggerType::Scheduled.as_str(), "scheduled");
    assert_eq!(TriggerType::Manual.as_str(), "manual");
    assert_eq!(TriggerType::Systemd.as_str(), "systemd");
}

#[test]
fn parse_severity_known_values() {
    assert_eq!(ScanRunner::parse_severity("critical"), Severity::Critical);
    assert_eq!(ScanRunner::parse_severity("HIGH"), Severity::High);
    assert_eq!(ScanRunner::parse_severity("Medium"), Severity::Medium);
    assert_eq!(ScanRunner::parse_severity("low"), Severity::Low);
    assert_eq!(ScanRunner::parse_severity("info"), Severity::Info);
}

#[test]
fn parse_severity_unknown_defaults_medium() {
    assert_eq!(ScanRunner::parse_severity("unknown"), Severity::Medium);
    assert_eq!(ScanRunner::parse_severity(""), Severity::Medium);
}

#[tokio::test]
async fn process_findings_filters_by_severity() {
    let dir = tempdir().unwrap();
    let db = Arc::new(
        ScanHistoryManager::new(&dir.path().join("test.db"))
            .await
            .unwrap(),
    );
    let json_store = Arc::new(JsonStore::new(dir.path()).await.unwrap());

    let runner = ScanRunner::with_params(
        db,
        json_store,
        Severity::High, // Only High and Critical
        vec![],
        "testhost".to_string(),
    );

    let scan_results = vec![make_scan_result(
        "kernel",
        vec![
            make_finding("K001", Severity::Critical),
            make_finding("K002", Severity::High),
            make_finding("K003", Severity::Medium), // Should be filtered
            make_finding("K004", Severity::Low),    // Should be filtered
        ],
        true,
    )];

    let findings = runner.process_findings(&scan_results);
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().any(|f| f.finding_id == "K001"));
    assert!(findings.iter().any(|f| f.finding_id == "K002"));
}

#[tokio::test]
async fn build_summary_counts_severities() {
    let dir = tempdir().unwrap();
    let db = Arc::new(
        ScanHistoryManager::new(&dir.path().join("test.db"))
            .await
            .unwrap(),
    );
    let json_store = Arc::new(JsonStore::new(dir.path()).await.unwrap());

    let runner = ScanRunner::with_params(
        db,
        json_store,
        Severity::Info,
        vec![],
        "testhost".to_string(),
    );

    let findings = vec![
        ScanFinding {
            plugin_id: "kernel".to_string(),
            finding_id: "K001".to_string(),
            severity: "critical".to_string(),
            title: "Critical issue".to_string(),
            description: None,
            current_value: None,
            recommended_value: None,
            category: None,
            compliance_mappings: None,
        },
        ScanFinding {
            plugin_id: "kernel".to_string(),
            finding_id: "K002".to_string(),
            severity: "high".to_string(),
            title: "High issue".to_string(),
            description: None,
            current_value: None,
            recommended_value: None,
            category: None,
            compliance_mappings: None,
        },
        ScanFinding {
            plugin_id: "ssh".to_string(),
            finding_id: "S001".to_string(),
            severity: "medium".to_string(),
            title: "Medium issue".to_string(),
            description: None,
            current_value: None,
            recommended_value: None,
            category: None,
            compliance_mappings: None,
        },
    ];

    let summary = runner.build_summary(
        "test-session",
        &["kernel".to_string(), "ssh".to_string()],
        &findings,
        false,
    );

    assert_eq!(summary.session_id, "test-session");
    assert_eq!(summary.total_findings, 3);
    assert_eq!(summary.critical_count, 1);
    assert_eq!(summary.high_count, 1);
    assert_eq!(summary.medium_count, 1);
    assert_eq!(summary.low_count, 0);
    assert!(!summary.had_errors);
}

#[tokio::test]
async fn build_json_export_includes_errors() {
    let dir = tempdir().unwrap();
    let db = Arc::new(
        ScanHistoryManager::new(&dir.path().join("test.db"))
            .await
            .unwrap(),
    );
    let json_store = Arc::new(JsonStore::new(dir.path()).await.unwrap());

    let runner = ScanRunner::with_params(
        db,
        json_store,
        Severity::Info,
        vec![],
        "testhost".to_string(),
    );

    let scan_results = vec![
        make_scan_result("kernel", vec![], true),
        make_scan_result("ssh", vec![], false), // Failed plugin
    ];

    let export = runner.build_json_export(&scan_results, &[]);

    assert_eq!(export.host, "testhost");
    assert_eq!(export.plugins_scanned.len(), 2);
    assert_eq!(export.plugin_errors.len(), 1);
    assert_eq!(export.plugin_errors[0].id, "ssh");
}

#[tokio::test]
async fn process_findings_converts_compliance_mappings() {
    let dir = tempdir().unwrap();
    let db = Arc::new(
        ScanHistoryManager::new(&dir.path().join("test.db"))
            .await
            .unwrap(),
    );
    let json_store = Arc::new(JsonStore::new(dir.path()).await.unwrap());

    let runner = ScanRunner::with_params(
        db,
        json_store,
        Severity::Info,
        vec![],
        "testhost".to_string(),
    );

    let mut finding = make_finding("K001", Severity::High);
    finding.finding_compliance = vec![hardener_common::types::ComplianceMapping {
        compliance_framework: hardener_common::types::ComplianceFramework::CIS,
        compliance_control_id: "1.5.1".to_string(),
        compliance_control_title: "Test control".to_string(),
        compliance_section: None,
    }];

    let scan_results = vec![make_scan_result("kernel", vec![finding], true)];
    let findings = runner.process_findings(&scan_results);

    assert_eq!(findings.len(), 1);
    let mappings = findings[0].compliance_mappings.as_ref().unwrap();
    assert_eq!(mappings.len(), 1);
    assert!(mappings[0].contains("CIS"));
    assert!(mappings[0].contains("1.5.1"));
}
