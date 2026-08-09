use super::*;
use hardener_types::{ExceptionOutcome, FindingCategory, Severity};

fn finding(key: Option<&str>, current: &str) -> Finding {
    Finding {
        finding_category: FindingCategory::Services,
        finding_current_value: current.to_string(),
        finding_description: String::new(),
        finding_explanation: String::new(),
        finding_id: "service_bluetooth".to_string(),
        finding_impact: String::new(),
        finding_recommended_value: "disabled".to_string(),
        finding_remediation_steps: vec![],
        finding_severity: Severity::Medium,
        finding_title: "Bluetooth service is enabled".to_string(),
        finding_compliance: vec![],
        finding_exception: ExceptionOutcome::NotConfigured,
        finding_exception_key: key.map(str::to_string),
    }
}

/// The value written is the one this scan just read, not one carried in from a
/// row that may be days old. A stale pin makes an exception that never applies.
#[test]
fn the_pinned_value_comes_from_the_matching_finding() {
    let findings = vec![
        finding(Some("cups"), "enabled"),
        finding(Some("bluetooth"), "active"),
    ];

    let pinned = pin_from_findings(&findings, "bluetooth").expect("the key is present");

    assert_eq!(pinned.finding_current_value, "active");
}

/// A key the host's own scan did not produce is refused. That refusal is also
/// the input validation for the desktop: a crafted key cannot reach the
/// document, because it never matches a live finding.
#[test]
fn an_unknown_key_is_refused_by_name() {
    let findings = vec![finding(Some("cups"), "enabled")];

    let err = pin_from_findings(&findings, "bluetooth").expect_err("an absent key must refuse");

    assert!(
        err.to_string().contains("bluetooth"),
        "the refusal names the key: {err}"
    );
}

/// A finding with no key cannot be excepted at all, and must not be matched by
/// a caller passing an empty key.
#[test]
fn a_keyless_finding_never_matches() {
    let findings = vec![finding(None, "enabled")];

    assert!(pin_from_findings(&findings, "").is_err());
}
