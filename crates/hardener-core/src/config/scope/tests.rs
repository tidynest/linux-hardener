#![cfg(test)]
//! Unit tests for [`scope`](super).

use super::*;
use chrono::NaiveDate;

fn day(s: &str) -> NaiveDate {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").expect("test date parses")
}

fn exclusion(review_by: Option<&str>) -> ScopeExclusion {
    ScopeExclusion {
        reason: "No physical premises".to_string(),
        approved_by: Some("eric".to_string()),
        approved_date: Some("2026-08-18".to_string()),
        ticket: None,
        review_by: review_by.map(str::to_string),
        hosts: Vec::new(),
    }
}

/// Only NIST 800-171 differs, and it differs because CMMC certification is
/// valid for three years. Every other framework either states twelve months
/// (PCI DSS 12.5.2, FedRAMP CA-2) or states no interval at all, in which case
/// twelve is this project's default and is documented as such.
#[test]
fn review_intervals_follow_the_framework_owners() {
    assert_eq!(default_review_months("800-171"), 36);
    for id in [
        "cis", "stig", "nist", "pcidss", "hipaa", "gdpr", "iso27001", "soc2", "fedramp",
    ] {
        assert_eq!(default_review_months(id), 12, "{id} defaults to 12 months");
    }
}

#[test]
fn an_absent_review_by_is_defaulted_from_the_approval_date() {
    let e = exclusion(None);
    assert_eq!(
        e.review_deadline("iso27001", day("2020-01-01")),
        day("2027-08-18"),
        "twelve months after the approval date, not after the fallback"
    );
}

#[test]
fn an_absent_approval_date_falls_back_to_the_supplied_day() {
    let mut e = exclusion(None);
    e.approved_date = None;
    assert_eq!(
        e.review_deadline("iso27001", day("2026-08-18")),
        day("2027-08-18")
    );
}

#[test]
fn an_explicit_review_by_wins_over_the_default() {
    let e = exclusion(Some("2026-12-01"));
    assert_eq!(
        e.review_deadline("iso27001", day("2026-08-18")),
        day("2026-12-01")
    );
}

#[test]
fn an_exclusion_is_valid_up_to_and_including_its_deadline() {
    let e = exclusion(Some("2026-12-01"));
    assert!(e.is_valid_on("iso27001", day("2026-11-30")));
    assert!(
        e.is_valid_on("iso27001", day("2026-12-01")),
        "the deadline day itself is still valid"
    );
    assert!(!e.is_valid_on("iso27001", day("2026-12-02")));
}

/// A malformed date must not silently extend an exclusion. Failing closed means
/// the control returns to counting against the score.
#[test]
fn an_unparseable_review_by_is_invalid_rather_than_ignored() {
    let e = exclusion(Some("not-a-date"));
    assert!(!e.is_valid_on("iso27001", day("2026-08-18")));
}

#[test]
fn the_config_section_parses_from_toml() {
    let toml = r#"
[compliance.not_applicable.iso27001."A.7.1"]
reason = "No physical premises; all infrastructure is cloud-hosted"
approved_by = "eric"
approved_date = "2026-08-18"
ticket = "SEC-412"
review_by = "2027-08-18"
hosts = ["web-01.example.net"]
"#;
    let config: crate::config::HardenerConfig = toml::from_str(toml).expect("parses");
    let entry = config
        .compliance
        .not_applicable
        .get("iso27001")
        .and_then(|f| f.get("A.7.1"))
        .expect("the exclusion is present");
    assert_eq!(entry.ticket.as_deref(), Some("SEC-412"));
    assert_eq!(entry.hosts, vec!["web-01.example.net".to_string()]);
}

/// The section is optional. A config that never mentions compliance must still
/// load, or every existing deployment breaks on upgrade.
#[test]
fn a_config_without_the_section_still_loads() {
    let config: crate::config::HardenerConfig = toml::from_str("[global]\n").expect("parses");
    assert!(config.compliance.not_applicable.is_empty());
}
