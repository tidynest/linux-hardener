#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`notification`](super).
//!
//! Split out of `notification/mod.rs`. That file *is* the module `notification`, so its tests
//! go to `notification/tests.rs` in the directory it already owns; a
//! `notification/mod/` would resolve to no module at all. `super` is unchanged.

use super::*;
use crate::runner::ScanSummary;

/// Creates a test summary with specified severity counts.
fn make_summary(critical: usize, high: usize, medium: usize, low: usize) -> ScanSummary {
    ScanSummary {
        session_id: "test-session".to_string(),
        host: "testhost".to_string(),
        plugins_scanned: vec!["kernel".to_string()],
        total_findings: critical + high + medium + low,
        critical_count: critical,
        high_count: high,
        medium_count: medium,
        low_count: low,
        info_count: 0,
        json_path: None,
        json_hash: None,
        had_errors: false,
        regression: None,
    }
}

#[test]
fn notification_result_ok() {
    let result = NotificationResult::ok("email");
    assert!(result.success);
    assert_eq!(result.channel, "email");
    assert!(result.error.is_none());
}

#[test]
fn notification_result_failed() {
    let result = NotificationResult::failed("webhook:slack", "Connection timeout");
    assert!(!result.success);
    assert_eq!(result.channel, "webhook:slack");
    assert_eq!(result.error, Some("Connection timeout".to_string()));
}

#[test]
fn parse_severity_all_levels() {
    assert_eq!(parse_severity("critical"), Severity::Critical);
    assert_eq!(parse_severity("CRITICAL"), Severity::Critical);
    assert_eq!(parse_severity("high"), Severity::High);
    assert_eq!(parse_severity("HIGH"), Severity::High);
    assert_eq!(parse_severity("medium"), Severity::Medium);
    assert_eq!(parse_severity("MEDIUM"), Severity::Medium);
    assert_eq!(parse_severity("low"), Severity::Low);
    assert_eq!(parse_severity("LOW"), Severity::Low);
    assert_eq!(parse_severity("info"), Severity::Info);
    assert_eq!(parse_severity("INFO"), Severity::Info);
}

#[test]
fn parse_severity_unknown_defaults_medium() {
    assert_eq!(parse_severity("unknown"), Severity::Medium);
    assert_eq!(parse_severity(""), Severity::Medium);
    assert_eq!(parse_severity("invalid"), Severity::Medium);
}

#[test]
fn threshold_critical_requires_critical() {
    assert!(meets_severity_threshold(
        &make_summary(1, 0, 0, 0),
        Severity::Critical
    ));
    assert!(!meets_severity_threshold(
        &make_summary(0, 5, 0, 0),
        Severity::Critical
    ));
    assert!(!meets_severity_threshold(
        &make_summary(0, 0, 10, 0),
        Severity::Critical
    ));
}

#[test]
fn threshold_high_accepts_critical_or_high() {
    assert!(meets_severity_threshold(
        &make_summary(1, 0, 0, 0),
        Severity::High
    ));
    assert!(meets_severity_threshold(
        &make_summary(0, 1, 0, 0),
        Severity::High
    ));
    assert!(!meets_severity_threshold(
        &make_summary(0, 0, 10, 0),
        Severity::High
    ));
}

#[test]
fn threshold_medium_accepts_critical_high_medium() {
    assert!(meets_severity_threshold(
        &make_summary(1, 0, 0, 0),
        Severity::Medium
    ));
    assert!(meets_severity_threshold(
        &make_summary(0, 1, 0, 0),
        Severity::Medium
    ));
    assert!(meets_severity_threshold(
        &make_summary(0, 0, 1, 0),
        Severity::Medium
    ));
    assert!(!meets_severity_threshold(
        &make_summary(0, 0, 0, 5),
        Severity::Medium
    ));
}

#[test]
fn threshold_low_accepts_all_except_info() {
    assert!(meets_severity_threshold(
        &make_summary(1, 0, 0, 0),
        Severity::Low
    ));
    assert!(meets_severity_threshold(
        &make_summary(0, 1, 0, 0),
        Severity::Low
    ));
    assert!(meets_severity_threshold(
        &make_summary(0, 0, 1, 0),
        Severity::Low
    ));
    assert!(meets_severity_threshold(
        &make_summary(0, 0, 0, 1),
        Severity::Low
    ));
}

#[test]
fn threshold_info_accepts_any_findings() {
    let mut summary = make_summary(0, 0, 0, 0);
    summary.info_count = 1;
    summary.total_findings = 1;
    assert!(meets_severity_threshold(&summary, Severity::Info));
}

#[test]
fn threshold_no_findings_never_triggers() {
    let empty = make_summary(0, 0, 0, 0);
    assert!(!meets_severity_threshold(&empty, Severity::Critical));
    assert!(!meets_severity_threshold(&empty, Severity::High));
    assert!(!meets_severity_threshold(&empty, Severity::Medium));
    assert!(!meets_severity_threshold(&empty, Severity::Low));
    assert!(!meets_severity_threshold(&empty, Severity::Info));
}

use crate::config::NotifyMode;
use crate::db::ScanSession;

fn prev_session(critical: i32, high: i32, medium: i32, low: i32) -> ScanSession {
    ScanSession {
        id: "prev".into(),
        started_at: 100,
        completed_at: Some(100),
        status: "completed".into(),
        trigger_type: "schedule".into(),
        host_identifier: "h".into(),
        plugins_scanned: String::new(),
        total_findings: critical + high + medium + low,
        critical_count: critical,
        high_count: high,
        medium_count: medium,
        low_count: low,
        info_count: 0,
        error_message: None,
        json_file_path: None,
        hash: None,
    }
}

#[test]
fn findings_mode_matches_threshold_no_annotation() {
    // Findings mode ignores history: sends iff threshold met, never annotates.
    let prev = prev_session(0, 0, 0, 0);
    let cur = make_summary(1, 0, 0, 0); // 1 critical
    let (send, info) = alert_decision(NotifyMode::Findings, Severity::Critical, Some(&prev), &cur);
    assert!(send);
    assert!(info.is_none());

    let clean = make_summary(0, 0, 0, 0);
    let (send, _) = alert_decision(
        NotifyMode::Findings,
        Severity::Critical,
        Some(&prev),
        &clean,
    );
    assert!(!send);
}

#[test]
fn regression_mode_quiet_until_worse() {
    let prev = prev_session(1, 0, 0, 0); // already 1 critical
    // Same posture: no alert even though threshold is met.
    let same = make_summary(1, 0, 0, 0);
    let (send, _) = alert_decision(
        NotifyMode::Regression,
        Severity::Critical,
        Some(&prev),
        &same,
    );
    assert!(!send);

    // Worse: a new critical -> alert + annotation.
    let worse = make_summary(2, 0, 0, 0);
    let (send, info) = alert_decision(
        NotifyMode::Regression,
        Severity::Critical,
        Some(&prev),
        &worse,
    );
    assert!(send);
    let info = info.expect("regression annotated");
    assert_eq!(info.delta_critical, 1);
}

#[test]
fn regression_first_scan_never_alerts() {
    let cur = make_summary(5, 0, 0, 0);
    let (send, _) = alert_decision(NotifyMode::Regression, Severity::Critical, None, &cur);
    assert!(!send);
}

#[test]
fn regression_respects_floor() {
    let prev = prev_session(0, 0, 0, 3); // 3 low
    let cur = make_summary(0, 0, 0, 5); // 5 low, worse only at Low level
    // Floor High: low changes are below the floor -> not a regression.
    let (send, _) = alert_decision(NotifyMode::Regression, Severity::High, Some(&prev), &cur);
    assert!(!send);
    // Floor Low: counts -> regression.
    let (send, info) = alert_decision(NotifyMode::Regression, Severity::Low, Some(&prev), &cur);
    assert!(send);
    assert_eq!(info.unwrap().delta_low, 2);
}

#[test]
fn both_mode_alerts_and_annotates_on_regression() {
    let prev = prev_session(1, 0, 0, 0);
    let worse = make_summary(2, 0, 0, 0);
    let (send, info) = alert_decision(NotifyMode::Both, Severity::Critical, Some(&prev), &worse);
    assert!(send);
    assert!(info.is_some());
}

#[test]
fn both_mode_absolute_without_previous() {
    // Both mode, first scan with findings at/above the floor: sends, not annotated.
    let cur = make_summary(1, 0, 0, 0);
    let (send, info) = alert_decision(NotifyMode::Both, Severity::Critical, None, &cur);
    assert!(send);
    assert!(info.is_none());
}
