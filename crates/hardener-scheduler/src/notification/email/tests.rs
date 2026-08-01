#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`email`](super).
//!
//! Split out of `notification/email.rs`. This file sits in the `email/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::notification::email` and every import carried
//! across unchanged, private items included.

use super::*;
use crate::runner::{RegressionInfo, ScanSummary};

fn summary(regression: Option<RegressionInfo>) -> ScanSummary {
    ScanSummary {
        session_id: "s".into(),
        host: "host1".into(),
        plugins_scanned: vec!["kernel".into()],
        total_findings: 3,
        critical_count: 2,
        high_count: 1,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        json_path: None,
        json_hash: None,
        had_errors: false,
        regression,
    }
}

#[test]
fn subject_and_body_plain_without_regression() {
    let s = summary(None);
    assert!(!format_subject(&s).contains("REGRESSION"));
    assert!(!format_body(&s).contains("REGRESSION"));
}

#[test]
fn subject_and_body_show_regression() {
    let s = summary(Some(RegressionInfo {
        previous_started_at: 1_700_000_000,
        previous_total: 1,
        delta_critical: 1,
        delta_high: -2,
        delta_medium: 0,
        delta_low: 0,
    }));
    assert!(format_subject(&s).starts_with("[REGRESSION] "));
    let body = format_body(&s);
    assert!(body.contains("REGRESSION since the previous scan"));
    assert!(body.contains("Critical: +1"));
    assert!(body.contains("High: -2"));
}
