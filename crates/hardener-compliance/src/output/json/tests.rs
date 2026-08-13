#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`json`](super).
//!
//! Split out of `output/json.rs`. This file sits in the `output/json/`
//! directory beside it, which the 2018 path rules allow with no `mod.rs` and
//! no `#[path]`, so `super` still resolves to `crate::output::json` and every
//! import carried across unchanged, private items included.

use super::*;
use crate::report::{ComplianceReport, ComplianceSummary, ControlResult};
use chrono::Utc;
use hardener_common::types::{ComplianceFramework, ComplianceProfile, ControlStatus};

#[test]
fn test_json_formatter_basic() {
    let report = ComplianceReport {
        report_framework: ComplianceFramework::CIS,
        report_profile: ComplianceProfile::default(),
        report_coverage_note: None,
        report_generated_at: Utc::now(),
        report_controls: vec![ControlResult {
            control_id: "1.5.1".to_string(),
            control_title: "Ensure ASLR is enabled".to_string(),
            control_section: "Initial Setup".to_string(),
            control_status: ControlStatus::Pass,
            control_findings: vec![],
        }],
        report_summary: ComplianceSummary {
            summary_total_controls: 1,
            summary_passing: 1,
            summary_failing: 0,
            summary_not_applicable: 0,
            summary_manual_review: 0,
            summary_score_percentage: 100.0,
        },
    };

    let formatter = JsonFormatter::new();
    let output = formatter.format(&report);

    assert!(output.contains("\"report_framework\":\"CIS\""));
    assert!(output.contains("\"report_framework_name\":\"CIS Benchmark\""));
    assert!(output.contains(
        "\"report_framework_description\":\"Center for Internet Security Benchmarks for Linux\""
    ));
    assert!(output.contains("\"control_id\":\"1.5.1\""));
    assert!(output.contains("\"summary_score_percentage\":100.0"));
}

#[test]
fn test_json_formatter_pretty() {
    let report = ComplianceReport {
        report_framework: ComplianceFramework::CIS,
        report_profile: ComplianceProfile::default(),
        report_coverage_note: None,
        report_generated_at: Utc::now(),
        report_controls: vec![],
        report_summary: ComplianceSummary {
            summary_total_controls: 0,
            summary_passing: 0,
            summary_failing: 0,
            summary_not_applicable: 0,
            summary_manual_review: 0,
            summary_score_percentage: 100.0,
        },
    };

    let formatter = JsonFormatter::pretty();
    let output = formatter.format(&report);

    // Pretty format should have newlines
    assert!(output.contains('\n'));
    assert!(output.contains("  ")); // Indentation
}
