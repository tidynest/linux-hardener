#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`csv`](super).
//!
//! Split out of `output/csv.rs`. This file sits in the `output/csv/`
//! directory beside it, which the 2018 path rules allow with no `mod.rs` and
//! no `#[path]`, so `super` still resolves to `crate::output::csv` and every
//! import carried across unchanged, private items included.

use super::*;
use crate::report::{ComplianceReport, ComplianceSummary, ControlResult};
use chrono::Utc;
use hardener_common::types::{ComplianceFramework, ComplianceProfile};

#[test]
fn test_csv_formatter_basic() {
    let report = ComplianceReport {
        report_framework: ComplianceFramework::CIS,
        report_profile: ComplianceProfile::default(),
        report_generated_at: Utc::now(),
        report_controls: vec![
            ControlResult {
                control_id: "1.5.1".to_string(),
                control_title: "Ensure ASLR is enabled".to_string(),
                control_section: "Initial Setup".to_string(),
                control_status: ControlStatus::Pass,
                control_findings: vec![],
            },
            ControlResult {
                control_id: "1.5.2".to_string(),
                control_title: "Ensure ptrace is restricted".to_string(),
                control_section: "Initial Setup".to_string(),
                control_status: ControlStatus::Fail,
                control_findings: vec![],
            },
        ],
        report_summary: ComplianceSummary {
            summary_total_controls: 2,
            summary_passing: 1,
            summary_failing: 1,
            summary_not_applicable: 0,
            summary_manual_review: 0,
            summary_score_percentage: 50.0,
        },
    };

    let formatter = CsvFormatter::new();
    let output = formatter.format(&report);

    assert!(output.contains("Framework,Framework Name,Framework Description,Control ID"));
    assert!(output.contains("CIS,CIS Benchmark"));
    assert!(output.contains("Center for Internet Security Benchmarks for Linux"));
    assert!(output.contains("PASS"));
    assert!(output.contains("FAIL"));
}

#[test]
fn finding_count_counts_live_violations_only() {
    // The count column tracks the violations behind the status. A control
    // that passes because its sole deviation is documented must not report
    // a finding against itself.
    let controls = vec![
        ControlResult {
            control_id: "1.5.1".to_string(),
            control_title: "Ensure ASLR is enabled".to_string(),
            control_section: "Initial Setup".to_string(),
            control_status: ControlStatus::Pass,
            control_findings: vec![crate::output::test_support::finding("Excepted", true)],
        },
        ControlResult {
            control_id: "1.5.2".to_string(),
            control_title: "Ensure ptrace is restricted".to_string(),
            control_section: "Initial Setup".to_string(),
            control_status: ControlStatus::Fail,
            control_findings: vec![
                crate::output::test_support::finding("Excepted", true),
                crate::output::test_support::finding("Live", false),
            ],
        },
    ];
    let report = ComplianceReport {
        report_framework: ComplianceFramework::CIS,
        report_profile: ComplianceProfile::default(),
        report_generated_at: Utc::now(),
        report_summary: ComplianceSummary::from_controls(&controls),
        report_controls: controls,
    };

    let output = CsvFormatter::new().format(&report);

    assert!(
        output.contains("Initial Setup,PASS,0"),
        "a control passed by an exception has no live finding, got:\n{output}"
    );
    assert!(
        output.contains("Initial Setup,FAIL,1"),
        "only the live finding counts against a failing control, got:\n{output}"
    );
}

#[test]
fn test_csv_escape() {
    assert_eq!(escape_csv_field("simple"), "simple");
    assert_eq!(escape_csv_field("with,comma"), "\"with,comma\"");
    assert_eq!(escape_csv_field("with\"quote"), "\"with\"\"quote\"");
}

#[test]
fn test_csv_formula_injection_guard() {
    // Formula-triggering characters get tab-prefixed inside quotes
    assert_eq!(
        escape_csv_field("=cmd|'/C calc'!A0"),
        "\"\t=cmd|'/C calc'!A0\""
    );
    assert_eq!(escape_csv_field("+1+1"), "\"\t+1+1\"");
    assert_eq!(escape_csv_field("-1-1"), "\"\t-1-1\"");
    assert_eq!(escape_csv_field("@SUM(A1)"), "\"\t@SUM(A1)\"");
    // Normal text unchanged
    assert_eq!(
        escape_csv_field("Ensure ASLR is enabled"),
        "Ensure ASLR is enabled"
    );
}
