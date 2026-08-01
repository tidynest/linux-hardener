#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`pdf`](super).
//!
//! Split out of `output/pdf.rs`. This file sits in the `output/pdf/`
//! directory beside it, which the 2018 path rules allow with no `mod.rs` and
//! no `#[path]`, so `super` still resolves to `crate::output::pdf` and every
//! import carried across unchanged, private items included.

use super::*;
use crate::report::{ComplianceReport, ComplianceSummary, ControlResult};
use chrono::Utc;
use hardener_common::types::{ComplianceFramework, ComplianceProfile};

#[test]
fn test_pdf_formatter_creates_output() {
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

    let formatter = PdfFormatter::new();
    let output = formatter.format(&report);

    // PDF files start with %PDF-
    assert!(output.starts_with("%PDF-"), "Output should be a valid PDF");
    assert!(output.len() > 1000, "PDF should have substantial content");
}

#[test]
fn test_truncate_string() {
    assert_eq!(truncate_string("short", 10), "short");
    assert_eq!(
        truncate_string("this is a longer string", 10),
        "this is a ..."
    );
}

#[test]
fn test_pdf_formatter_default() {
    let _formatter = PdfFormatter;
}
