#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`html`](super).
//!
//! Split out of `output/html.rs`. This file sits in the `output/html/`
//! directory beside it, which the 2018 path rules allow with no `mod.rs` and
//! no `#[path]`, so `super` still resolves to `crate::output::html` and every
//! import carried across unchanged, private items included.

use super::*;
use crate::report::{ComplianceReport, ComplianceSummary, ControlResult};
use chrono::Utc;
use hardener_common::types::{ComplianceFramework, ComplianceProfile};

#[test]
fn test_html_formatter_basic() {
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

    let formatter = HtmlFormatter::new();
    let output = formatter.format(&report);

    assert!(output.contains("<!DOCTYPE html>"));
    assert!(output.contains("CIS Benchmark Compliance Report"));
    assert!(output.contains("100.0%"));
    assert!(output.contains("PASS"));
}

#[test]
fn passing_control_shows_the_deviation_its_exception_documents() {
    // A control that passes only because the config documents the deviation
    // must render the deviation, styled as an exception rather than as a
    // failure row.
    let controls = vec![ControlResult {
        control_id: "1.5.1".to_string(),
        control_title: "Ensure ASLR is enabled".to_string(),
        control_section: "Initial Setup".to_string(),
        control_status: ControlStatus::Pass,
        control_findings: vec![crate::output::test_support::finding(
            "Root login permitted",
            true,
        )],
    }];
    let report = ComplianceReport {
        report_framework: ComplianceFramework::CIS,
        report_profile: ComplianceProfile::default(),
        report_coverage_note: None,
        report_generated_at: Utc::now(),
        report_summary: ComplianceSummary::from_controls(&controls),
        report_controls: controls,
    };

    let output = HtmlFormatter::new().format(&report);

    assert!(output.contains("POLICY EXCEPTION"));
    assert!(output.contains("Root login permitted"));
    assert!(
        output.contains("tr class=\"exception\""),
        "an excepted deviation must not be styled as a failure row, got:\n{output}"
    );
}

/// A one-pass, one-excluded CIS report, so the scoring denominator (1) and the
/// catalogue size (2) are different numbers.
fn report_with_one_exclusion() -> ComplianceReport {
    let controls = vec![
        ControlResult {
            control_id: "1.5.1".to_string(),
            control_title: "Ensure ASLR is enabled".to_string(),
            control_section: "Initial Setup".to_string(),
            control_status: ControlStatus::Pass,
            control_findings: vec![],
        },
        ControlResult {
            control_id: "7.1".to_string(),
            control_title: "Physical entry controls".to_string(),
            control_section: "Physical".to_string(),
            control_status: ControlStatus::NotApplicable,
            control_findings: vec![],
        },
    ];
    ComplianceReport {
        report_framework: ComplianceFramework::CIS,
        report_profile: ComplianceProfile::default(),
        report_coverage_note: None,
        report_generated_at: Utc::now(),
        report_summary: ComplianceSummary::from_controls(&controls),
        report_controls: controls,
    }
}

/// The same requirement the text formatter carries: a score whose denominator
/// a human reduced says so beside the figure. The HTML report is shared, so it
/// is read by people who never saw the terminal output.
#[test]
fn the_score_box_says_a_human_reduced_the_denominator() {
    let output = HtmlFormatter::new().format(&report_with_one_exclusion());

    assert!(
        output.contains("class=\"scope-note\""),
        "the clause needs its own class or it cannot be styled apart from the \
         stats, got:\n{output}"
    );
    assert!(
        output.contains("Score measured against 1 of 2 controls"),
        "the clause must name the scoring denominator, got:\n{output}"
    );
    assert!(
        output.contains("an operator declared 1 not applicable"),
        "and must make plain that a human moved it, got:\n{output}"
    );
    assert!(
        output.contains(".scope-note {"),
        "the embedded stylesheet must carry a rule for it, or the class is \
         inert, got:\n{output}"
    );
}

/// The negative control: no exclusions, no clause.
#[test]
fn a_report_with_no_exclusions_carries_no_scope_clause() {
    let mut report = report_with_one_exclusion();
    report.report_controls[1].control_status = ControlStatus::ManualReview;
    report.report_summary = ComplianceSummary::from_controls(&report.report_controls);

    let output = HtmlFormatter::new().format(&report);
    assert_eq!(output.matches("class=\"scope-note\"").count(), 0);
}

#[test]
fn test_html_escape() {
    assert_eq!(html_escape("<script>"), "&lt;script&gt;");
    assert_eq!(html_escape("a & b"), "a &amp; b");
}

/// One document per file, whatever the number of frameworks in it.
///
/// The trait's default `format_all` joins whole rendered documents with a
/// blank line. For HTML that produced one `<!DOCTYPE html>`, `<html>`,
/// `<head>` and `<body>` per selected framework in a single file, plus one
/// copy of the whole embedded stylesheet each. A browser recovers from it and
/// shows the content, which is exactly why no eyeball caught it and no
/// substring assertion could: every framework's markup really was present.
///
/// Counting the structural landmarks is what a parser would object to,
/// without taking a parser as a dependency.
#[test]
fn several_frameworks_render_as_one_document() {
    let report_for = |framework| {
        let controls = vec![ControlResult {
            control_id: "1.5.1".to_string(),
            control_title: "Ensure ASLR is enabled".to_string(),
            control_section: "Initial Setup".to_string(),
            control_status: ControlStatus::Pass,
            control_findings: vec![],
        }];
        ComplianceReport {
            report_framework: framework,
            report_profile: ComplianceProfile::default(),
            report_coverage_note: None,
            report_generated_at: Utc::now(),
            report_summary: ComplianceSummary::from_controls(&controls),
            report_controls: controls,
        }
    };

    let output = HtmlFormatter::new().format_all(&[
        report_for(ComplianceFramework::CIS),
        report_for(ComplianceFramework::STIG),
    ]);

    assert_eq!(
        output.matches("<!DOCTYPE html>").count(),
        1,
        "a file carries one document type declaration, not one per framework"
    );
    assert_eq!(output.matches("<html").count(), 1, "one root element");
    assert_eq!(output.matches("</html>").count(), 1, "closed once");
    assert_eq!(output.matches("<body>").count(), 1, "one body");
    assert_eq!(
        output.matches("<style>").count(),
        1,
        "the stylesheet is shared, not repeated per framework"
    );

    // The point of one document is that it still carries every framework.
    assert!(
        output.contains("CIS Benchmark"),
        "the first framework is present"
    );
    assert!(
        output.contains("DISA STIG"),
        "the second framework is present too, got:\n{output}"
    );
}

/// A single-framework export is unchanged by the above.
///
/// `format` now delegates to `format_all` over a one-element slice, so this
/// pins that the delegation added nothing and removed nothing: header once,
/// body once, footer once, exactly as it was rendered before.
#[test]
fn a_single_framework_document_is_header_body_footer() {
    let output = HtmlFormatter::new().format(&report_with_one_exclusion());

    assert!(output.starts_with("<!DOCTYPE html>"));
    assert!(output.trim_end().ends_with("</html>"));
    assert_eq!(output.matches("<!DOCTYPE html>").count(), 1);
    assert_eq!(output.matches("</html>").count(), 1);
}
