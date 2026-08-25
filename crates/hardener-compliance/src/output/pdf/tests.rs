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
        report_coverage_note: None,
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

/// A one-pass, one-`third` CIS report, so `NotApplicable` gives a scoring
/// denominator (1) different from the catalogue size (2).
fn two_control_report(third: ControlStatus) -> ComplianceReport {
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
            control_status: third,
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

/// The PDF is the artefact an auditor is handed, and it stated a score whose
/// denominator a human had reduced with no sentence anywhere saying so.
///
/// A PDF's text is drawn as subset glyphs, so the sentence cannot be grepped
/// out of the bytes. What is assertable is that the clause exists for this
/// report, that it fits the page once wrapped, and that drawing it puts more
/// content in the document than the same report without an exclusion. That
/// last one is the part a deleted `draw_text` call would break.
#[test]
fn the_summary_box_carries_the_exclusion_clause() {
    let excluded = two_control_report(ControlStatus::NotApplicable);
    let note = crate::output::exclusion_note(&excluded.report_summary)
        .expect("a report with an exclusion has a clause");
    assert!(note.contains("Score measured against 1 of 2 controls"));

    let lines = wrap_text(&note, WRAP_CHARS);
    assert!(lines.len() > 1, "the clause is longer than one 8pt line");
    assert!(
        lines.iter().all(|l| l.chars().count() <= WRAP_CHARS),
        "every wrapped line must fit the content width, got: {lines:?}"
    );
    assert_eq!(
        lines.join(" "),
        note,
        "wrapping must not drop or reword a syllable of it"
    );

    let with_clause = PdfFormatter::new().format_bytes(&excluded);
    let without =
        PdfFormatter::new().format_bytes(&two_control_report(ControlStatus::ManualReview));
    assert!(
        with_clause.len() > without.len(),
        "the clause must actually be drawn: {} bytes with it, {} without",
        with_clause.len(),
        without.len()
    );
}

#[test]
fn wrap_text_leaves_an_overlong_word_whole() {
    // Never truncate: an over-long "word" here is a control id or a hostname,
    // and half an identifier is worse than a line that overhangs.
    assert_eq!(
        wrap_text("a supercalifragilistic b", 5),
        vec!["a", "supercalifragilistic", "b"]
    );
    assert_eq!(wrap_text("", 10), Vec::<String>::new());
}

#[test]
fn test_truncate_string() {
    assert_eq!(truncate_string("short", 10), "short");
    assert_eq!(
        truncate_string("this is a longer string", 10),
        "this is a ..."
    );
}

/// One control under the named framework, enough to draw a page.
fn report_for(framework: ComplianceFramework) -> ComplianceReport {
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
}

/// A set of frameworks renders as one document, not as the first of them.
///
/// Every consumer of this renderer selects a set and exports once, and until
/// `format_all_bytes` existed all five of them wrote `reports[0]`. The check
/// is the byte length rather than a page count, because krilla exposes no
/// reader: two reports must produce materially more document than one, and
/// the single-report rendering must still be exactly what it always was.
#[test]
fn every_selected_framework_reaches_the_document() {
    let cis = report_for(ComplianceFramework::CIS);
    let stig = report_for(ComplianceFramework::STIG);

    let formatter = PdfFormatter::new();
    let one = formatter.format_all_bytes(std::slice::from_ref(&cis));
    let both = formatter.format_all_bytes(&[cis.clone(), stig]);

    assert_eq!(
        one,
        formatter.format_bytes(&cis),
        "a one-report set must render exactly as the single-report path does"
    );
    assert!(
        both.len() > one.len(),
        "two frameworks must carry more document than one, got {} against {}",
        both.len(),
        one.len()
    );
}

/// An empty set yields a real if contentless PDF rather than a panic.
///
/// `reports[0]` panicked, and it was reachable: `parse_frameworks` in the
/// desktop drops unknown identifiers silently, so an export naming none the
/// enum recognises produced an empty vector and indexed it. No caller refuses
/// the export first, so what an operator gets is this: measured at 1457 bytes
/// of PDF 1.7 carrying no pages. The header is asserted rather than the
/// length, because the length is an artefact of krilla's own preamble and
/// would move under a version bump that changed nothing here.
#[test]
fn an_empty_set_renders_a_pdf_rather_than_panicking() {
    let bytes = PdfFormatter::new().format_all_bytes(&[]);

    assert!(
        bytes.starts_with(b"%PDF-"),
        "an empty set must still produce something a reader recognises, got {:?}",
        String::from_utf8_lossy(&bytes[..bytes.len().min(12)])
    );
}
