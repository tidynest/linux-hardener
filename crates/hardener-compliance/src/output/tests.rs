#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Tests for [`ReportFormatter`](super::ReportFormatter)'s own defaults.
//!
//! The five formatters each had their own test module and the trait beneath
//! them had none, so its two defaults were reached by every one of them and
//! asserted by none.
//!
//! Both were measured before these were written, by mutating the default and
//! running the whole workspace:
//!
//! - `format_all_bytes` put back to `self.format_bytes(&reports[0])`, the exact
//!   shape its own doc comment records as the defect it was written to fix:
//!   **2277 passed, 0 failed.** Every non-PDF export would have rendered the
//!   first framework and dropped the rest without a word.
//! - the default `format_all`'s `join("\n\n")` reduced to `join("")`:
//!   **2277 passed, 0 failed.** Two text reports would have run together with
//!   no boundary between them.
//!
//! Only `PdfFormatter` was covered, and only because it overrides
//! `format_all_bytes` and its own module tests the override. An override being
//! proven says nothing about the default the other four inherit.

use super::*;
use crate::report::{ComplianceReport, ComplianceSummary, ControlResult};
use chrono::Utc;
use hardener_common::types::{ComplianceFramework, ComplianceProfile, ControlStatus};

/// A one-control report for `framework`. The control is identical across
/// frameworks on purpose: the framework name is then the only thing that
/// distinguishes two reports, so a renderer that dropped one cannot be masked
/// by content that differs anyway.
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

/// A formatter that overrides nothing, so what it exercises is the trait
/// itself rather than any shipping renderer's idea of a document.
struct BareFormatter;

impl ReportFormatter for BareFormatter {
    fn format(&self, report: &ComplianceReport) -> String {
        report.report_framework.to_string()
    }
}

/// The default combines every report, in the order given, separated by a blank
/// line.
///
/// The separator is asserted, not just the presence of both names. Reduce the
/// join to `""` and two text reports run together with no boundary, which for
/// the one formatter that inherits this is the difference between a readable
/// export and one an operator cannot segment.
#[test]
fn the_default_format_all_joins_every_report_with_a_blank_line() {
    let output = BareFormatter.format_all(&[
        report_for(ComplianceFramework::CIS),
        report_for(ComplianceFramework::STIG),
        report_for(ComplianceFramework::HIPAA),
    ]);

    assert_eq!(output, "CIS\n\nSTIG\n\nHIPAA");
}

/// **The mutation this module exists for.** The default byte path must carry
/// every report, not the first of them.
///
/// `format_all_bytes` was added because every caller wanting bytes for a set
/// reached for `format_bytes(&reports[0])`, which rendered one framework, threw
/// the rest away silently, and panicked on an empty set. The PDF override is
/// guarded in its own module; the default the other four inherit was not.
#[test]
fn the_default_format_all_bytes_carries_every_report() {
    let bytes = BareFormatter.format_all_bytes(&[
        report_for(ComplianceFramework::CIS),
        report_for(ComplianceFramework::STIG),
    ]);

    assert_eq!(String::from_utf8(bytes).expect("utf-8"), "CIS\n\nSTIG");
}

/// An empty set is empty output, not a panic.
///
/// `reports[0]` panicked here, and it was reachable: the desktop's
/// `parse_frameworks` drops unrecognised identifiers silently, so an export
/// naming none the enum knows produces an empty vector. That the result is
/// contentless is a separate open question about refusing the export; that it
/// does not panic is settled here.
#[test]
fn an_empty_set_is_empty_output_rather_than_a_panic() {
    assert_eq!(BareFormatter.format_all(&[]), "");
    assert!(BareFormatter.format_all_bytes(&[]).is_empty());
}

/// **Every shipping formatter carries every selected framework**, whether it
/// inherits the default or overrides it.
///
/// A total check rather than four per-formatter ones. The failure it guards is
/// a renderer dropping reports after the first, and that failure does not care
/// which of the two paths a formatter took to get there: CSV and JSON override
/// `format_all`, HTML overrides it too, Text inherits it, and all four inherit
/// `format_all_bytes`. Testing the ones that override says nothing about the
/// one that does not, which is exactly how this went unnoticed.
///
/// PDF is absent because it is feature-gated and its own module already drives
/// the same guarantee through its override, by byte length, since krilla
/// exposes no reader.
#[test]
fn every_shipping_formatter_carries_both_frameworks_through_format_all_bytes() {
    let reports = [
        report_for(ComplianceFramework::CIS),
        report_for(ComplianceFramework::STIG),
    ];

    let formatters: [(&str, Box<dyn ReportFormatter>); 4] = [
        ("text", Box::new(TextFormatter::new())),
        ("json", Box::new(JsonFormatter::pretty())),
        ("csv", Box::new(CsvFormatter::new())),
        ("html", Box::new(HtmlFormatter::new())),
    ];

    for (name, formatter) in formatters {
        let rendered = String::from_utf8(formatter.format_all_bytes(&reports))
            .unwrap_or_else(|_| panic!("{name} must render as UTF-8"));

        for framework in ["CIS", "STIG"] {
            assert!(
                rendered.contains(framework),
                "{name} dropped {framework}: a selected framework must reach the file"
            );
        }
    }
}
