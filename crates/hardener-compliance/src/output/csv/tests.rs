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
        report_coverage_note: None,
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

/// Reads a CSV document the way a spreadsheet does, per RFC 4180.
///
/// Written out here rather than pulled in as a dependency, because what is
/// needed is one reader in one test rather than a crate in the shipping
/// graph. It is deliberately strict: a bare quote inside an unquoted field
/// and an unterminated quoted field both panic, since a renderer producing
/// either has already broken the row for every real consumer.
fn read_csv(document: &str) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut chars = document.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' if field.is_empty() => {
                loop {
                    match chars.next() {
                        Some('"') if chars.peek() == Some(&'"') => {
                            chars.next();
                            field.push('"');
                        }
                        Some('"') => break,
                        Some(ch) => field.push(ch),
                        None => panic!("unterminated quoted field in:\n{document}"),
                    }
                }
                match chars.peek() {
                    Some(',') | Some('\n') | None => {}
                    Some(other) => panic!("text after a closing quote: {other:?}"),
                }
            }
            '"' => panic!("bare quote inside an unquoted field in:\n{document}"),
            ',' => record.push(std::mem::take(&mut field)),
            '\n' => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
            }
            _ => field.push(c),
        }
    }
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    records
}

/// The reader above is itself a check, so it is pinned before anything is
/// judged by it. Otherwise a reader that silently mis-splits would report
/// the renderer green for the same reason the substring assertions do.
#[test]
fn the_csv_reader_splits_the_way_a_spreadsheet_does() {
    assert_eq!(read_csv("a,b\n"), vec![vec!["a", "b"]]);
    assert_eq!(
        read_csv("\"with,comma\",b\n"),
        vec![vec!["with,comma", "b"]]
    );
    assert_eq!(
        read_csv("\"say \"\"hi\"\"\",b\n"),
        vec![vec!["say \"hi\"", "b"]]
    );
    assert_eq!(
        read_csv("\"two\nlines\",b\n"),
        vec![vec!["two\nlines", "b"]]
    );
    assert_eq!(read_csv("a,b"), vec![vec!["a", "b"]]);
}

/// The rendered document is handed to a reader, which nothing had ever done.
///
/// Every other assertion in this file searches the rendered string for a
/// substring, and a substring cannot see a column boundary. With a title
/// carrying a comma, dropping `escape_csv_field` from that column leaves
/// `output.contains("Ensure ASLR is enabled")` true, leaves every existing
/// test in this file green, and shifts Status and Finding Count one place
/// right for the positional consumer `CSV_HEADER`'s own comment describes.
#[test]
fn a_field_carrying_a_comma_does_not_shift_the_columns_after_it() {
    let title = "Ensure /etc/passwd, /etc/group and /etc/shadow are 0644";
    let section = "Initial Setup, Filesystem";
    let controls = vec![ControlResult {
        control_id: "1.5.1".to_string(),
        control_title: title.to_string(),
        control_section: section.to_string(),
        control_status: ControlStatus::Fail,
        control_findings: vec![crate::output::test_support::finding("Live", false)],
    }];
    let report = ComplianceReport {
        report_framework: ComplianceFramework::CIS,
        report_profile: ComplianceProfile::default(),
        report_coverage_note: None,
        report_generated_at: Utc::now(),
        report_summary: ComplianceSummary::from_controls(&controls),
        report_controls: controls,
    };

    let output = CsvFormatter::new().format(&report);
    let records = read_csv(&output);

    let header: Vec<&str> = CSV_HEADER.trim_end().split(',').collect();
    assert_eq!(
        records.len(),
        2,
        "one header and one control row: {records:?}"
    );
    assert_eq!(records[0], header, "the header must survive the reader");

    let row = &records[1];
    assert_eq!(
        row.len(),
        header.len(),
        "a row must carry exactly one field per column, got {row:?}"
    );
    assert_eq!(
        row[4], title,
        "the title must round-trip through the reader"
    );
    assert_eq!(row[5], section, "the section must round-trip too");
    assert_eq!(
        row[6], "FAIL",
        "Status must stay in the column named for it"
    );
    assert_eq!(row[7], "1", "Finding Count must stay in its own column");
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
