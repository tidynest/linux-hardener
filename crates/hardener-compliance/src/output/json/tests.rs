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

/// The machine-readable renderers name the profile whose identifier scheme
/// they used.
///
/// `report --framework stig --profile rhel10` and `--profile generic` produce
/// completely disjoint control id sets: 25 controls of the form
/// `RHEL-10-200531` against 22 of another scheme, 47 differing lines and not
/// one in common. The text, HTML and PDF renderers say which, through
/// `report_title`. JSON and CSV did not, so two runs that agree on nothing
/// produced byte-indistinguishable metadata and a consumer archiving evidence
/// could not tell which scheme a stored report used (#163).
#[test]
fn json_names_the_profile_it_rendered() {
    let report_for = |profile| ComplianceReport {
        report_framework: ComplianceFramework::STIG,
        report_profile: profile,
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
    let generic = formatter.format(&report_for(ComplianceProfile::Generic));
    let rhel10 = formatter.format(&report_for(ComplianceProfile::Rhel10));

    assert!(
        generic.contains("report_profile"),
        "the field must be present, not merely differ: {generic}"
    );

    // The two must be distinguishable. Comparing the rendered documents rather
    // than asserting a spelling means this still holds if the serialised
    // representation changes, and fails if the field is emitted as a constant.
    let strip = |s: &str| {
        s.lines()
            .filter(|l| !l.contains("report_generated_at"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_ne!(
        strip(&generic),
        strip(&rhel10),
        "two profiles with disjoint control id schemes must not render \
         identical JSON"
    );
}

/// The rendered document is handed to a deserialiser, which nothing had done.
///
/// Every other assertion in this file searches the rendered string, and a
/// substring cannot see nesting. `output.contains("\"summary_passing\":1")`
/// holds whether that field sits inside `report_summary` or is flattened
/// beside it at the top level, and the second shape breaks every consumer
/// reading the documented structure while leaving this file green.
#[test]
fn the_rendered_json_parses_back_into_the_documented_shape() {
    let controls = vec![ControlResult {
        control_id: "1.5.1".to_string(),
        control_title: "Ensure ASLR is enabled".to_string(),
        control_section: "Initial Setup".to_string(),
        control_status: ControlStatus::Pass,
        control_findings: vec![],
    }];
    let report = ComplianceReport {
        report_framework: ComplianceFramework::CIS,
        report_profile: ComplianceProfile::default(),
        report_coverage_note: None,
        report_generated_at: Utc::now(),
        report_summary: ComplianceSummary::from_controls(&controls),
        report_controls: controls,
    };

    let output = JsonFormatter::new().format(&report);
    let value: serde_json::Value =
        serde_json::from_str(&output).expect("the renderer must emit parseable JSON");

    assert_eq!(value["report_framework"], "CIS");
    assert_eq!(value["report_framework_name"], "CIS Benchmark");
    assert_eq!(
        value["report_controls"].as_array().map(Vec::len),
        Some(1),
        "controls must be an array of the controls, not a scalar"
    );
    assert_eq!(value["report_controls"][0]["control_id"], "1.5.1");
    assert_eq!(
        value["report_summary"]["summary_passing"], 1,
        "the summary must stay nested under its own key"
    );
    assert!(
        value.get("report_coverage_note").is_none(),
        "a complete run omits the note rather than carrying a null"
    );
}

/// `format_all` emits one array, and it is the entry point every consumer
/// uses: the CLI, the report wizard and the desktop all call it, and no test
/// in this crate entered it. The default trait implementation joins rendered
/// documents with a blank line, which for JSON would be two objects in a row
/// and parseable by nothing.
#[test]
fn format_all_emits_one_array_a_consumer_can_parse() {
    let report_for = |framework| ComplianceReport {
        report_framework: framework,
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

    let output = JsonFormatter::new().format_all(&[
        report_for(ComplianceFramework::CIS),
        report_for(ComplianceFramework::STIG),
    ]);
    let value: serde_json::Value =
        serde_json::from_str(&output).expect("format_all must emit parseable JSON");

    let reports = value.as_array().expect("format_all emits an array");
    assert_eq!(reports.len(), 2, "every selected framework is carried");
    assert_eq!(reports[0]["report_framework"], "CIS");
    assert_eq!(reports[1]["report_framework"], "STIG");
}
