#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`text`](super).
//!
//! Split out of `output/text.rs`. This file sits in the `output/text/`
//! directory beside it, which the 2018 path rules allow with no `mod.rs` and
//! no `#[path]`, so `super` still resolves to `crate::output::text` and every
//! import carried across unchanged, private items included.

use super::*;
use crate::report::{ComplianceReport, ComplianceSummary, ControlResult};
use chrono::Utc;
use hardener_common::types::{ComplianceFramework, ComplianceProfile};

#[test]
fn test_text_formatter_basic() {
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

    let formatter = TextFormatter::new();
    let output = formatter.format(&report);

    assert!(output.contains("CIS Benchmark Compliance Report"));
    assert!(output.contains("Center for Internet Security Benchmarks for Linux"));
    assert!(output.contains("[PASS]"));
    assert!(output.contains("[FAIL]"));
    assert!(output.contains("Score:          50.0%"));
}

/// A single-control CIS report carrying the given status and findings.
fn report_with(status: ControlStatus, findings: Vec<hardener_types::Finding>) -> ComplianceReport {
    let controls = vec![ControlResult {
        control_id: "1.5.1".to_string(),
        control_title: "Ensure ASLR is enabled".to_string(),
        control_section: "Initial Setup".to_string(),
        control_status: status,
        control_findings: findings,
    }];
    ComplianceReport {
        report_framework: ComplianceFramework::CIS,
        report_profile: ComplianceProfile::default(),
        report_coverage_note: None,
        report_generated_at: Utc::now(),
        report_summary: ComplianceSummary::from_controls(&controls),
        report_controls: controls,
    }
}

#[test]
fn passing_control_shows_the_deviation_its_exception_documents() {
    // A control that passes only because the config documents the deviation
    // must not read as an untouched, genuinely compliant check.
    let report = report_with(
        ControlStatus::Pass,
        vec![crate::output::test_support::finding(
            "Root login permitted",
            true,
        )],
    );
    let output = TextFormatter::new().format(&report);

    assert!(output.contains("[PASS]"));
    assert!(
        output.contains("POLICY EXCEPTION: Root login permitted"),
        "an excepted deviation must be shown as evidence, got:\n{output}"
    );
}

#[test]
fn failing_control_does_not_render_an_excepted_finding_as_a_violation() {
    // Mixed control: one live violation and one documented deviation. Both
    // are listed, but only the live one carries a severity.
    let report = report_with(
        ControlStatus::Fail,
        vec![
            crate::output::test_support::finding("Root login permitted", true),
            crate::output::test_support::finding("Password auth enabled", false),
        ],
    );
    let output = TextFormatter::new().format(&report);

    assert!(output.contains("POLICY EXCEPTION: Root login permitted"));
    assert!(output.contains("HIGH: Password auth enabled"));
}

#[test]
fn an_excluded_control_is_named_so_the_score_explains_its_own_denominator() {
    // Declaring a control not applicable removes it from the denominator and
    // so raises the score. The artefact must name what stopped counting, or a
    // score that rose because a human said so reads exactly like one that rose
    // because the host improved.
    let report = report_with(ControlStatus::NotApplicable, vec![]);
    let output = TextFormatter::new().format(&report);

    assert!(
        output.contains("\nNot applicable\n"),
        "the excluded controls need a heading of their own, distinct from the \
         summary's `Not Applicable: N` count, got:\n{output}"
    );
    assert!(
        output.contains("1.5.1 Ensure ASLR is enabled"),
        "each excluded control is named, got:\n{output}"
    );
}

/// An empty STIG report under the given profile.
fn stig_report(profile: ComplianceProfile) -> ComplianceReport {
    ComplianceReport {
        report_framework: ComplianceFramework::STIG,
        report_profile: profile,
        report_coverage_note: None,
        report_generated_at: Utc::now(),
        report_controls: vec![],
        report_summary: ComplianceSummary::from_controls(&[]),
    }
}

#[test]
fn test_text_formatter_profile_label_in_heading() {
    let formatter = TextFormatter::new();

    let rhel10 = formatter.format(&stig_report(ComplianceProfile::Rhel10));
    assert!(rhel10.contains("DISA STIG Compliance Report (DISA RHEL 10 STIG V1R1)"));

    // Generic STIG names its baseline honestly instead of implying universality.
    let generic = formatter.format(&stig_report(ComplianceProfile::Generic));
    assert!(generic.contains("DISA STIG Compliance Report (RHEL 8 baseline IDs)"));
}
