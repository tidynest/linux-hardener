#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`generator`](super).
//!
//! Split out of `generator.rs`. This file sits in the `generator/` directory
//! beside it, which the 2018 path rules allow with no `mod.rs` and no
//! `#[path]`, so `super` still resolves to `crate::generator` and every
//! import carried across unchanged, private items included.

use super::*;
use crate::config::{OutputFormat, Scenario};
use hardener_common::types::{
    ComplianceProfile, FindingCategory, FindingPolicyException, Severity,
};

/// A finding carrying a single CIS mapping for the given control id.
fn cis_finding(control_id: &str) -> Finding {
    Finding {
        finding_category: FindingCategory::Kernel,
        finding_current_value: "1".to_string(),
        finding_description: "Test finding".to_string(),
        finding_explanation: "Test explanation".to_string(),
        finding_id: format!("test_{}", control_id),
        finding_impact: "Test impact".to_string(),
        finding_recommended_value: "2".to_string(),
        finding_remediation_steps: vec!["Fix it".to_string()],
        finding_severity: Severity::Medium,
        finding_title: "Test Finding".to_string(),
        finding_compliance: vec![mapping(ComplianceFramework::CIS, control_id)],
        finding_policy_exception: None,
    }
}

/// A finding carrying a single STIG mapping for the given control id.
fn stig_finding(control_id: &str) -> Finding {
    let mut finding = cis_finding(control_id);
    finding.finding_compliance = vec![mapping(ComplianceFramework::STIG, control_id)];
    finding
}

fn mapping(framework: ComplianceFramework, id: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: framework,
        compliance_control_id: id.to_string(),
        compliance_control_title: format!("Control {id}"),
        compliance_section: Some("Test Section".to_string()),
    }
}

fn config_for(framework: ComplianceFramework) -> ReportConfig {
    config_with_profile(framework, ComplianceProfile::Generic)
}

fn config_with_profile(framework: ComplianceFramework, profile: ComplianceProfile) -> ReportConfig {
    ReportConfig {
        scenario: Scenario::Custom(vec![framework]),
        formats: vec![OutputFormat::Text],
        output_dir: None,
        profile,
    }
}

#[test]
fn assessed_control_passes_on_clean_system() {
    // CIS 1.5.1 is in coverage; with no finding it must report Pass (Option B).
    let coverage = vec![mapping(ComplianceFramework::CIS, "1.5.1")];
    let generator = ReportGenerator::new(config_for(ComplianceFramework::CIS), coverage);
    let report = generator.generate(&[], &[]).pop().unwrap();

    let result = report
        .report_controls
        .iter()
        .find(|c| c.control_id == "1.5.1")
        .expect("1.5.1 in catalogue");
    assert_eq!(result.control_status, ControlStatus::Pass);
}

#[test]
fn unchecked_control_reports_manual_review_not_pass() {
    // CIS 1.5.1 is covered (would Pass on a clean system, per the test
    // above), but this run could not evaluate the check that covers it.
    // The absence of a finding proves nothing here, so it must not
    // auto-pass.
    let coverage = vec![mapping(ComplianceFramework::CIS, "1.5.1")];
    let generator = ReportGenerator::new(config_for(ComplianceFramework::CIS), coverage);
    let unchecked = vec![UncheckedCheck {
        unchecked_check_id: "pam-minlen".to_string(),
        unchecked_title: "PAM setting: minlen".to_string(),
        unchecked_category: FindingCategory::Authentication,
        unchecked_reason: "requires root".to_string(),
        unchecked_blocker: hardener_types::UncheckedBlocker::Privilege,
        unchecked_compliance: vec![mapping(ComplianceFramework::CIS, "1.5.1")],
    }];
    let report = generator.generate(&[], &unchecked).pop().unwrap();

    let control = report
        .report_controls
        .iter()
        .find(|c| c.control_id == "1.5.1")
        .unwrap();
    assert_eq!(control.control_status, ControlStatus::ManualReview);
}

#[test]
fn finding_beats_unchecked_for_the_same_control() {
    // A control can carry both a real finding and an unchecked covering
    // check (e.g. one of two covering checks ran and failed). The proven
    // failure outranks the uncertainty: Fail wins over ManualReview.
    let coverage = vec![mapping(ComplianceFramework::CIS, "1.5.1")];
    let generator = ReportGenerator::new(config_for(ComplianceFramework::CIS), coverage);
    let unchecked = vec![UncheckedCheck {
        unchecked_check_id: "pam-minlen".to_string(),
        unchecked_title: "PAM setting: minlen".to_string(),
        unchecked_category: FindingCategory::Authentication,
        unchecked_reason: "requires root".to_string(),
        unchecked_blocker: hardener_types::UncheckedBlocker::Privilege,
        unchecked_compliance: vec![mapping(ComplianceFramework::CIS, "1.5.1")],
    }];
    let report = generator
        .generate(&[cis_finding("1.5.1")], &unchecked)
        .pop()
        .unwrap();

    let control = report
        .report_controls
        .iter()
        .find(|c| c.control_id == "1.5.1")
        .unwrap();
    assert_eq!(control.control_status, ControlStatus::Fail);
}

#[test]
fn mapped_finding_fails_its_control() {
    let coverage = vec![mapping(ComplianceFramework::CIS, "1.5.1")];
    let generator = ReportGenerator::new(config_for(ComplianceFramework::CIS), coverage);
    let report = generator
        .generate(&[cis_finding("1.5.1")], &[])
        .pop()
        .unwrap();

    assert!(report.report_summary.summary_failing >= 1);
    let result = report
        .report_controls
        .iter()
        .find(|c| c.control_id == "1.5.1")
        .unwrap();
    assert_eq!(result.control_status, ControlStatus::Fail);
}

#[test]
fn excepted_finding_does_not_fail_control() {
    // A finding annotated with a policy exception (set by Plugin::scan when
    // the value matches a valid config exception) must not drive its
    // control to Fail: the annotation is honoured, not merely recorded.
    let coverage = vec![mapping(ComplianceFramework::CIS, "1.5.1")];
    let generator = ReportGenerator::new(config_for(ComplianceFramework::CIS), coverage);
    let mut excepted = cis_finding("1.5.1");
    excepted.finding_policy_exception = Some(FindingPolicyException::default());
    let report = generator.generate(&[excepted], &[]).pop().unwrap();

    let result = report
        .report_controls
        .iter()
        .find(|c| c.control_id == "1.5.1")
        .expect("1.5.1 in catalogue");
    assert_ne!(result.control_status, ControlStatus::Fail);
    // The deviation is still evidence: a control passed by an exception
    // must not be indistinguishable from a genuinely compliant one.
    assert_eq!(
        result.control_findings.len(),
        1,
        "the excepted finding must stay attached as visible evidence"
    );
    assert!(
        result.control_findings[0]
            .finding_policy_exception
            .is_some()
    );
}

#[test]
fn live_finding_still_fails_a_control_that_also_has_an_excepted_one() {
    // Catalogue path, mixed case: one documented deviation plus one real
    // violation. The exception covers only its own finding, so the control
    // still fails, and both findings are carried as evidence.
    let coverage = vec![mapping(ComplianceFramework::CIS, "1.5.1")];
    let generator = ReportGenerator::new(config_for(ComplianceFramework::CIS), coverage);
    let mut excepted = cis_finding("1.5.1");
    excepted.finding_id = "test_excepted".to_string();
    excepted.finding_policy_exception = Some(FindingPolicyException::default());
    let report = generator
        .generate(&[excepted, cis_finding("1.5.1")], &[])
        .pop()
        .unwrap();

    let result = report
        .report_controls
        .iter()
        .find(|c| c.control_id == "1.5.1")
        .expect("1.5.1 in catalogue");
    assert_eq!(result.control_status, ControlStatus::Fail);
    assert_eq!(result.control_findings.len(), 2);
}

#[test]
fn safe_failure_net_fails_a_mixed_uncatalogued_control() {
    // Safe-failure-net path, mixed case: the excepted finding must not
    // suppress the live one, so the uncatalogued control is still emitted
    // as a Fail carrying both findings.
    let mut excepted = cis_finding("ZZ-UNCATALOGUED-9999");
    excepted.finding_id = "test_excepted".to_string();
    excepted.finding_policy_exception = Some(FindingPolicyException::default());
    let generator = ReportGenerator::new(config_for(ComplianceFramework::CIS), vec![]);
    let report = generator
        .generate(&[excepted, cis_finding("ZZ-UNCATALOGUED-9999")], &[])
        .pop()
        .unwrap();

    let result = report
        .report_controls
        .iter()
        .find(|c| c.control_id == "ZZ-UNCATALOGUED-9999")
        .expect("a live finding must still surface an uncatalogued control");
    assert_eq!(result.control_status, ControlStatus::Fail);
    assert_eq!(result.control_findings.len(), 2);
}

#[test]
fn excepted_finding_on_uncatalogued_control_is_not_emitted() {
    // Safe-failure-net path: a finding mapped to a control absent from
    // both the catalogue and coverage would normally still Fail (a wrong
    // mapping can only ever over-report, per the net's own purpose). But
    // when the SOLE finding mapped to that control is excepted, there is
    // no live violation to surface, so the net must skip it entirely
    // rather than manufacture a Fail row with an empty findings list.
    let mut excepted = cis_finding("ZZ-UNCATALOGUED-9999");
    excepted.finding_policy_exception = Some(FindingPolicyException::default());
    let generator = ReportGenerator::new(config_for(ComplianceFramework::CIS), vec![]);
    let report = generator.generate(&[excepted], &[]).pop().unwrap();

    assert!(
        report
            .report_controls
            .iter()
            .all(|c| c.control_id != "ZZ-UNCATALOGUED-9999")
    );
}

#[test]
fn uncovered_catalogue_control_is_manual_review() {
    // A curated CIS control with no coverage entry cannot be auto-passed.
    let generator = ReportGenerator::new(config_for(ComplianceFramework::CIS), vec![]);
    let report = generator.generate(&[], &[]).pop().unwrap();

    assert_eq!(report.report_summary.summary_passing, 0);
    assert!(report.report_summary.summary_manual_review >= 1);
    assert_ne!(report.report_summary.summary_score_percentage, 100.0);
}

#[test]
fn derived_framework_lists_only_assessed_controls() {
    // STIG has no curated catalogue: its controls are derived from coverage,
    // so a clean system reports every covered control as Pass, none manual.
    let coverage = vec![mapping(ComplianceFramework::STIG, "RHEL-08-010430")];
    let generator = ReportGenerator::new(config_for(ComplianceFramework::STIG), coverage);
    let report = generator.generate(&[], &[]).pop().unwrap();

    assert_eq!(report.report_summary.summary_total_controls, 1);
    assert_eq!(report.report_summary.summary_passing, 1);
    assert_eq!(report.report_summary.summary_manual_review, 0);
}

#[test]
fn soc2_clean_coverage_renders_pass_controls() {
    // SOC 2 has no curated catalogue: the derived catalogue IS the coverage
    // set, so on a clean system every covered criterion reports Pass and
    // nothing needs manual review.
    let coverage = vec![
        mapping(ComplianceFramework::SOC2, "CC6.1"),
        mapping(ComplianceFramework::SOC2, "CC7.2"),
    ];
    let generator = ReportGenerator::new(config_for(ComplianceFramework::SOC2), coverage);
    let report = generator.generate(&[], &[]).pop().unwrap();

    assert_eq!(report.report_framework, ComplianceFramework::SOC2);
    assert_eq!(report.report_summary.summary_total_controls, 2);
    assert_eq!(report.report_summary.summary_passing, 2);
    assert_eq!(report.report_summary.summary_manual_review, 0);
}

#[test]
fn nist_800_171_clean_coverage_renders_pass_controls() {
    // 800-171 has no curated catalogue: the derived catalogue IS the
    // coverage set, so on a clean system every covered requirement
    // reports Pass and nothing needs manual review.
    let coverage = vec![
        mapping(ComplianceFramework::NIST800171, "3.4.2"),
        mapping(ComplianceFramework::NIST800171, "3.13.1"),
    ];
    let generator = ReportGenerator::new(config_for(ComplianceFramework::NIST800171), coverage);
    let report = generator.generate(&[], &[]).pop().unwrap();

    assert_eq!(report.report_framework, ComplianceFramework::NIST800171);
    assert_eq!(report.report_summary.summary_total_controls, 2);
    assert_eq!(report.report_summary.summary_passing, 2);
    assert_eq!(report.report_summary.summary_manual_review, 0);
}

#[test]
fn fedramp_clean_coverage_renders_pass_controls() {
    // FedRAMP has no curated catalogue: the derived catalogue IS the
    // coverage set (baseline-filtered 800-53 ids), so on a clean system
    // every covered control reports Pass and nothing needs manual review.
    let coverage = vec![
        mapping(ComplianceFramework::FedRAMP, "SC-7"),
        mapping(ComplianceFramework::FedRAMP, "AC-6(1)"),
    ];
    let generator = ReportGenerator::new(config_for(ComplianceFramework::FedRAMP), coverage);
    let report = generator.generate(&[], &[]).pop().unwrap();

    assert_eq!(report.report_framework, ComplianceFramework::FedRAMP);
    assert_eq!(report.report_summary.summary_total_controls, 2);
    assert_eq!(report.report_summary.summary_passing, 2);
    assert_eq!(report.report_summary.summary_manual_review, 0);
}

#[test]
fn rhel10_finding_reports_translated_stig_id() {
    // A canonical RHEL-08 finding renders under its sourced RHEL-10 id, and
    // the embedded finding copy carries the translated mapping list.
    let coverage = vec![mapping(ComplianceFramework::STIG, "RHEL-08-010430")];
    let generator = ReportGenerator::new(
        config_with_profile(ComplianceFramework::STIG, ComplianceProfile::Rhel10),
        coverage,
    );
    let report = generator
        .generate(&[stig_finding("RHEL-08-010430")], &[])
        .pop()
        .unwrap();

    assert!(
        report
            .report_controls
            .iter()
            .all(|c| c.control_id != "RHEL-08-010430")
    );
    let result = report
        .report_controls
        .iter()
        .find(|c| c.control_id == "RHEL-10-701130")
        .expect("translated control present");
    assert_eq!(result.control_status, ControlStatus::Fail);
    let embedded = &result.control_findings[0].finding_compliance;
    assert!(
        embedded
            .iter()
            .any(|m| m.compliance_control_id == "RHEL-10-701130")
    );
    assert!(
        embedded
            .iter()
            .all(|m| m.compliance_control_id != "RHEL-08-010430")
    );
    assert_eq!(report.report_profile, ComplianceProfile::Rhel10);
}

#[test]
fn rhel10_clean_coverage_passes_translated_id() {
    // Pass path: a covered control with no finding passes under its
    // translated id, and the canonical id is nowhere in the report.
    let coverage = vec![mapping(ComplianceFramework::STIG, "RHEL-08-010430")];
    let generator = ReportGenerator::new(
        config_with_profile(ComplianceFramework::STIG, ComplianceProfile::Rhel10),
        coverage,
    );
    let report = generator.generate(&[], &[]).pop().unwrap();

    assert_eq!(report.report_summary.summary_total_controls, 1);
    let result = report
        .report_controls
        .iter()
        .find(|c| c.control_id == "RHEL-10-701130")
        .expect("translated control present");
    assert_eq!(result.control_status, ControlStatus::Pass);
}

#[test]
fn rhel10_drops_unsourced_stig_id_without_tripping_safe_net() {
    // An id V1R1 does not source vanishes from the profiled report: it
    // buckets under no control and must not surface via the safe-failure
    // net as a Fail row wearing a generic id.
    let coverage = vec![mapping(ComplianceFramework::STIG, "RHEL-08-010430")];
    let generator = ReportGenerator::new(
        config_with_profile(ComplianceFramework::STIG, ComplianceProfile::Rhel10),
        coverage,
    );
    let report = generator
        .generate(&[stig_finding("RHEL-08-999999")], &[])
        .pop()
        .unwrap();

    assert!(
        report
            .report_controls
            .iter()
            .all(|c| !c.control_id.contains("999999"))
    );
    assert_eq!(report.report_summary.summary_failing, 0);
}

#[test]
fn generic_profile_reports_canonical_ids_unchanged() {
    // The same inputs under Generic keep today's ids and titles exactly:
    // the covered control fails on its finding and the unknown id still
    // surfaces through the safe-failure net.
    let coverage = vec![mapping(ComplianceFramework::STIG, "RHEL-08-010430")];
    let generator = ReportGenerator::new(config_for(ComplianceFramework::STIG), coverage);
    let mut finding = stig_finding("RHEL-08-010430");
    finding
        .finding_compliance
        .push(mapping(ComplianceFramework::STIG, "RHEL-08-999999"));
    let report = generator.generate(&[finding], &[]).pop().unwrap();

    let ids: Vec<&str> = report
        .report_controls
        .iter()
        .map(|c| c.control_id.as_str())
        .collect();
    assert_eq!(ids, vec!["RHEL-08-010430", "RHEL-08-999999"]);
    assert!(report.report_controls.iter().all(|c| {
        c.control_status == ControlStatus::Fail
            && c.control_title == format!("Control {}", c.control_id)
    }));
    assert_eq!(report.report_profile, ComplianceProfile::Generic);
}

#[test]
fn noncatalogue_finding_still_surfaces_as_failure() {
    // A finding whose control id is in neither catalogue nor coverage must
    // still fail; a wrong mapping can only ever over-report a failure.
    let mut finding = cis_finding("1.5.1");
    finding
        .finding_compliance
        .push(mapping(ComplianceFramework::STIG, "OL08-00-999999"));
    let generator = ReportGenerator::new(config_for(ComplianceFramework::STIG), vec![]);
    let report = generator.generate(&[finding], &[]).pop().unwrap();

    assert!(
        report
            .report_controls
            .iter()
            .any(|c| c.control_id == "OL08-00-999999" && c.control_status == ControlStatus::Fail)
    );
}
