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

/// One plugin declaring exactly `coverage`, so the assessed set is what the
/// caller asked for.
///
/// The generator takes an inventory rather than a bare coverage union now,
/// because it has to name the plugins that produced no evidence. These tests
/// care only about which controls are assessable.
fn inventory_declaring(coverage: Vec<ComplianceMapping>) -> PluginInventory {
    PluginInventory::Known(vec![hardener_types::PluginCoverage {
        metadata: hardener_types::PluginMetadata {
            plugin_category: hardener_common::types::FindingCategory::Kernel,
            plugin_description: String::new(),
            plugin_id: PluginId::new("test-plugin"),
            plugin_name: "test plugin".to_string(),
            plugin_version: "0.1.0".to_string(),
        },
        coverage,
    }])
}
use crate::config::{OutputFormat, Scenario};
use hardener_common::types::{
    ComplianceProfile, FindingCategory, FindingPolicyException, Severity,
};
use hardener_core::config::scope::{ComplianceConfig, ScopeExclusion};
use hardener_types::{DeclineReason, ExceptionOutcome, FindingExceptionDeclined};
use std::collections::HashMap;

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
        finding_exception: ExceptionOutcome::NotConfigured,
        finding_exception_key: None,
    }
}

/// A finding carrying a single mapping for the given framework, control id and
/// severity. `cis_finding` is the fixed-framework, fixed-severity shorthand for
/// it, so the two share one finding shape rather than two copies of it.
fn mapped_finding(framework: ComplianceFramework, control_id: &str, severity: Severity) -> Finding {
    Finding {
        finding_severity: severity,
        finding_compliance: vec![mapping(framework, control_id)],
        ..cis_finding(control_id)
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

/// Builds the single report for one framework with an operator exclusion set
/// applied. `config_for` supplies the report config so the scenario, formats and
/// profile are defined once for every test in this file.
///
/// The report is about the local host, which is what every caller outside the
/// fleet path reports on. [`report_for_with_exclusions_on_host`] is the same
/// thing with a host named.
fn report_for_with_exclusions(
    framework: ComplianceFramework,
    coverage: Vec<ComplianceMapping>,
    findings: &[Finding],
    exclusions: ComplianceConfig,
) -> ComplianceReport {
    report_for_with_exclusions_on_host(framework, coverage, findings, exclusions, None)
}

/// [`report_for_with_exclusions`] with the host the report is about named as
/// `(target, hostname, name)`, which is the three spellings
/// `ScopeExclusion::covers_host` matches against. `None` is the local host.
fn report_for_with_exclusions_on_host(
    framework: ComplianceFramework,
    coverage: Vec<ComplianceMapping>,
    findings: &[Finding],
    exclusions: ComplianceConfig,
    host: Option<(&str, &str, &str)>,
) -> ComplianceReport {
    let generator = ReportGenerator::new(
        config_for(framework),
        inventory_declaring(coverage),
        exclusions,
    );
    let generator = match host {
        Some((target, hostname, name)) => {
            generator.for_host(target.to_string(), hostname.to_string(), name.to_string())
        }
        None => generator,
    };
    generator
        // `score`, not `generate`: these exercise the scoring rules, and
        // `generate` would flatten first and add a stand-in entry for the
        // plugin that declared this coverage and produced no result.
        .score(findings, &[])
        .into_iter()
        .next()
        .expect("one report")
}

/// The status a report gives one control. Panics when the control is absent,
/// because every caller here is asserting about a control it expects listed.
fn status_of(report: &ComplianceReport, control_id: &str) -> ControlStatus {
    report
        .report_controls
        .iter()
        .find(|c| c.control_id == control_id)
        .expect("control present")
        .control_status
        .clone()
}

/// Builds a `ComplianceConfig` holding one exclusion for one control.
fn one_exclusion(framework_id: &str, control_id: &str) -> ComplianceConfig {
    let mut controls = HashMap::new();
    controls.insert(
        control_id.to_string(),
        ScopeExclusion {
            reason: "No physical premises".to_string(),
            approved_by: Some("eric".to_string()),
            approved_date: Some("2026-08-18".to_string()),
            ticket: None,
            review_by: Some("2999-01-01".to_string()),
            hosts: Vec::new(),
        },
    );
    let mut frameworks = HashMap::new();
    frameworks.insert(framework_id.to_string(), controls);
    ComplianceConfig {
        not_applicable: frameworks,
    }
}

/// [`one_exclusion`] narrowed to a host list. An empty list is what
/// `one_exclusion` already produces, so this is only ever used to target.
fn one_exclusion_for_hosts(
    framework_id: &str,
    control_id: &str,
    hosts: &[&str],
) -> ComplianceConfig {
    let mut cfg = one_exclusion(framework_id, control_id);
    cfg.not_applicable
        .get_mut(framework_id)
        .expect("framework present")
        .get_mut(control_id)
        .expect("control present")
        .hosts = hosts.iter().map(|h| (*h).to_string()).collect();
    cfg
}

#[test]
fn an_exclusion_turns_manual_review_into_not_applicable() {
    // CIS with an empty coverage set assesses nothing, so every control is
    // ManualReview and any one of them is eligible for exclusion.
    let baseline = report_for_with_exclusions(
        ComplianceFramework::CIS,
        vec![],
        &[],
        ComplianceConfig::default(),
    );
    let target = baseline
        .report_controls
        .first()
        .expect("CIS has a curated catalogue")
        .control_id
        .clone();

    let report = report_for_with_exclusions(
        ComplianceFramework::CIS,
        vec![],
        &[],
        one_exclusion("cis", &target),
    );
    let control = report
        .report_controls
        .iter()
        .find(|c| c.control_id == target)
        .expect("the control is still listed");

    assert_eq!(control.control_status, ControlStatus::NotApplicable);
    assert_eq!(
        report.report_summary.summary_not_applicable, 1,
        "the summary counts it, so it leaves the denominator"
    );
    assert_eq!(
        report.report_summary.summary_manual_review,
        baseline.report_summary.summary_manual_review - 1,
        "exactly one control moved, and it moved out of ManualReview"
    );
}

/// THE CONTROLLING RULE. An exclusion must never mute a real finding. If this
/// test ever passes with the arm in the wrong position, the feature is a
/// blanket override for failing controls.
#[test]
fn an_exclusion_cannot_silence_a_failing_control() {
    let finding = mapped_finding(ComplianceFramework::CIS, "1.5.1", Severity::High);
    let report = report_for_with_exclusions(
        ComplianceFramework::CIS,
        vec![mapping(ComplianceFramework::CIS, "1.5.1")],
        &[finding],
        one_exclusion("cis", "1.5.1"),
    );
    let control = report
        .report_controls
        .iter()
        .find(|c| c.control_id == "1.5.1")
        .expect("covered control present");

    assert_eq!(
        control.control_status,
        ControlStatus::Fail,
        "a live finding always wins over an exclusion"
    );
    assert_eq!(report.report_summary.summary_not_applicable, 0);
}

/// The second half of the controlling rule: a control the engine *can* assess
/// is answered by the engine, not by a human's declaration.
#[test]
fn an_exclusion_cannot_override_an_assessed_pass() {
    let report = report_for_with_exclusions(
        ComplianceFramework::CIS,
        vec![mapping(ComplianceFramework::CIS, "1.5.1")],
        &[],
        one_exclusion("cis", "1.5.1"),
    );
    let control = report
        .report_controls
        .iter()
        .find(|c| c.control_id == "1.5.1")
        .expect("covered control present");

    assert_eq!(control.control_status, ControlStatus::Pass);
    assert_eq!(report.report_summary.summary_not_applicable, 0);
}

/// The third arm of the same rule, and the one nothing pinned: `unchecked`
/// sits above the exclusion arm, so a control whose covering check could not
/// run this session stays `ManualReview` even when an operator declared it out
/// of scope.
///
/// Moving the exclusion arm above `unchecked` left every other test in the
/// workspace green while changing a real score: the control would leave the
/// denominator on the strength of a run-time privilege accident rather than on
/// the declaration the report is meant to be about. Privilege is a property of
/// the run, not of applicability, so the conservative answer wins and this
/// test is what says so.
#[test]
fn an_unchecked_control_stays_manual_review_even_when_excluded() {
    // 1.5.1 is covered, so on a clean run it would Pass. This run could not
    // evaluate the covering check, and the operator has also declared the
    // control not applicable. Both facts are true at once, and the uncertainty
    // outranks the declaration.
    let generator = ReportGenerator::new(
        config_for(ComplianceFramework::CIS),
        inventory_declaring(vec![mapping(ComplianceFramework::CIS, "1.5.1")]),
        one_exclusion("cis", "1.5.1"),
    );
    let unchecked = vec![UncheckedCheck {
        unchecked_check_id: "pam-minlen".to_string(),
        unchecked_title: "PAM setting: minlen".to_string(),
        unchecked_category: FindingCategory::Authentication,
        unchecked_reason: "requires root".to_string(),
        unchecked_blocker: hardener_types::UncheckedBlocker::Privilege,
        unchecked_compliance: vec![mapping(ComplianceFramework::CIS, "1.5.1")],
    }];
    let report = generator.score(&[], &unchecked).pop().expect("one report");

    assert_eq!(
        status_of(&report, "1.5.1"),
        ControlStatus::ManualReview,
        "a check that could not run this session cannot be answered by a \
         declaration; the exclusion arm must stay below the unchecked arm"
    );
    assert_eq!(
        report.report_summary.summary_not_applicable, 0,
        "and so the control is still in the score's denominator"
    );
}

#[test]
fn an_expired_exclusion_falls_back_to_manual_review_not_to_pass() {
    let mut cfg = one_exclusion("cis", "1.5.1");
    cfg.not_applicable
        .get_mut("cis")
        .expect("framework present")
        .get_mut("1.5.1")
        .expect("control present")
        .review_by = Some("2020-01-01".to_string());

    let report = report_for_with_exclusions(ComplianceFramework::CIS, vec![], &[], cfg);
    let control = report
        .report_controls
        .iter()
        .find(|c| c.control_id == "1.5.1")
        .expect("control present");

    assert_eq!(control.control_status, ControlStatus::ManualReview);
}

/// An unknown framework id in the config is ignored rather than fatal, and an
/// exclusion for a control not in the catalogue changes nothing.
#[test]
fn an_exclusion_naming_nothing_real_is_inert() {
    let baseline = report_for_with_exclusions(
        ComplianceFramework::CIS,
        vec![],
        &[],
        ComplianceConfig::default(),
    );
    let report = report_for_with_exclusions(
        ComplianceFramework::CIS,
        vec![],
        &[],
        one_exclusion("not-a-framework", "9.9.9"),
    );
    assert_eq!(
        report.report_summary.summary_not_applicable,
        baseline.report_summary.summary_not_applicable
    );
}

/// An exclusion is scoped to the framework it was declared under.
///
/// The control id here is a real one in the CIS catalogue, declared under
/// STIG. Framework numbering schemes overlap, so a lookup that ignored the
/// framework key would take an operator's CIS declaration and quietly drop the
/// same-numbered control from a STIG or ISO 27001 report nobody made a claim
/// about. `an_exclusion_naming_nothing_real_is_inert` cannot see that: its
/// control id is fake as well, so it proves only that a fake control is inert.
#[test]
fn an_exclusion_under_another_framework_does_not_reach_a_real_control() {
    let report = report_for_with_exclusions(
        ComplianceFramework::CIS,
        vec![],
        &[],
        one_exclusion("stig", "1.5.1"),
    );

    assert_eq!(
        status_of(&report, "1.5.1"),
        ControlStatus::ManualReview,
        "a STIG declaration says nothing about the CIS control of the same number"
    );
    assert_eq!(report.report_summary.summary_not_applicable, 0);
}

/// Every other parser in this tool resolves a framework id through
/// `ComplianceFramework::from_id`, which is case insensitive and accepts the
/// documented aliases. The generator matched the config key exactly, so a
/// hand-written `[compliance.not_applicable.CIS]` or `.nist-800-171` was
/// silently inert: accepted by the config loader, ignored by the report, with
/// nothing anywhere pointing at the spelling.
#[test]
fn an_accepted_spelling_of_the_framework_key_resolves() {
    for spelling in ["CIS", "Cis"] {
        let report = report_for_with_exclusions(
            ComplianceFramework::CIS,
            vec![],
            &[],
            one_exclusion(spelling, "1.5.1"),
        );
        assert_eq!(
            status_of(&report, "1.5.1"),
            ControlStatus::NotApplicable,
            "{spelling:?} names CIS everywhere else in the tool"
        );
    }

    // An alias rather than a case variant. ISO 27001 is the other framework
    // with a curated catalogue, so it is the other one where an exclusion has
    // anything to convert: a derived catalogue is assessed by definition, and
    // the assessed arm sits above the exclusion arm.
    let report = report_for_with_exclusions(
        ComplianceFramework::ISO27001,
        vec![],
        &[],
        one_exclusion("iso-27001", "7.1"),
    );
    assert_eq!(
        status_of(&report, "7.1"),
        ControlStatus::NotApplicable,
        "iso-27001 is an accepted alias of iso27001"
    );
}

/// The other half: normalising the key must not turn an unresolvable one into
/// a match. A key naming no framework has no interval to measure a review
/// deadline against, so it stays inert, which is the existing fail-closed
/// behaviour and the only safe answer for a mechanism that raises a score.
#[test]
fn a_framework_key_naming_nothing_known_stays_inert() {
    let report = report_for_with_exclusions(
        ComplianceFramework::CIS,
        vec![],
        &[],
        one_exclusion("ciss", "1.5.1"),
    );

    assert_eq!(status_of(&report, "1.5.1"), ControlStatus::ManualReview);
    assert_eq!(report.report_summary.summary_not_applicable, 0);
}

#[test]
fn a_declined_exception_still_fails_its_control() {
    let finding = Finding {
        finding_exception: ExceptionOutcome::Declined(FindingExceptionDeclined {
            exception_declined_reason: DeclineReason::ValueMismatch {
                documented: "yes".to_string(),
                observed: "prohibit-password".to_string(),
            },
            exception_reason: "legacy jump host".to_string(),
        }),
        ..cis_finding("1.1.1")
    };

    assert!(
        has_live_finding(std::slice::from_ref(&finding)),
        "an exception that did not apply excuses nothing, so the control must fail"
    );
    assert!(
        !finding.is_policy_excepted(),
        "a declined exception must never read as a documented deviation"
    );
}

#[test]
fn assessed_control_passes_on_clean_system() {
    // CIS 1.5.1 is in coverage; with no finding it must report Pass (Option B).
    let coverage = vec![mapping(ComplianceFramework::CIS, "1.5.1")];
    let generator = ReportGenerator::new(
        config_for(ComplianceFramework::CIS),
        inventory_declaring(coverage),
        ComplianceConfig::default(),
    );
    let report = generator.score(&[], &[]).pop().unwrap();

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
    let generator = ReportGenerator::new(
        config_for(ComplianceFramework::CIS),
        inventory_declaring(coverage),
        ComplianceConfig::default(),
    );
    let unchecked = vec![UncheckedCheck {
        unchecked_check_id: "pam-minlen".to_string(),
        unchecked_title: "PAM setting: minlen".to_string(),
        unchecked_category: FindingCategory::Authentication,
        unchecked_reason: "requires root".to_string(),
        unchecked_blocker: hardener_types::UncheckedBlocker::Privilege,
        unchecked_compliance: vec![mapping(ComplianceFramework::CIS, "1.5.1")],
    }];
    let report = generator.score(&[], &unchecked).pop().unwrap();

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
    let generator = ReportGenerator::new(
        config_for(ComplianceFramework::CIS),
        inventory_declaring(coverage),
        ComplianceConfig::default(),
    );
    let unchecked = vec![UncheckedCheck {
        unchecked_check_id: "pam-minlen".to_string(),
        unchecked_title: "PAM setting: minlen".to_string(),
        unchecked_category: FindingCategory::Authentication,
        unchecked_reason: "requires root".to_string(),
        unchecked_blocker: hardener_types::UncheckedBlocker::Privilege,
        unchecked_compliance: vec![mapping(ComplianceFramework::CIS, "1.5.1")],
    }];
    let report = generator
        .score(&[cis_finding("1.5.1")], &unchecked)
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
    let generator = ReportGenerator::new(
        config_for(ComplianceFramework::CIS),
        inventory_declaring(coverage),
        ComplianceConfig::default(),
    );
    let report = generator.score(&[cis_finding("1.5.1")], &[]).pop().unwrap();

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
    let generator = ReportGenerator::new(
        config_for(ComplianceFramework::CIS),
        inventory_declaring(coverage),
        ComplianceConfig::default(),
    );
    let mut excepted = cis_finding("1.5.1");
    excepted.finding_exception = ExceptionOutcome::Applied(FindingPolicyException::default());
    let report = generator.score(&[excepted], &[]).pop().unwrap();

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
    assert!(result.control_findings[0].is_policy_excepted());
}

#[test]
fn live_finding_still_fails_a_control_that_also_has_an_excepted_one() {
    // Catalogue path, mixed case: one documented deviation plus one real
    // violation. The exception covers only its own finding, so the control
    // still fails, and both findings are carried as evidence.
    let coverage = vec![mapping(ComplianceFramework::CIS, "1.5.1")];
    let generator = ReportGenerator::new(
        config_for(ComplianceFramework::CIS),
        inventory_declaring(coverage),
        ComplianceConfig::default(),
    );
    let mut excepted = cis_finding("1.5.1");
    excepted.finding_id = "test_excepted".to_string();
    excepted.finding_exception = ExceptionOutcome::Applied(FindingPolicyException::default());
    let report = generator
        .score(&[excepted, cis_finding("1.5.1")], &[])
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
    excepted.finding_exception = ExceptionOutcome::Applied(FindingPolicyException::default());
    let generator = ReportGenerator::new(
        config_for(ComplianceFramework::CIS),
        inventory_declaring(vec![]),
        ComplianceConfig::default(),
    );
    let report = generator
        .score(&[excepted, cis_finding("ZZ-UNCATALOGUED-9999")], &[])
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
    excepted.finding_exception = ExceptionOutcome::Applied(FindingPolicyException::default());
    let generator = ReportGenerator::new(
        config_for(ComplianceFramework::CIS),
        inventory_declaring(vec![]),
        ComplianceConfig::default(),
    );
    let report = generator.score(&[excepted], &[]).pop().unwrap();

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
    let generator = ReportGenerator::new(
        config_for(ComplianceFramework::CIS),
        inventory_declaring(vec![]),
        ComplianceConfig::default(),
    );
    let report = generator.score(&[], &[]).pop().unwrap();

    assert_eq!(report.report_summary.summary_passing, 0);
    assert!(report.report_summary.summary_manual_review >= 1);
    assert_ne!(report.report_summary.summary_score_percentage, 100.0);
}

#[test]
fn derived_framework_lists_only_assessed_controls() {
    // STIG has no curated catalogue: its controls are derived from coverage,
    // so a clean system reports every covered control as Pass, none manual.
    let coverage = vec![mapping(ComplianceFramework::STIG, "RHEL-08-010430")];
    let generator = ReportGenerator::new(
        config_for(ComplianceFramework::STIG),
        inventory_declaring(coverage),
        ComplianceConfig::default(),
    );
    let report = generator.score(&[], &[]).pop().unwrap();

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
    let generator = ReportGenerator::new(
        config_for(ComplianceFramework::SOC2),
        inventory_declaring(coverage),
        ComplianceConfig::default(),
    );
    let report = generator.score(&[], &[]).pop().unwrap();

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
    let generator = ReportGenerator::new(
        config_for(ComplianceFramework::NIST800171),
        inventory_declaring(coverage),
        ComplianceConfig::default(),
    );
    let report = generator.score(&[], &[]).pop().unwrap();

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
    let generator = ReportGenerator::new(
        config_for(ComplianceFramework::FedRAMP),
        inventory_declaring(coverage),
        ComplianceConfig::default(),
    );
    let report = generator.score(&[], &[]).pop().unwrap();

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
        inventory_declaring(coverage),
        ComplianceConfig::default(),
    );
    let report = generator
        .score(&[stig_finding("RHEL-08-010430")], &[])
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
        inventory_declaring(coverage),
        ComplianceConfig::default(),
    );
    let report = generator.score(&[], &[]).pop().unwrap();

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
        inventory_declaring(coverage),
        ComplianceConfig::default(),
    );
    let report = generator
        .score(&[stig_finding("RHEL-08-999999")], &[])
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
    let generator = ReportGenerator::new(
        config_for(ComplianceFramework::STIG),
        inventory_declaring(coverage),
        ComplianceConfig::default(),
    );
    let mut finding = stig_finding("RHEL-08-010430");
    finding
        .finding_compliance
        .push(mapping(ComplianceFramework::STIG, "RHEL-08-999999"));
    let report = generator.score(&[finding], &[]).pop().unwrap();

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
    let generator = ReportGenerator::new(
        config_for(ComplianceFramework::STIG),
        inventory_declaring(vec![]),
        ComplianceConfig::default(),
    );
    let report = generator.score(&[finding], &[]).pop().unwrap();

    assert!(
        report
            .report_controls
            .iter()
            .any(|c| c.control_id == "OL08-00-999999" && c.control_status == ControlStatus::Fail)
    );
}

/// The report states that its scan was partial, in the same words `scan` uses.
///
/// `report` runs the very same scan as `scan`, which prints "27 check(s) could
/// not be verified, 26 of them for want of root; run with sudo for a fuller
/// scan". The report then printed a score and six summary numbers with no
/// caveat anywhere in either renderer, and the unchecked checks are in the
/// denominator of that score. An operator prints the report, sees 70.5%, and
/// has no way to learn from the document that a privileged re-run would produce
/// a different number. The report is the artefact people keep; `scan` is the one
/// they run once (#161).
///
/// The sentence is not composed here. `hardener_types::unchecked_summary` is
/// the single definition, already used by four renderers, and it decides when
/// to offer sudo based on each entry's own blocker rather than assuming root.
#[test]
fn a_partial_scan_says_so_in_the_report() {
    let generator = ReportGenerator::new(
        config_for(ComplianceFramework::CIS),
        inventory_declaring(vec![]),
        ComplianceConfig::default(),
    );

    let unchecked = vec![
        UncheckedCheck {
            unchecked_check_id: "pam-minlen".to_string(),
            unchecked_title: "PAM setting: minlen".to_string(),
            unchecked_category: FindingCategory::Authentication,
            unchecked_reason: "requires root".to_string(),
            unchecked_blocker: hardener_types::UncheckedBlocker::Privilege,
            unchecked_compliance: vec![mapping(ComplianceFramework::CIS, "1.5.1")],
        },
        UncheckedCheck {
            unchecked_check_id: "mac-enforcement-mode".to_string(),
            unchecked_title: "MAC enforcement mode".to_string(),
            unchecked_category: FindingCategory::Kernel,
            unchecked_reason: "no MAC system is installed".to_string(),
            unchecked_blocker: hardener_types::UncheckedBlocker::Environment,
            unchecked_compliance: vec![mapping(ComplianceFramework::CIS, "1.6.1.4")],
        },
    ];

    let report = generator.score(&[], &unchecked).pop().unwrap();

    let note = report
        .report_coverage_note
        .as_deref()
        .expect("a run that could not verify two checks must say so in the report");

    assert!(
        note.contains('2') && note.contains("could not be verified"),
        "the note must carry the count and the reason, got {note:?}"
    );
    assert!(
        note.contains("sudo"),
        "one of the two is privilege-blocked, so the remedy is worth offering: {note:?}"
    );

    // The other half, and the one that can rot: a complete run must claim
    // nothing. A note composed unconditionally would pass every assertion
    // above and put "0 check(s) could not be verified" on a clean report.
    let complete = generator.score(&[], &[]).pop().unwrap();
    assert!(
        complete.report_coverage_note.is_none(),
        "a run that verified everything has no caveat to make, got {:?}",
        complete.report_coverage_note
    );
}

/// The change trigger the frameworks actually specify. When a plugin gains
/// coverage for an excluded control, the engine's answer supersedes the
/// operator's declaration immediately, without waiting for `review_by`.
#[test]
fn gaining_coverage_supersedes_an_exclusion_without_waiting_for_review() {
    let cfg = one_exclusion("cis", "1.5.1");

    let before = report_for_with_exclusions(ComplianceFramework::CIS, vec![], &[], cfg.clone());
    let after = report_for_with_exclusions(
        ComplianceFramework::CIS,
        vec![mapping(ComplianceFramework::CIS, "1.5.1")],
        &[],
        cfg,
    );

    assert_eq!(status_of(&before, "1.5.1"), ControlStatus::NotApplicable);
    assert_eq!(
        status_of(&after, "1.5.1"),
        ControlStatus::Pass,
        "coverage supersedes the declaration; review_by is 2999 and irrelevant"
    );
}

/// An exclusion naming no host is a claim about the estate, so it applies
/// wherever the report is generated, remote hosts included.
#[test]
fn an_untargeted_exclusion_applies_to_every_host() {
    let report = report_for_with_exclusions_on_host(
        ComplianceFramework::CIS,
        vec![],
        &[],
        one_exclusion("cis", "1.5.1"),
        Some(("web-01:22", "web-01", "web-01")),
    );

    assert_eq!(status_of(&report, "1.5.1"), ControlStatus::NotApplicable);
}

/// The point of the host list: a claim made about one system must not raise
/// any other system's score, and must not silently raise the controller's own.
#[test]
fn a_targeted_exclusion_leaves_other_hosts_alone() {
    let cfg = one_exclusion_for_hosts("cis", "1.5.1", &["web-01"]);

    let matching = report_for_with_exclusions_on_host(
        ComplianceFramework::CIS,
        vec![],
        &[],
        cfg.clone(),
        Some(("web-01:22", "web-01", "web-01")),
    );
    let other = report_for_with_exclusions_on_host(
        ComplianceFramework::CIS,
        vec![],
        &[],
        cfg.clone(),
        Some(("db-01:22", "db-01", "db-01")),
    );
    let local =
        report_for_with_exclusions_on_host(ComplianceFramework::CIS, vec![], &[], cfg, None);

    assert_eq!(status_of(&matching, "1.5.1"), ControlStatus::NotApplicable);
    assert_eq!(status_of(&other, "1.5.1"), ControlStatus::ManualReview);
    assert_eq!(
        status_of(&local, "1.5.1"),
        ControlStatus::ManualReview,
        "a targeted exclusion must not silently alter the controller's own report"
    );
}

/// The three spellings the generator carries are all matched, so an operator
/// who wrote the canonical target, the bare hostname or the inventory display
/// name gets the same answer.
#[test]
fn the_canonical_target_form_matches_as_well_as_the_bare_hostname() {
    let host = Some(("ops@web-01:2222", "web-01", "web-01-prod"));

    for spelling in ["ops@web-01:2222", "web-01", "web-01-prod"] {
        let report = report_for_with_exclusions_on_host(
            ComplianceFramework::CIS,
            vec![],
            &[],
            one_exclusion_for_hosts("cis", "1.5.1", &[spelling]),
            host,
        );
        assert_eq!(
            status_of(&report, "1.5.1"),
            ControlStatus::NotApplicable,
            "the spelling {spelling:?} names this host"
        );
    }
}

/// A targeted exclusion is still only ever able to convert a `ManualReview`.
/// The host gate is an extra condition on the last arm, never a way past the
/// arms above it, so the matching host still fails on a live finding.
#[test]
fn a_matching_host_still_cannot_silence_a_failing_control() {
    let report = report_for_with_exclusions_on_host(
        ComplianceFramework::CIS,
        vec![mapping(ComplianceFramework::CIS, "1.5.1")],
        &[mapped_finding(
            ComplianceFramework::CIS,
            "1.5.1",
            Severity::High,
        )],
        one_exclusion_for_hosts("cis", "1.5.1", &["web-01"]),
        Some(("web-01:22", "web-01", "web-01")),
    );

    assert_eq!(status_of(&report, "1.5.1"), ControlStatus::Fail);
    assert_eq!(report.report_summary.summary_not_applicable, 0);
}
