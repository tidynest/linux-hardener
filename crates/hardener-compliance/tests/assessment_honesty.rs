//! Regression tests for honest compliance assessment.
//!
//! Two invariants this suite locks in:
//!
//! 1. **No false pass.** A control the hardening engine does not assess must be
//!    reported as `ManualReview`, never a green `Pass`. "Assessed" is declared by
//!    the engine's coverage set (`hardener_plugins::compliance_coverage()`),
//!    injected into the generator, not inferred from the absence of a finding.
//! 2. **Option B.** A control that *is* assessed and has no finding reports
//!    `Pass`, so a genuinely hardened system scores accurately rather than being
//!    buried under manual review.
//!
//! Coverage is built synthetically here so the cases are deterministic and the
//! compliance crate stays independent of the plugins crate.

use hardener_common::types::{
    ComplianceFramework, ComplianceMapping, ComplianceProfile, ControlStatus, FindingCategory,
    Severity,
};
use hardener_compliance::config::OutputFormat;
use hardener_compliance::{
    ComplianceReport, ComplianceSummary, ControlResult, ReportConfig, ReportGenerator, Scenario,
};
use hardener_core::config::scope::ComplianceConfig;
use hardener_core::plugin::Finding;
use hardener_types::ExceptionOutcome;
use hardener_types::{PluginCoverage, PluginId, PluginInventory, PluginMetadata, ScanResult};

fn mapping(framework: ComplianceFramework, id: &str) -> ComplianceMapping {
    ComplianceMapping {
        compliance_framework: framework,
        compliance_control_id: id.to_string(),
        compliance_control_title: format!("Control {id}"),
        compliance_section: Some("Access Control".to_string()),
    }
}

/// An insecure `PermitRootLogin` finding, tagged for both CIS and STIG: the
/// shape the SSH plugin now emits (multi-framework mappings).
fn insecure_root_login() -> Finding {
    Finding {
        finding_category: FindingCategory::Network,
        finding_current_value: "yes".to_string(),
        finding_description: "Disable direct root login via SSH".to_string(),
        finding_explanation: "Root login over SSH is enabled.".to_string(),
        finding_id: "ssh-permitrootlogin".to_string(),
        finding_impact: "Allows direct privileged remote access".to_string(),
        finding_recommended_value: "no".to_string(),
        finding_remediation_steps: vec!["Set PermitRootLogin no".to_string()],
        finding_severity: Severity::Critical,
        finding_title: "Insecure SSH setting: PermitRootLogin".to_string(),
        finding_compliance: vec![
            mapping(ComplianceFramework::CIS, "5.2.10"),
            mapping(ComplianceFramework::STIG, "RHEL-08-010550"),
        ],
        finding_exception: ExceptionOutcome::NotConfigured,
        finding_exception_key: None,
    }
}

/// One plugin declaring `coverage`, which reported `findings` and completed.
///
/// The generator flattens results itself now, so a test that wants "these
/// controls are assessed and here is what was found" says so by handing it a
/// plugin that ran. Passing findings with no plugin behind them would be the
/// unassessed case, which is a different test.
fn scanned(
    coverage: Vec<ComplianceMapping>,
    findings: &[Finding],
) -> (PluginInventory, ScanResult) {
    let id = "test-plugin";
    (
        PluginInventory::Known(vec![PluginCoverage {
            metadata: PluginMetadata {
                plugin_category: FindingCategory::Kernel,
                plugin_description: String::new(),
                plugin_id: PluginId::new(id),
                plugin_name: "test plugin".to_string(),
                plugin_version: "0.1.0".to_string(),
            },
            coverage,
        }]),
        ScanResult {
            scan_plugin_id: PluginId::new(id),
            scan_success: true,
            scan_findings: findings.to_vec(),
            scan_unchecked: vec![],
            scan_duration_us: 0,
            scan_error: None,
        },
    )
}

fn report_for(
    framework: ComplianceFramework,
    coverage: Vec<ComplianceMapping>,
    findings: &[Finding],
) -> ComplianceReport {
    let (inventory, result) = scanned(coverage, findings);
    ReportGenerator::new(
        ReportConfig {
            scenario: Scenario::Custom(vec![framework]),
            formats: vec![OutputFormat::Text],
            output_dir: None,
            profile: ComplianceProfile::default(),
        },
        inventory,
        ComplianceConfig::default(),
    )
    .generate(&[result], &[])
    .into_iter()
    .next()
    .expect("one report")
}

/// A control result carrying nothing but the status the score is computed from.
fn control(id: &str, status: ControlStatus) -> ControlResult {
    ControlResult {
        control_id: id.to_string(),
        control_title: format!("Control {id}"),
        control_section: "Fixture".to_string(),
        control_status: status,
        control_findings: Vec::new(),
    }
}

#[test]
fn wholesale_exclusion_does_not_score_as_full_compliance() {
    // An operator can now declare controls not applicable in configuration, so
    // an all-excluded framework is reachable from input rather than impossible.
    // Nothing was assessed, and of the two readings available for an empty
    // denominator the one that claims full compliance is the forbidden one.
    let controls = vec![
        control("1.1", ControlStatus::NotApplicable),
        control("1.2", ControlStatus::NotApplicable),
        control("1.3", ControlStatus::NotApplicable),
    ];

    let summary = ComplianceSummary::from_controls(&controls);

    assert_eq!(summary.summary_total_controls, 3);
    assert_eq!(summary.summary_not_applicable, 3);
    assert_ne!(
        summary.summary_score_percentage, 100.0,
        "every control excluded means nothing was assessed; the report, the PDF \
         and the CSV must not print full compliance"
    );
}

#[test]
fn a_genuinely_empty_report_still_scores_full() {
    // The guard above must not spread to the empty report, where there are no
    // controls at all and so nothing to overstate.
    let summary = ComplianceSummary::from_controls(&[]);

    assert_eq!(summary.summary_total_controls, 0);
    assert_eq!(summary.summary_score_percentage, 100.0);
}

#[test]
fn unassessed_curated_controls_are_manual_review_not_false_pass() {
    // CIS ships a curated catalogue. With an empty coverage set the engine
    // assesses nothing, so every control must require manual review, never a
    // fabricated "100% compliant".
    let report = report_for(ComplianceFramework::CIS, vec![], &[]);
    let s = &report.report_summary;

    assert!(s.summary_total_controls > 0, "CIS has a curated catalogue");
    assert_eq!(s.summary_passing, 0, "nothing assessed must not pass");
    assert_eq!(s.summary_failing, 0, "no findings to fail on");
    assert_eq!(
        s.summary_manual_review, s.summary_total_controls,
        "every unassessed control must be flagged for manual review"
    );
    assert_ne!(
        s.summary_score_percentage, 100.0,
        "must not claim full compliance"
    );
}

#[test]
fn assessed_passing_control_reports_pass() {
    // Option B: a covered control with no finding is a genuine pass.
    let report = report_for(
        ComplianceFramework::CIS,
        vec![mapping(ComplianceFramework::CIS, "1.5.1")],
        &[],
    );
    let control = report
        .report_controls
        .iter()
        .find(|c| c.control_id == "1.5.1")
        .expect("covered control present");
    assert_eq!(control.control_status, ControlStatus::Pass);
    // Uncovered curated controls remain manual review, not pass.
    assert!(report.report_summary.summary_manual_review >= 1);
}

#[test]
fn assessed_failing_control_reports_fail() {
    let report = report_for(
        ComplianceFramework::CIS,
        vec![mapping(ComplianceFramework::CIS, "5.2.10")],
        &[insecure_root_login()],
    );
    let control = report
        .report_controls
        .iter()
        .find(|c| c.control_id == "5.2.10")
        .expect("covered control present");
    assert_eq!(control.control_status, ControlStatus::Fail);
}

#[test]
fn derived_framework_reports_only_assessed_controls() {
    // STIG has no curated catalogue: its controls are derived from coverage.
    // A clean system reports every covered control as Pass (Option B) and
    // introduces no manual-review noise from controls the engine never checks.
    let coverage = vec![
        mapping(ComplianceFramework::STIG, "RHEL-08-010430"),
        mapping(ComplianceFramework::STIG, "RHEL-08-010550"),
    ];
    let report = report_for(ComplianceFramework::STIG, coverage, &[]);
    let s = &report.report_summary;

    assert_eq!(s.summary_total_controls, 2);
    assert_eq!(s.summary_passing, 2);
    assert_eq!(s.summary_manual_review, 0);
}

#[test]
fn derived_framework_fails_on_insecure_finding() {
    let coverage = vec![mapping(ComplianceFramework::STIG, "RHEL-08-010550")];
    let report = report_for(
        ComplianceFramework::STIG,
        coverage,
        &[insecure_root_login()],
    );
    assert!(
        report.report_summary.summary_failing >= 1,
        "a STIG-mapped insecure finding must fail"
    );
}

#[test]
fn noncatalogue_finding_mapping_surfaces_as_failure() {
    // Safe-failure invariant: a finding referencing a control that is in neither
    // the catalogue nor the coverage set must still produce a real failure, never
    // be silently dropped. A wrong mapping can only ever over-report a failure.
    let mut finding = insecure_root_login();
    finding.finding_compliance.push(mapping(
        ComplianceFramework::STIG,
        "OL08-00-999999", // not in coverage, no curated catalogue
    ));
    let report = report_for(ComplianceFramework::STIG, vec![], &[finding]);

    assert!(report.report_summary.summary_failing >= 1);
    assert!(
        report
            .report_controls
            .iter()
            .any(|c| c.control_id == "OL08-00-999999"),
        "the non-catalogue control must appear in the report"
    );
}
