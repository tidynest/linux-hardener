//! Regression tests for honest compliance assessment.
//!
//! A control that the hardening engine does not automatically assess must be
//! reported as `ManualReview`, never as a green `Pass`. Today only CIS findings
//! are emitted by plugins, so every other framework's controls are unassessed
//! and must surface as "manual review" — not a false "100% compliant".

use hardener_common::types::{ComplianceFramework, ComplianceMapping, FindingCategory, Severity};
use hardener_compliance::config::OutputFormat;
use hardener_compliance::{ComplianceReport, ReportConfig, ReportGenerator, Scenario};
use hardener_core::plugin::Finding;

/// A finding for an insecure `PermitRootLogin`, carrying only a CIS mapping —
/// exactly what the SSH plugin emits today.
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
        finding_compliance: vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "5.2.10".to_string(),
            compliance_control_title: "Ensure SSH root login is disabled".to_string(),
            compliance_section: Some("Access Control".to_string()),
        }],
        finding_policy_exception: None,
    }
}

fn report_for(framework: ComplianceFramework, findings: &[Finding]) -> ComplianceReport {
    ReportGenerator::new(ReportConfig {
        scenario: Scenario::Custom(vec![framework]),
        formats: vec![OutputFormat::Text],
        output_dir: None,
    })
    .generate(findings)
    .into_iter()
    .next()
    .expect("one report")
}

#[test]
fn unassessed_framework_reports_manual_review_not_false_pass() {
    // An insecure system, evaluated against a framework the engine does NOT
    // automatically assess (only CIS is wired today).
    let report = report_for(ComplianceFramework::STIG, &[insecure_root_login()]);
    let s = &report.report_summary;

    assert!(s.summary_total_controls > 0, "STIG has a control catalog");
    // The honest result: no automated pass, no automated fail — manual review.
    assert_eq!(
        s.summary_passing, 0,
        "must NOT mark unassessed controls as passing"
    );
    assert_eq!(
        s.summary_failing, 0,
        "no STIG finding mappings exist to fail on"
    );
    assert_eq!(
        s.summary_manual_review, s.summary_total_controls,
        "every unassessed control must be flagged for manual review"
    );
    // And crucially: not a false "100% compliant".
    assert_ne!(
        s.summary_score_percentage, 100.0,
        "must not claim full compliance"
    );
}

#[test]
fn cis_is_assessed_so_it_still_passes_and_fails_normally() {
    // CIS is automatically assessed: an insecure finding must FAIL its control,
    // and the remaining CIS controls must still PASS (not regress to manual review).
    let report = report_for(ComplianceFramework::CIS, &[insecure_root_login()]);
    let s = &report.report_summary;

    assert!(
        s.summary_failing >= 1,
        "CIS must detect the insecure finding"
    );
    assert!(s.summary_passing >= 1, "other CIS controls still pass");
    assert_eq!(
        s.summary_manual_review, 0,
        "CIS controls are assessed, never manual review"
    );
}

#[test]
fn clean_system_does_not_fabricate_compliance_for_unassessed_frameworks() {
    // No findings at all (a clean scan). CIS = all pass; STIG = all manual review.
    let cis = report_for(ComplianceFramework::CIS, &[]);
    assert_eq!(
        cis.report_summary.summary_passing, cis.report_summary.summary_total_controls,
        "clean system passes all assessed CIS controls"
    );

    let stig = report_for(ComplianceFramework::STIG, &[]);
    assert_eq!(
        stig.report_summary.summary_manual_review, stig.report_summary.summary_total_controls,
        "clean system still cannot auto-certify STIG — manual review"
    );
}
