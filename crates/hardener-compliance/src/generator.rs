//! Report generation from scan findings.
//!
//! The ReportGenerator takes scan findings and the engine's automated-coverage
//! set and produces compliance reports by mapping findings to framework controls.

use crate::config::ReportConfig;
use crate::frameworks;
use crate::report::{ComplianceReport, ComplianceSummary, ControlResult};
use chrono::Utc;
use hardener_common::types::{ComplianceFramework, ComplianceMapping, ControlStatus};
use hardener_core::plugin::Finding;
use std::collections::HashSet;

/// Generates compliance reports from scan findings.
pub struct ReportGenerator {
    config: ReportConfig,
    /// Every `(framework, control)` the engine actually assesses, supplied by the
    /// caller (the plugins crate's `compliance_coverage()`). A control present
    /// here can report `Pass`/`Fail`; one absent is `ManualReview`.
    coverage: Vec<ComplianceMapping>,
}

impl ReportGenerator {
    /// Creates a new ReportGenerator.
    ///
    /// `coverage` is the engine's automated-coverage set — the union of every
    /// control any plugin can assess. Callers obtain it from
    /// `hardener_plugins::compliance_coverage()`; the compliance crate stays
    /// independent of the plugins crate by taking it as a parameter.
    pub fn new(config: ReportConfig, coverage: Vec<ComplianceMapping>) -> Self {
        Self { config, coverage }
    }

    /// Generates compliance reports for all frameworks in the configured scenario.
    ///
    /// Returns one report per framework.
    pub fn generate(&self, findings: &[Finding]) -> Vec<ComplianceReport> {
        self.config
            .scenario
            .frameworks()
            .iter()
            .map(|framework| self.generate_for_framework(framework, findings))
            .collect()
    }

    /// Generates a compliance report for a single framework.
    fn generate_for_framework(
        &self,
        framework: &ComplianceFramework,
        findings: &[Finding],
    ) -> ComplianceReport {
        // Controls the engine assesses for this framework, from plugin coverage.
        let assessed: HashSet<&str> = self
            .coverage
            .iter()
            .filter(|m| m.compliance_framework == *framework)
            .map(|m| m.compliance_control_id.as_str())
            .collect();

        // Build the control catalogue: the curated standard (CIS / ISO 27001),
        // if any, merged with the derived coverage set and deduplicated by id.
        // For frameworks without a curated catalogue the result *is* the coverage
        // set, so every listed control is assessed and reports `Pass`/`Fail`.
        let mut catalogue = frameworks::curated_controls(framework).unwrap_or_default();
        let mut catalogue_ids: HashSet<String> = catalogue
            .iter()
            .map(|c| c.compliance_control_id.clone())
            .collect();
        for mapping in self
            .coverage
            .iter()
            .filter(|m| m.compliance_framework == *framework)
        {
            if catalogue_ids.insert(mapping.compliance_control_id.clone()) {
                catalogue.push(mapping.clone());
            }
        }

        // Map each control to a result. A mapped finding always fails the control.
        // With no finding, the control passes only if the engine actually assesses
        // it; otherwise the absence of a finding proves nothing, so it requires
        // manual review rather than a misleading automatic pass.
        let mut controls: Vec<ControlResult> = catalogue
            .iter()
            .map(|control| {
                let related = related_findings(findings, framework, &control.compliance_control_id);
                let status = if !related.is_empty() {
                    ControlStatus::Fail
                } else if assessed.contains(control.compliance_control_id.as_str()) {
                    ControlStatus::Pass
                } else {
                    ControlStatus::ManualReview
                };
                ControlResult {
                    control_id: control.compliance_control_id.clone(),
                    control_title: control.compliance_control_title.clone(),
                    control_section: control
                        .compliance_section
                        .clone()
                        .unwrap_or_else(|| "General".to_string()),
                    control_status: status,
                    control_findings: related,
                }
            })
            .collect();

        // Safe-failure net: a finding referencing a control absent from the
        // catalogue is still a real failure and must appear in the report rather
        // than be silently dropped. (With derived catalogues this is rarely hit,
        // but it guarantees a wrong mapping can only ever over-report a failure.)
        let mut seen: HashSet<String> = controls.iter().map(|c| c.control_id.clone()).collect();
        for mapping in findings.iter().flat_map(|f| &f.finding_compliance) {
            if mapping.compliance_framework != *framework
                || !seen.insert(mapping.compliance_control_id.clone())
            {
                continue;
            }
            let related = related_findings(findings, framework, &mapping.compliance_control_id);
            controls.push(ControlResult {
                control_id: mapping.compliance_control_id.clone(),
                control_title: mapping.compliance_control_title.clone(),
                control_section: mapping
                    .compliance_section
                    .clone()
                    .unwrap_or_else(|| "General".to_string()),
                control_status: ControlStatus::Fail,
                control_findings: related,
            });
        }

        let summary = ComplianceSummary::from_controls(&controls);

        ComplianceReport {
            report_framework: *framework,
            report_generated_at: Utc::now(),
            report_controls: controls,
            report_summary: summary,
        }
    }
}

/// Collects all findings mapping to a given `(framework, control_id)`.
fn related_findings(
    findings: &[Finding],
    framework: &ComplianceFramework,
    control_id: &str,
) -> Vec<Finding> {
    findings
        .iter()
        .filter(|f| {
            f.finding_compliance.iter().any(|c| {
                c.compliance_framework == *framework && c.compliance_control_id == control_id
            })
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{OutputFormat, Scenario};
    use hardener_common::types::{FindingCategory, Severity};

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

    fn mapping(framework: ComplianceFramework, id: &str) -> ComplianceMapping {
        ComplianceMapping {
            compliance_framework: framework,
            compliance_control_id: id.to_string(),
            compliance_control_title: format!("Control {id}"),
            compliance_section: Some("Test Section".to_string()),
        }
    }

    fn config_for(framework: ComplianceFramework) -> ReportConfig {
        ReportConfig {
            scenario: Scenario::Custom(vec![framework]),
            formats: vec![OutputFormat::Text],
            output_dir: None,
        }
    }

    #[test]
    fn assessed_control_passes_on_clean_system() {
        // CIS 1.5.1 is in coverage; with no finding it must report Pass (Option B).
        let coverage = vec![mapping(ComplianceFramework::CIS, "1.5.1")];
        let generator = ReportGenerator::new(config_for(ComplianceFramework::CIS), coverage);
        let report = generator.generate(&[]).pop().unwrap();

        let result = report
            .report_controls
            .iter()
            .find(|c| c.control_id == "1.5.1")
            .expect("1.5.1 in catalogue");
        assert_eq!(result.control_status, ControlStatus::Pass);
    }

    #[test]
    fn mapped_finding_fails_its_control() {
        let coverage = vec![mapping(ComplianceFramework::CIS, "1.5.1")];
        let generator = ReportGenerator::new(config_for(ComplianceFramework::CIS), coverage);
        let report = generator.generate(&[cis_finding("1.5.1")]).pop().unwrap();

        assert!(report.report_summary.summary_failing >= 1);
        let result = report
            .report_controls
            .iter()
            .find(|c| c.control_id == "1.5.1")
            .unwrap();
        assert_eq!(result.control_status, ControlStatus::Fail);
    }

    #[test]
    fn uncovered_catalogue_control_is_manual_review() {
        // A curated CIS control with no coverage entry cannot be auto-passed.
        let generator = ReportGenerator::new(config_for(ComplianceFramework::CIS), vec![]);
        let report = generator.generate(&[]).pop().unwrap();

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
        let report = generator.generate(&[]).pop().unwrap();

        assert_eq!(report.report_summary.summary_total_controls, 1);
        assert_eq!(report.report_summary.summary_passing, 1);
        assert_eq!(report.report_summary.summary_manual_review, 0);
    }

    #[test]
    fn noncatalogue_finding_still_surfaces_as_failure() {
        // A finding whose control id is in neither catalogue nor coverage must
        // still fail — a wrong mapping can only ever over-report a failure.
        let mut finding = cis_finding("1.5.1");
        finding
            .finding_compliance
            .push(mapping(ComplianceFramework::STIG, "OL08-00-999999"));
        let generator = ReportGenerator::new(config_for(ComplianceFramework::STIG), vec![]);
        let report = generator.generate(&[finding]).pop().unwrap();

        assert!(
            report.report_controls.iter().any(
                |c| c.control_id == "OL08-00-999999" && c.control_status == ControlStatus::Fail
            )
        );
    }
}
