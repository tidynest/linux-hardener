//! Report generation from scan findings.
//!
//! The ReportGenerator takes scan findings and produces compliance reports
//! by mapping findings to framework controls.

use crate::config::ReportConfig;
use crate::frameworks;
use crate::report::{ComplianceReport, ComplianceSummary, ControlResult};
use chrono::Utc;
use hardener_common::types::{ComplianceFramework, ControlStatus};
use hardener_core::plugin::Finding;

/// Generates compliance reports from scan findings.
pub struct ReportGenerator {
    config: ReportConfig,
}

impl ReportGenerator {
    /// Creates a new ReportGenerator with the given configuration.
    pub fn new(config: ReportConfig) -> Self {
        Self { config }
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
        // Get all controls defined for this framework
        let all_controls = frameworks::get_controls(framework);

        // Map each control to its result based on findings
        let controls: Vec<ControlResult> = all_controls
            .iter()
            .map(|control| {
                // Find all findings that map to this control
                let related_findings: Vec<Finding> = findings
                    .iter()
                    .filter(|f| {
                        f.finding_compliance.iter().any(|c| {
                            c.compliance_framework == *framework
                                && c.compliance_control_id == control.compliance_control_id
                        })
                    })
                    .cloned()
                    .collect();

                // Determine status: if there are findings, the control failed
                let status = if related_findings.is_empty() {
                    ControlStatus::Pass
                } else {
                    ControlStatus::Fail
                };

                ControlResult {
                    control_id: control.compliance_control_id.clone(),
                    control_title: control.compliance_control_title.clone(),
                    control_section: control
                        .compliance_section
                        .clone()
                        .unwrap_or_else(|| "General".to_string()),
                    control_status: status,
                    control_findings: related_findings,
                }
            })
            .collect();

        // Calculate summary statistics
        let summary = ComplianceSummary::from_controls(&controls);

        ComplianceReport {
            report_framework: *framework,
            report_generated_at: Utc::now(),
            report_controls: controls,
            report_summary: summary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{OutputFormat, Scenario};
    use hardener_common::types::{ComplianceMapping, FindingCategory, Severity};

    fn create_test_finding(control_id: &str) -> Finding {
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
            finding_compliance: vec![ComplianceMapping {
                compliance_framework: ComplianceFramework::CIS,
                compliance_control_id: control_id.to_string(),
                compliance_control_title: "Test Control".to_string(),
                compliance_section: Some("Test Section".to_string()),
            }],
            finding_policy_exception: None,
        }
    }

    #[test]
    fn test_generate_empty_findings() {
        let config = ReportConfig {
            scenario: Scenario::Server,
            formats: vec![OutputFormat::Text],
            output_dir: None,
        };
        let generator = ReportGenerator::new(config);
        let reports = generator.generate(&[]);

        // Server scenario includes CIS and STIG
        assert_eq!(reports.len(), 2);

        // With no findings, all controls should pass
        for report in &reports {
            assert_eq!(report.report_summary.summary_failing, 0);
            assert_eq!(
                report.report_summary.summary_passing,
                report.report_summary.summary_total_controls
            );
        }
    }

    #[test]
    fn test_generate_with_findings() {
        let config = ReportConfig {
            scenario: Scenario::Custom(vec![ComplianceFramework::CIS]),
            formats: vec![OutputFormat::Text],
            output_dir: None,
        };
        let generator = ReportGenerator::new(config);

        // Create a finding that maps to CIS 1.5.1
        let findings = vec![create_test_finding("1.5.1")];
        let reports = generator.generate(&findings);

        assert_eq!(reports.len(), 1);
        let report = &reports[0];

        // Should have at least one failing control
        assert!(report.report_summary.summary_failing >= 1);
    }
}
