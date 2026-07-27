//! Plain text report formatter.
//!
//! Produces human-readable compliance reports for terminal output.

use crate::output::{ReportFormatter, report_title};
use crate::report::ComplianceReport;
use hardener_common::types::ControlStatus;

/// Formats compliance reports as plain text.
pub struct TextFormatter;

impl TextFormatter {
    /// Creates a new TextFormatter.
    pub fn new() -> Self {
        Self
    }
}

impl Default for TextFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportFormatter for TextFormatter {
    fn format(&self, report: &ComplianceReport) -> String {
        let mut output = String::new();

        // Header
        output.push_str(&report_title(report));
        output.push('\n');
        output.push_str(report.report_framework.description());
        output.push('\n');
        output.push_str(&"=".repeat(60));
        output.push('\n');
        output.push_str(&format!(
            "Generated: {}\n",
            report.report_generated_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        output.push('\n');

        // Group controls by section
        let mut sections: std::collections::BTreeMap<&str, Vec<&crate::report::ControlResult>> =
            std::collections::BTreeMap::new();

        for control in &report.report_controls {
            sections
                .entry(control.control_section.as_str())
                .or_default()
                .push(control);
        }

        // Output each section
        for (section, controls) in &sections {
            output.push_str(&format!("\n{}\n", section));
            output.push_str(&"-".repeat(section.len()));
            output.push('\n');

            for control in controls {
                let status_str = match control.control_status {
                    ControlStatus::Pass => "[PASS]",
                    ControlStatus::Fail => "[FAIL]",
                    ControlStatus::NotApplicable => "[N/A] ",
                    ControlStatus::ManualReview => "[MANUAL]",
                };

                output.push_str(&format!(
                    "  {} {} {}\n",
                    control.control_id, status_str, control.control_title
                ));

                // Show the evidence behind the status. A control carrying only
                // excepted findings passes, but the documented deviations are
                // still listed so the pass is not mistaken for a clean one.
                for finding in &control.control_findings {
                    output.push_str(&format!(
                        "        → {}: {}\n",
                        finding.evidence_label(),
                        finding.finding_title
                    ));
                }
            }
        }

        // Summary
        output.push_str(&format!("\n{}\n", "=".repeat(60)));
        output.push_str("Summary\n");
        output.push_str(&"-".repeat(7));
        output.push('\n');
        output.push_str(&format!(
            "  Total Controls: {}\n",
            report.report_summary.summary_total_controls
        ));
        output.push_str(&format!(
            "  Passing:        {}\n",
            report.report_summary.summary_passing
        ));
        output.push_str(&format!(
            "  Failing:        {}\n",
            report.report_summary.summary_failing
        ));
        if report.report_summary.summary_not_applicable > 0 {
            output.push_str(&format!(
                "  Not Applicable: {}\n",
                report.report_summary.summary_not_applicable
            ));
        }
        if report.report_summary.summary_manual_review > 0 {
            output.push_str(&format!(
                "  Manual Review:  {}\n",
                report.report_summary.summary_manual_review
            ));
        }
        output.push_str(&format!(
            "  Score:          {:.1}%\n",
            report.report_summary.summary_score_percentage
        ));

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{ComplianceReport, ComplianceSummary, ControlResult};
    use chrono::Utc;
    use hardener_common::types::{ComplianceFramework, ComplianceProfile};

    #[test]
    fn test_text_formatter_basic() {
        let report = ComplianceReport {
            report_framework: ComplianceFramework::CIS,
            report_profile: ComplianceProfile::default(),
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
    fn report_with(
        status: ControlStatus,
        findings: Vec<hardener_types::Finding>,
    ) -> ComplianceReport {
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

    /// An empty STIG report under the given profile.
    fn stig_report(profile: ComplianceProfile) -> ComplianceReport {
        ComplianceReport {
            report_framework: ComplianceFramework::STIG,
            report_profile: profile,
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
}
