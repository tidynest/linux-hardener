//! Plain text report formatter.
//!
//! Produces human-readable compliance reports for terminal output.

use crate::output::ReportFormatter;
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
        output.push_str(&format!(
            "{} Compliance Report\n",
            report.report_framework
        ));
        output.push_str(&"=".repeat(60));
        output.push('\n');
        output.push_str(&format!(
            "Generated: {}\n",
            report.report_generated_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        output.push('\n');

        // Group controls by section
        let mut sections: std::collections::BTreeMap<&str,
            Vec<&crate::report::ControlResult>> =
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

                // Show findings for failed controls
                if control.control_status == ControlStatus::Fail {
                    for finding in &control.control_findings {
                        output.push_str(&format!(
                            "        → {}: {}\n",
                            finding.finding_severity, finding.finding_title
                        ));
                    }
                }
            }
        }

        // Summary
        output.push_str(&format!(
            "\n{}\n",
            "=".repeat(60)
        ));
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
    use hardener_common::types::ComplianceFramework;

    #[test]
    fn test_text_formatter_basic() {
        let report = ComplianceReport {
            report_framework: ComplianceFramework::CIS,
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

        assert!(output.contains("CIS Compliance Report"));
        assert!(output.contains("[PASS]"));
        assert!(output.contains("[FAIL]"));
        assert!(output.contains("Score:          50.0%"));
    }
}