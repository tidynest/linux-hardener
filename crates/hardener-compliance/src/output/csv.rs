//! CSV report formatter.
//!
//! Produces compliance reports in CSV format for spreadsheet analysis.

use crate::output::ReportFormatter;
use crate::report::ComplianceReport;
use hardener_common::types::ControlStatus;

/// Formats compliance reports as CSV.
pub struct CsvFormatter;

impl CsvFormatter {
    /// Creates a new CsvFormatter.
    pub fn new() -> Self {
        Self
    }
}

impl Default for CsvFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportFormatter for CsvFormatter {
    fn format(&self, report: &ComplianceReport) -> String {
        let mut output = String::new();

        // CSV Header
        output.push_str("Framework,Control ID,Control Title,Section,Status,Finding Count\n");

        // Data rows
        for control in &report.report_controls {
            let status_str = match control.control_status {
                ControlStatus::Pass => "PASS",
                ControlStatus::Fail => "FAIL",
                ControlStatus::NotApplicable => "N/A",
                ControlStatus::ManualReview => "MANUAL",
            };

            // Escape CSV fields that might contain commas or quotes
            let title_escaped = escape_csv_field(&control.control_title);
            let section_escaped = escape_csv_field(&control.control_section);

            output.push_str(&format!(
                "{},{},{},{},{},{}\n",
                report.report_framework,
                control.control_id,
                title_escaped,
                section_escaped,
                status_str,
                control.control_findings.len()
            ));
        }

        output
    }

    fn format_all(&self, reports: &[ComplianceReport]) -> String {
        let mut output = String::new();

        // CSV Header (once)
        output.push_str("Framework,Control ID,Control Title,Section,Status,Finding Count\n");

        // Data rows from all reports
        for report in reports {
            for control in &report.report_controls {
                let status_str = match control.control_status {
                    ControlStatus::Pass => "PASS",
                    ControlStatus::Fail => "FAIL",
                    ControlStatus::NotApplicable => "N/A",
                    ControlStatus::ManualReview => "MANUAL",
                };

                let title_escaped = escape_csv_field(&control.control_title);
                let section_escaped = escape_csv_field(&control.control_section);

                output.push_str(&format!(
                    "{},{},{},{},{},{}\n",
                    report.report_framework,
                    control.control_id,
                    title_escaped,
                    section_escaped,
                    status_str,
                    control.control_findings.len()
                ));
            }
        }

        output
    }
}

/// Escapes a CSV field by wrapping in quotes if it contains special characters.
fn escape_csv_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{ComplianceReport, ComplianceSummary, ControlResult};
    use chrono::Utc;
    use hardener_common::types::ComplianceFramework;

    #[test]
    fn test_csv_formatter_basic() {
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

        let formatter = CsvFormatter::new();
        let output = formatter.format(&report);

        assert!(output.contains("Framework,Control ID"));
        assert!(output.contains("CIS,1.5.1"));
        assert!(output.contains("PASS"));
        assert!(output.contains("FAIL"));
    }

    #[test]
    fn test_csv_escape() {
        assert_eq!(escape_csv_field("simple"), "simple");
        assert_eq!(escape_csv_field("with,comma"), "\"with,comma\"");
        assert_eq!(escape_csv_field("with\"quote"), "\"with\"\"quote\"");
    }
}
