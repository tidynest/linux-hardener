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

const CSV_HEADER: &str = "Framework,Framework Name,Framework Description,Control ID,Control Title,Section,Status,Finding Count\n";

impl ReportFormatter for CsvFormatter {
    fn format(&self, report: &ComplianceReport) -> String {
        let mut output = String::from(CSV_HEADER);
        write_report_rows(&mut output, report);
        output
    }

    fn format_all(&self, reports: &[ComplianceReport]) -> String {
        let mut output = String::from(CSV_HEADER);
        for report in reports {
            write_report_rows(&mut output, report);
        }
        output
    }
}

fn write_report_rows(output: &mut String, report: &ComplianceReport) {
    let framework_escaped = escape_csv_field(&report.report_framework.to_string());
    let framework_name = escape_csv_field(report.report_framework.full_name());
    let framework_description = escape_csv_field(report.report_framework.description());

    for control in &report.report_controls {
        let status_str = match control.control_status {
            ControlStatus::Pass => "PASS",
            ControlStatus::Fail => "FAIL",
            ControlStatus::NotApplicable => "N/A",
            ControlStatus::ManualReview => "MANUAL",
        };

        output.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            framework_escaped,
            framework_name,
            framework_description,
            escape_csv_field(&control.control_id),
            escape_csv_field(&control.control_title),
            escape_csv_field(&control.control_section),
            status_str,
            control.control_findings.len(),
        ));
    }
}

/// Escapes a CSV field by wrapping in quotes if it contains special characters.
///
/// Also neutralises formula injection: cells starting with `=`, `+`, `-`,
/// `@`, `\t`, or `\r` are prefixed with a tab inside the quoted field
/// (OWASP recommendation) to prevent spreadsheet formula execution.
fn escape_csv_field(field: &str) -> String {
    let needs_formula_guard = field
        .as_bytes()
        .first()
        .is_some_and(|&b| matches!(b, b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r'));

    if needs_formula_guard || field.contains(',') || field.contains('"') || field.contains('\n') {
        let escaped = field.replace('"', "\"\"");
        if needs_formula_guard {
            format!("\"\t{}\"", escaped)
        } else {
            format!("\"{}\"", escaped)
        }
    } else {
        field.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{ComplianceReport, ComplianceSummary, ControlResult};
    use chrono::Utc;
    use hardener_common::types::{ComplianceFramework, ComplianceProfile};

    #[test]
    fn test_csv_formatter_basic() {
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

        let formatter = CsvFormatter::new();
        let output = formatter.format(&report);

        assert!(output.contains("Framework,Framework Name,Framework Description,Control ID"));
        assert!(output.contains("CIS,CIS Benchmark"));
        assert!(output.contains("Center for Internet Security Benchmarks for Linux"));
        assert!(output.contains("PASS"));
        assert!(output.contains("FAIL"));
    }

    #[test]
    fn test_csv_escape() {
        assert_eq!(escape_csv_field("simple"), "simple");
        assert_eq!(escape_csv_field("with,comma"), "\"with,comma\"");
        assert_eq!(escape_csv_field("with\"quote"), "\"with\"\"quote\"");
    }

    #[test]
    fn test_csv_formula_injection_guard() {
        // Formula-triggering characters get tab-prefixed inside quotes
        assert_eq!(
            escape_csv_field("=cmd|'/C calc'!A0"),
            "\"\t=cmd|'/C calc'!A0\""
        );
        assert_eq!(escape_csv_field("+1+1"), "\"\t+1+1\"");
        assert_eq!(escape_csv_field("-1-1"), "\"\t-1-1\"");
        assert_eq!(escape_csv_field("@SUM(A1)"), "\"\t@SUM(A1)\"");
        // Normal text unchanged
        assert_eq!(
            escape_csv_field("Ensure ASLR is enabled"),
            "Ensure ASLR is enabled"
        );
    }
}
