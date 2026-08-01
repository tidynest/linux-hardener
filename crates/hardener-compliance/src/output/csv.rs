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

        // Live violations only: a control now carries its excepted findings as
        // evidence, and counting those here would report a documented deviation
        // as a finding against a control this run passed. The exceptions
        // themselves are listed in the text, HTML, PDF and JSON reports.
        let live_findings = control
            .control_findings
            .iter()
            .filter(|f| !f.is_policy_excepted())
            .count();

        output.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            framework_escaped,
            framework_name,
            framework_description,
            escape_csv_field(&control.control_id),
            escape_csv_field(&control.control_title),
            escape_csv_field(&control.control_section),
            status_str,
            live_findings,
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
mod tests;
