//! JSON report formatter.
//!
//! Produces machine-readable compliance reports in JSON format.

use crate::output::ReportFormatter;
use crate::report::ComplianceReport;
use serde::Serialize;

/// Extended report with framework metadata for JSON output.
#[derive(Serialize)]
struct JsonReport<'a> {
    /// The compliance framework identifier.
    report_framework: &'a hardener_common::types::ComplianceFramework,
    /// Full name of the framework.
    report_framework_name: &'static str,
    /// Description of the framework.
    report_framework_description: &'static str,
    /// When this report was generated.
    report_generated_at: &'a chrono::DateTime<chrono::Utc>,
    /// Individual control check results.
    report_controls: &'a [hardener_types::ControlResult],
    /// Summary statistics for the report.
    report_summary: &'a hardener_types::ComplianceSummary,
}

impl<'a> JsonReport<'a> {
    fn from_report(report: &'a ComplianceReport) -> Self {
        JsonReport {
            report_framework: &report.report_framework,
            report_framework_name: report.report_framework.full_name(),
            report_framework_description: report.report_framework.description(),
            report_generated_at: &report.report_generated_at,
            report_controls: &report.report_controls,
            report_summary: &report.report_summary,
        }
    }
}

/// Formats compliance reports as JSON.
pub struct JsonFormatter {
    /// Whether to pretty-print the output.
    pretty: bool,
}

impl JsonFormatter {
    /// Creates a new JsonFormatter with compact output.
    pub fn new() -> JsonFormatter {
        JsonFormatter { pretty: false }
    }

    /// Creates a new JsonFormatter with pretty-printed output.
    pub fn pretty() -> Self {
        JsonFormatter { pretty: true }
    }
}

impl Default for JsonFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportFormatter for JsonFormatter {
    fn format(&self, report: &ComplianceReport) -> String {
        let json_report = JsonReport::from_report(report);
        if self.pretty {
            serde_json::to_string_pretty(&json_report)
                .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialise report: {}\"}}", e))
        } else {
            serde_json::to_string(&json_report)
                .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialise report: {}\"}}", e))
        }
    }

    fn format_all(&self, reports: &[ComplianceReport]) -> String {
        let json_reports: Vec<_> = reports.iter().map(JsonReport::from_report).collect();
        if self.pretty {
            serde_json::to_string_pretty(&json_reports).unwrap_or_else(|e| {
                format!("{{\"error\": \"Failed to serialise reports: {}\"}}", e)
            })
        } else {
            serde_json::to_string(&json_reports).unwrap_or_else(|e| {
                format!("{{\"error\": \"Failed to serialise reports: {}\"}}", e)
            })
        }
    }
}

#[cfg(test)]
mod tests;
