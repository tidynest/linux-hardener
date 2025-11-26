//! JSON report formatter.
//!
//! Produces machine-readable compliance reports in JSON format.

use crate::output::ReportFormatter;
use crate::report::ComplianceReport;

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
        if self.pretty {
            serde_json::to_string_pretty(report)
                .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialise report: {}\"}}", e))
        } else {
            serde_json::to_string(report)
                .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialise report: {}\"}}", e))
        }
    }

    fn format_all(&self, reports: &[ComplianceReport]) -> String {
        if self.pretty {
            serde_json::to_string_pretty(reports).unwrap_or_else(|e| {
                format!("{{\"error\": \"Failed to serialise reports: {}\"}}", e)
            })
        } else {
            serde_json::to_string(reports).unwrap_or_else(|e| {
                format!("{{\"error\": \"Failed to serialise reports: {}\"}}", e)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{ComplianceReport, ComplianceSummary, ControlResult};
    use chrono::Utc;
    use hardener_common::types::{ComplianceFramework, ControlStatus};

    #[test]
    fn test_json_formatter_basic() {
        let report = ComplianceReport {
            report_framework: ComplianceFramework::CIS,
            report_generated_at: Utc::now(),
            report_controls: vec![ControlResult {
                control_id: "1.5.1".to_string(),
                control_title: "Ensure ASLR is enabled".to_string(),
                control_section: "Initial Setup".to_string(),
                control_status: ControlStatus::Pass,
                control_findings: vec![],
            }],
            report_summary: ComplianceSummary {
                summary_total_controls: 1,
                summary_passing: 1,
                summary_failing: 0,
                summary_not_applicable: 0,
                summary_manual_review: 0,
                summary_score_percentage: 100.0,
            },
        };

        let formatter = JsonFormatter::new();
        let output = formatter.format(&report);

        assert!(output.contains("\"report_framework\":\"CIS\""));
        assert!(output.contains("\"control_id\":\"1.5.1\""));
        assert!(output.contains("\"summary_score_percentage\":100.0"));
    }

    #[test]
    fn test_json_formatter_pretty() {
        let report = ComplianceReport {
            report_framework: ComplianceFramework::CIS,
            report_generated_at: Utc::now(),
            report_controls: vec![],
            report_summary: ComplianceSummary {
                summary_total_controls: 0,
                summary_passing: 0,
                summary_failing: 0,
                summary_not_applicable: 0,
                summary_manual_review: 0,
                summary_score_percentage: 100.0,
            },
        };

        let formatter = JsonFormatter::pretty();
        let output = formatter.format(&report);

        // Pretty format should have newlines
        assert!(output.contains('\n'));
        assert!(output.contains("  ")); // Indentation
    }
}
