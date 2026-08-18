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

        // The controls a human declared out of scope, named individually. They
        // left the score's denominator and so raised it, and a reader cannot
        // tell that from a number that rose because the host improved unless
        // the artefact says which controls stopped counting. The declared
        // reason lives in the scope configuration rather than on the report, so
        // the listing identifies each control instead of quoting it.
        let excluded: Vec<&crate::report::ControlResult> = report
            .report_controls
            .iter()
            .filter(|control| control.control_status == ControlStatus::NotApplicable)
            .collect();
        if !excluded.is_empty() {
            const EXCLUDED_HEADING: &str = "Not applicable";
            output.push_str(&format!("\n{EXCLUDED_HEADING}\n"));
            output.push_str(&"-".repeat(EXCLUDED_HEADING.len()));
            output.push('\n');
            output.push_str("  Declared out of scope, so outside the score below.\n");
            for control in excluded {
                output.push_str(&format!(
                    "  {} {}\n",
                    control.control_id, control.control_title
                ));
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

        // Directly under the score, because it is the score the caveat is
        // about: the checks that could not run are in its denominator, so a
        // privileged re-run produces a different number. The report used to
        // publish the figure and say nothing, and the report is the artefact
        // an operator keeps (#161).
        if let Some(note) = report.report_coverage_note.as_deref() {
            output.push_str(&format!("\n  {note}\n"));
        }

        output
    }
}

#[cfg(test)]
mod tests;
