//! HTML report formatter.
//!
//! Produces styled HTML compliance reports for web viewing and sharing.

use crate::output::{ReportFormatter, report_title};
use crate::report::ComplianceReport;
use hardener_common::types::ControlStatus;

/// Formats compliance reports as HTML.
pub struct HtmlFormatter;

impl HtmlFormatter {
    /// Creates a new HtmlFormatter.
    pub fn new() -> Self {
        Self
    }
}

impl Default for HtmlFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportFormatter for HtmlFormatter {
    fn format(&self, report: &ComplianceReport) -> String {
        let mut html = String::new();

        // HTML Header with embedded CSS
        html.push_str(HTML_HEADER);

        // Report Title
        html.push_str(&format!(
            "<h1>{}</h1>\n",
            html_escape(&report_title(report))
        ));
        html.push_str(&format!(
            "<p class=\"subtitle\">{}</p>\n",
            html_escape(report.report_framework.description())
        ));
        html.push_str(&format!(
            "<p class=\"generated\">Generated: {}</p>\n",
            report.report_generated_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        // Summary Box
        html.push_str("<div class=\"summary\">\n");
        html.push_str("<h2>Summary</h2>\n");
        html.push_str(&format!(
            "<div class=\"score\">{:.1}%</div>\n",
            report.report_summary.summary_score_percentage
        ));
        html.push_str("<div class=\"stats\">\n");
        html.push_str(&format!(
            "<span class=\"pass\">Passing: {}</span>\n",
            report.report_summary.summary_passing
        ));
        html.push_str(&format!(
            "<span class=\"fail\">Failing: {}</span>\n",
            report.report_summary.summary_failing
        ));
        if report.report_summary.summary_not_applicable > 0 {
            html.push_str(&format!(
                "<span class=\"na\">N/A: {}</span>\n",
                report.report_summary.summary_not_applicable
            ));
        }
        html.push_str("</div>\n</div>\n");

        let sections_vec = super::group_controls_by_section(report);

        for (section, controls) in &sections_vec {
            html.push_str(&format!("<h2>{}</h2>\n", html_escape(section)));
            html.push_str("<table>\n");
            html.push_str(
                "<thead><tr><th>Control ID</th><th>Title</th><th>Status</th></tr></thead>\n",
            );
            html.push_str("<tbody>\n");

            for control in controls {
                let (status_str, status_class) = match control.control_status {
                    ControlStatus::Pass => ("PASS", "pass"),
                    ControlStatus::Fail => ("FAIL", "fail"),
                    ControlStatus::NotApplicable => ("N/A", "na"),
                    ControlStatus::ManualReview => ("MANUAL", "manual"),
                };

                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td class=\"{}\">{}</td></tr>\n",
                    html_escape(&control.control_id),
                    html_escape(&control.control_title),
                    status_class,
                    status_str
                ));

                // Show the evidence behind the status. A control carrying only
                // excepted findings passes, but the documented deviations are
                // still listed (in their own style) so the pass is not mistaken
                // for a clean one.
                for finding in &control.control_findings {
                    let row_class = if finding.is_policy_excepted() {
                        "exception"
                    } else {
                        "finding"
                    };
                    html.push_str(&format!(
                        "<tr class=\"{}\"><td></td><td colspan=\"2\">→ [{}] {}</td></tr>\n",
                        row_class,
                        html_escape(&finding.evidence_label()),
                        html_escape(&finding.finding_title)
                    ));
                }
            }

            html.push_str("</tbody>\n</table>\n");
        }

        // HTML Footer
        html.push_str(HTML_FOOTER);

        html
    }
}

/// Escapes HTML special characters.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const HTML_HEADER: &str = r#"<!DOCTYPE html>
  <html lang="en">
  <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Compliance Report</title>
      <style>
          body {
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen,
  Ubuntu, sans-serif;
              max-width: 1200px;
              margin: 0 auto;
              padding: 20px;
              background: #f5f5f5;
              color: #333;
          }
          h1 {
              color: #2c3e50;
              border-bottom: 3px solid #3498db;
              padding-bottom: 10px;
          }
          h2 {
              color: #34495e;
              margin-top: 30px;
          }
          .subtitle {
              color: #5d6d7e;
              font-size: 1.1em;
              font-style: italic;
              margin-top: -10px;
              margin-bottom: 5px;
          }
          .generated {
              color: #7f8c8d;
              font-size: 0.9em;
          }
          .summary {
              background: white;
              border-radius: 8px;
              padding: 20px;
              margin: 20px 0;
              box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          }
          .score {
              font-size: 3em;
              font-weight: bold;
              color: #27ae60;
          }
          .stats span {
              display: inline-block;
              margin-right: 20px;
              padding: 5px 15px;
              border-radius: 4px;
          }
          .stats .pass { background: #d4edda; color: #155724; }
          .stats .fail { background: #f8d7da; color: #721c24; }
          .stats .na { background: #e2e3e5; color: #383d41; }
          table {
              width: 100%;
              border-collapse: collapse;
              background: white;
              border-radius: 8px;
              overflow: hidden;
              box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          }
          th, td {
              padding: 12px 15px;
              text-align: left;
              border-bottom: 1px solid #ddd;
          }
          th {
              background: #3498db;
              color: white;
          }
          tr:hover {
              background: #f8f9fa;
          }
          td.pass { color: #155724; font-weight: bold; }
          td.fail { color: #721c24; font-weight: bold; }
          td.na { color: #383d41; }
          td.manual { color: #856404; }
          tr.finding td {
              background: #fff3cd;
              font-size: 0.9em;
              color: #856404;
          }
          tr.exception td {
              background: #e8eef6;
              font-size: 0.9em;
              color: #2c3e50;
              font-style: italic;
          }
      </style>
  </head>
  <body>
  "#;

const HTML_FOOTER: &str = r#"
  <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color:
  #7f8c8d; font-size: 0.9em;">
      Generated by Linux System Hardener
  </footer>
  </body>
  </html>
  "#;

#[cfg(test)]
mod tests;
