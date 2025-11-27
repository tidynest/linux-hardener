//! Report output formatters.
//!
//! Provides formatters to convert compliance reports to various output formats.

pub mod csv;
pub mod html;
pub mod json;
pub mod pdf;
pub mod text;

pub use csv::CsvFormatter;
pub use html::HtmlFormatter;
pub use json::JsonFormatter;
pub use pdf::PdfFormatter;
pub use text::TextFormatter;

use crate::report::ComplianceReport;

/// Trait for formatting compliance reports.
pub trait ReportFormatter {
    /// Formats a single compliance report.
    fn format(&self, report: &ComplianceReport) -> String;

    /// Formats multiple compliance reports.
    fn format_all(&self, reports: &[ComplianceReport]) -> String {
        reports
            .iter()
            .map(|r| self.format(r))
            .collect::<Vec<_>>()
            .join("\n\n")
    }
}
