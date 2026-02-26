//! Report output formatters.
//!
//! Provides formatters to convert compliance reports to various output formats.

pub mod csv;
pub mod html;
pub mod json;
#[cfg(feature = "pdf")]
pub mod pdf;
pub mod text;

pub use csv::CsvFormatter;
pub use html::HtmlFormatter;
pub use json::JsonFormatter;
#[cfg(feature = "pdf")]
pub use pdf::PdfFormatter;
pub use text::TextFormatter;

use crate::report::ComplianceReport;

/// Trait for formatting compliance reports.
pub trait ReportFormatter {
    /// Formats a single compliance report.
    fn format(&self, report: &ComplianceReport) -> String;

    /// Formats a report as raw bytes. Defaults to UTF-8 encoding of `format()`.
    /// Override for binary formats (e.g. PDF).
    fn format_bytes(&self, report: &ComplianceReport) -> Vec<u8> {
        self.format(report).into_bytes()
    }

    /// Formats multiple compliance reports.
    fn format_all(&self, reports: &[ComplianceReport]) -> String {
        reports
            .iter()
            .map(|r| self.format(r))
            .collect::<Vec<_>>()
            .join("\n\n")
    }
}
