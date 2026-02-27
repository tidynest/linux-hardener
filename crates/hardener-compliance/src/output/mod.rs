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

/// Compares dotted control IDs numerically (e.g. "1.5.2" < "1.10.1").
pub(crate) fn compare_control_ids(id_a: &str, id_b: &str) -> std::cmp::Ordering {
    let parts_a: Vec<u32> = id_a.split('.').filter_map(|s| s.parse().ok()).collect();
    let parts_b: Vec<u32> = id_b.split('.').filter_map(|s| s.parse().ok()).collect();

    for (pa, pb) in parts_a.iter().zip(parts_b.iter()) {
        match pa.cmp(pb) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }

    parts_a.len().cmp(&parts_b.len())
}

/// Sorts grouped sections by their first control ID in numerical order.
pub(crate) fn sort_sections_by_control_id<'a>(
    sections: &mut [(&'a str, Vec<&'a crate::report::ControlResult>)],
) {
    sections.sort_by(|a, b| {
        let id_a = a.1.first().map(|c| c.control_id.as_str()).unwrap_or("");
        let id_b = b.1.first().map(|c| c.control_id.as_str()).unwrap_or("");
        compare_control_ids(id_a, id_b)
    });
}

/// Groups report controls by section name.
pub(crate) fn group_controls_by_section<'a>(
    report: &'a ComplianceReport,
) -> Vec<(&'a str, Vec<&'a crate::report::ControlResult>)> {
    let mut sections: std::collections::BTreeMap<&str, Vec<&'a crate::report::ControlResult>> =
        std::collections::BTreeMap::new();
    for control in &report.report_controls {
        sections
            .entry(control.control_section.as_str())
            .or_default()
            .push(control);
    }
    let mut sorted: Vec<_> = sections.into_iter().collect();
    sort_sections_by_control_id(&mut sorted);
    sorted
}
