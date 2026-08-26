//! Report configuration page.
//!
//! Defines scenarios, output formats, and report configuration.

use clap::ValueEnum;
use hardener_common::types::{ComplianceFramework, ComplianceProfile};
use std::path::PathBuf;

/// Pre-defined compliance scenarios for common use cases.
#[derive(Clone, Debug)]
pub enum Scenario {
    /// Production server hardening (CIS Server, STIG).
    Server,
    /// Desktop/laptop security (CIS Workstation).
    Workstation,
    /// Government compliance (STIG, NIST 800-53, NIST SP 800-171, FedRAMP).
    Government,
    /// Healthcare systems (HIPAA, NIST).
    Healthcare,
    /// Payment processing (PCI-DSS, CIS).
    Financial,
    /// EU data protection (GDPR Art, 32).
    Gdpr,
    /// Comprehensive check against all frameworks.
    All,
    /// User-selected frameworks.
    Custom(Vec<ComplianceFramework>),
}

impl Scenario {
    /// Returns the compliance frameworks included in this scenario.
    pub fn frameworks(&self) -> Vec<ComplianceFramework> {
        match self {
            Scenario::Server => vec![ComplianceFramework::CIS, ComplianceFramework::STIG],
            Scenario::Workstation => vec![ComplianceFramework::CIS],
            Scenario::Government => vec![
                ComplianceFramework::STIG,
                ComplianceFramework::NIST,
                ComplianceFramework::NIST800171,
                ComplianceFramework::FedRAMP,
            ],
            Scenario::Healthcare => vec![ComplianceFramework::HIPAA, ComplianceFramework::NIST],
            Scenario::Financial => vec![ComplianceFramework::PCIDSS, ComplianceFramework::CIS],
            Scenario::Gdpr => vec![ComplianceFramework::GDPR],
            // The catalogue itself, so a framework added to
            // `ComplianceFramework::ALL` reaches `--scenario all` without a
            // second edit. This was a hand-written list of nine until
            // 2026-08-18 and had drifted: ISO 27001 was missing while
            // `name()` returned "All Frameworks", so the scenario rendered
            // nine reports and said nothing about the tenth. A literal here
            // is a second copy of `ALL` and drifted exactly as a second copy
            // does.
            //
            // Deliberately NOT the same decision as `FLEET_FRAMEWORKS` in
            // `src-tauri/src/commands.rs`, which still omits ISO 27001: that
            // one adds a column to the fleet table, and ISO 27001's ceiling
            // is a measured 11.8 per cent, so the column can never leave the
            // critical band however well a host is hardened. A report the
            // operator asked for by name is not a column they did not.
            Scenario::All => ComplianceFramework::ALL.to_vec(),
            Scenario::Custom(frameworks) => frameworks.clone(),
        }
    }

    /// Returns a human-readable name for the scenario.
    pub fn name(&self) -> &'static str {
        match self {
            Scenario::Server => "Server",
            Scenario::Workstation => "Workstation",
            Scenario::Government => "Government",
            Scenario::Healthcare => "Healthcare",
            Scenario::Financial => "Financial",
            Scenario::Gdpr => "Gdpr",
            Scenario::All => "All Frameworks",
            Scenario::Custom(_) => "Custom",
        }
    }
}

/// Output format for compliance reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    /// Plain text format for terminal viewing.
    Text,
    /// JSON format for API/automation integration.
    Json,
    /// CSV format for spreadsheet analysis.
    Csv,
    /// HTML format for web viewing.
    Html,
    /// PDF format for printing/archiving.
    Pdf,
}

impl OutputFormat {
    /// Returns the file extension for this format.
    pub fn extension(&self) -> &'static str {
        match self {
            OutputFormat::Text => "txt",
            OutputFormat::Json => "json",
            OutputFormat::Csv => "csv",
            OutputFormat::Html => "html",
            OutputFormat::Pdf => "pdf",
        }
    }

    /// The format a file extension names, if it names one this tool renders.
    ///
    /// The inverse of [`extension`](Self::extension), and deliberately a closed
    /// list: `Path::extension` returns whatever follows the last dot of a file
    /// name, which is not the same question as "what document is this". A dated
    /// name like `report.2026.08.03` has extension `03` and `session-1.5.1` has
    /// `1`, and neither operator was asking for a document at all. Only a name
    /// that really does name one of these formats carries an expectation worth
    /// acting on. `htm` is accepted beside `html` because they are one document
    /// type; the comparison is case-insensitive.
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension.to_ascii_lowercase().as_str() {
            "txt" => Some(OutputFormat::Text),
            "json" => Some(OutputFormat::Json),
            "csv" => Some(OutputFormat::Csv),
            "htm" | "html" => Some(OutputFormat::Html),
            "pdf" => Some(OutputFormat::Pdf),
            _ => None,
        }
    }

    /// The document `path`'s extension names, when it names one this crate
    /// renders and it is not `self`. `None` means the path raises no objection.
    ///
    /// The decision behind every "that extension contradicts the format you
    /// chose" refusal, in one place, because the refusals themselves cannot be:
    /// the CLI names `--output` in its message and the desktop has no flag to
    /// name. Sharing the sentence would put a flag name in front of a desktop
    /// operator; sharing nothing let the desktop write PDF bytes into a file
    /// the CLI refuses to open, which is what it did until 2026-08-26.
    ///
    /// A path with no extension, or one naming no format this crate renders,
    /// is not a contradiction. `report.2026.08.03` has extension `03` and the
    /// operator was not asking for a document at all, which is the reason
    /// [`from_extension`](Self::from_extension) is a closed list.
    pub fn contradicted_by(self, path: &std::path::Path) -> Option<Self> {
        path.extension()
            .and_then(|e| e.to_str())
            .and_then(Self::from_extension)
            .filter(|named| *named != self)
    }
}

/// Configuration for report generation.
#[derive(Clone, Debug)]
pub struct ReportConfig {
    /// The scenario determining which frameworks to check.
    pub scenario: Scenario,
    /// Output formats to generate.
    pub formats: Vec<OutputFormat>,
    /// Optional output directory for saving reports.
    pub output_dir: Option<PathBuf>,
    /// OS-specific profile selecting which control identifiers reports render.
    pub profile: ComplianceProfile,
}

impl Default for ReportConfig {
    fn default() -> ReportConfig {
        ReportConfig {
            scenario: Scenario::Server,
            formats: vec![OutputFormat::Text],
            output_dir: None,
            profile: ComplianceProfile::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The extension-to-format mapping is the shared judgement behind two
    /// commands' `--output` refusals, and it lived in neither's tests: a
    /// one-word edit here silently changed what `history export` accepts and
    /// what `report --output` refuses, with nothing red.
    #[test]
    fn every_format_is_found_by_the_extension_it_writes() {
        for format in [
            OutputFormat::Text,
            OutputFormat::Json,
            OutputFormat::Csv,
            OutputFormat::Html,
            OutputFormat::Pdf,
        ] {
            assert_eq!(
                OutputFormat::from_extension(format.extension()),
                Some(format),
                "{format:?} must be recoverable from the extension it writes, or \
                 a path this tool produced would be refused by the check that \
                 reads it back"
            );
        }
        assert_eq!(
            OutputFormat::from_extension("HTM"),
            Some(OutputFormat::Html),
            "htm is html, and the comparison ignores case"
        );
    }

    /// The control against the list being widened. `Path::extension` answers
    /// "what follows the last dot", so these are what a dated or versioned file
    /// name yields, and treating them as documents would refuse working
    /// invocations that asked for no document at all.
    #[test]
    fn a_suffix_that_names_no_document_maps_to_nothing() {
        for suffix in ["03", "1", "gz", "md", "xml", "", "tar"] {
            assert_eq!(
                OutputFormat::from_extension(suffix),
                None,
                "'{suffix}' names no document this tool renders"
            );
        }
        assert_eq!(
            OutputFormat::from_extension("json"),
            Some(OutputFormat::Json),
            "and the list has not been emptied, which would make the control vacuous"
        );
    }
}
