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
            // Nine of the ten frameworks in `ComplianceFramework::ALL`.
            // **ISO 27001 is omitted, and `name()` still calls this "All
            // Frameworks"**, so `hardener report --scenario all` renders nine
            // and says nothing about the tenth. Measured against the release
            // binary 2026-08-18: nine reports, no ISO 27001 anywhere in the
            // output. `tests/config_tests.rs` asserts `len() == 9`, so the
            // suite pins the omission rather than catching it.
            //
            // Whether that is right is a product decision, not an oversight to
            // patch here: ISO 27001 is one of only two curated catalogues
            // (CIS being the other), so it is among the better-evidenced
            // frameworks rather than a thin derived one. Adding it changes
            // every `--scenario all` report. `FLEET_FRAMEWORKS` in
            // `src-tauri/src/commands.rs` omits the same framework and says so
            // in one line; this list said nothing at all until now.
            Scenario::All => vec![
                ComplianceFramework::CIS,
                ComplianceFramework::STIG,
                ComplianceFramework::NIST,
                ComplianceFramework::PCIDSS,
                ComplianceFramework::HIPAA,
                ComplianceFramework::GDPR,
                ComplianceFramework::SOC2,
                ComplianceFramework::NIST800171,
                ComplianceFramework::FedRAMP,
            ],
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
