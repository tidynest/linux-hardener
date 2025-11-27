//! Report configuration page.
//!
//! Defines scenarios, output formats, and report configuration.

use clap::ValueEnum;
use hardener_common::types::ComplianceFramework;
use std::path::PathBuf;

/// Pre-defined compliance scenarios for common use cases.
#[derive(Clone, Debug)]
pub enum Scenario {
    /// Production server hardening (CIS Server, STIG).
    Server,
    /// Desktop/laptop security (CIS Workstation).
    Workstation,
    /// Government compliance (STIG, NIST 800-53).
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
            Scenario::Government => vec![ComplianceFramework::STIG, ComplianceFramework::NIST],
            Scenario::Healthcare => vec![ComplianceFramework::HIPAA, ComplianceFramework::NIST],
            Scenario::Financial => vec![ComplianceFramework::PCIDSS, ComplianceFramework::CIS],
            Scenario::Gdpr => vec![ComplianceFramework::GDPR],
            Scenario::All => vec![
                ComplianceFramework::CIS,
                ComplianceFramework::STIG,
                ComplianceFramework::NIST,
                ComplianceFramework::PCIDSS,
                ComplianceFramework::HIPAA,
                ComplianceFramework::GDPR,
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
}

impl Default for ReportConfig {
    fn default() -> ReportConfig {
        ReportConfig {
            scenario: Scenario::Server,
            formats: vec![OutputFormat::Text],
            output_dir: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scenario_server_frameworks() {
        let scenario = Scenario::Server;
        let frameworks = scenario.frameworks();
        assert!(frameworks.contains(&ComplianceFramework::CIS));
        assert!(frameworks.contains(&ComplianceFramework::STIG));
        assert_eq!(frameworks.len(), 2);
    }

    #[test]
    fn test_scenario_workstation_frameworks() {
        let scenario = Scenario::Workstation;
        let frameworks = scenario.frameworks();
        assert!(frameworks.contains(&ComplianceFramework::CIS));
        assert_eq!(frameworks.len(), 1);
    }

    #[test]
    fn test_scenario_government_frameworks() {
        let scenario = Scenario::Government;
        let frameworks = scenario.frameworks();
        assert!(frameworks.contains(&ComplianceFramework::STIG));
        assert!(frameworks.contains(&ComplianceFramework::NIST));
        assert_eq!(frameworks.len(), 2);
    }

    #[test]
    fn test_scenario_healthcare_frameworks() {
        let scenario = Scenario::Healthcare;
        let frameworks = scenario.frameworks();
        assert!(frameworks.contains(&ComplianceFramework::HIPAA));
        assert!(frameworks.contains(&ComplianceFramework::NIST));
        assert_eq!(frameworks.len(), 2);
    }

    #[test]
    fn test_scenario_financial_frameworks() {
        let scenario = Scenario::Financial;
        let frameworks = scenario.frameworks();
        assert!(frameworks.contains(&ComplianceFramework::PCIDSS));
        assert!(frameworks.contains(&ComplianceFramework::CIS));
        assert_eq!(frameworks.len(), 2);
    }

    #[test]
    fn test_scenario_gdpr_frameworks() {
        let scenario = Scenario::Gdpr;
        let frameworks = scenario.frameworks();
        assert!(frameworks.contains(&ComplianceFramework::GDPR));
        assert_eq!(frameworks.len(), 1);
    }

    #[test]
    fn test_scenario_all_frameworks() {
        let scenario = Scenario::All;
        let frameworks = scenario.frameworks();
        assert_eq!(frameworks.len(), 6);
        assert!(frameworks.contains(&ComplianceFramework::CIS));
        assert!(frameworks.contains(&ComplianceFramework::STIG));
        assert!(frameworks.contains(&ComplianceFramework::NIST));
        assert!(frameworks.contains(&ComplianceFramework::PCIDSS));
        assert!(frameworks.contains(&ComplianceFramework::HIPAA));
        assert!(frameworks.contains(&ComplianceFramework::GDPR));
    }

    #[test]
    fn test_scenario_custom_frameworks() {
        let custom = vec![ComplianceFramework::CIS, ComplianceFramework::GDPR];
        let scenario = Scenario::Custom(custom.clone());
        let frameworks = scenario.frameworks();
        assert_eq!(frameworks, custom);
    }

    #[test]
    fn test_scenario_names() {
        assert_eq!(Scenario::Server.name(), "Server");
        assert_eq!(Scenario::Workstation.name(), "Workstation");
        assert_eq!(Scenario::Government.name(), "Government");
        assert_eq!(Scenario::Healthcare.name(), "Healthcare");
        assert_eq!(Scenario::Financial.name(), "Financial");
        assert_eq!(Scenario::Gdpr.name(), "Gdpr");
        assert_eq!(Scenario::All.name(), "All Frameworks");
        assert_eq!(Scenario::Custom(vec![]).name(), "Custom");
    }

    #[test]
    fn test_output_format_extensions() {
        assert_eq!(OutputFormat::Text.extension(), "txt");
        assert_eq!(OutputFormat::Json.extension(), "json");
        assert_eq!(OutputFormat::Csv.extension(), "csv");
        assert_eq!(OutputFormat::Html.extension(), "html");
        assert_eq!(OutputFormat::Pdf.extension(), "pdf");
    }

    #[test]
    fn test_report_config_default() {
        let config = ReportConfig::default();
        assert!(matches!(config.scenario, Scenario::Server));
        assert_eq!(config.formats, vec![OutputFormat::Text]);
        assert!(config.output_dir.is_none());
    }
}
