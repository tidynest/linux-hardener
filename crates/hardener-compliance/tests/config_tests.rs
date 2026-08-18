use hardener_common::types::ComplianceFramework;
use hardener_compliance::{OutputFormat, ReportConfig, Scenario};

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
    assert!(frameworks.contains(&ComplianceFramework::NIST800171));
    assert!(frameworks.contains(&ComplianceFramework::FedRAMP));
    assert_eq!(frameworks.len(), 4);
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

/// `Scenario::All` is the catalogue itself, so this cannot fail against the
/// current implementation. It is a guard against a future edit re-hardcoding
/// the list: a literal drifts silently from `ComplianceFramework::ALL`, and
/// that is precisely how ISO 27001 came to be missing from a scenario named
/// "All Frameworks" while nine `contains` assertions stayed green. Equality
/// rather than membership, so a framework added to `ALL` and not reaching
/// `All` is caught by the same line.
#[test]
fn test_scenario_all_frameworks() {
    let scenario = Scenario::All;
    assert_eq!(scenario.frameworks(), ComplianceFramework::ALL.to_vec());
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
