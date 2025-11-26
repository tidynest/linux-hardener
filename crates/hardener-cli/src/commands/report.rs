//! Compliance report generation command.

use anyhow::{anyhow, Result};
use hardener_common::types::ComplianceFramework;
use hardener_compliance::{
    JsonFormatter, OutputFormat, ReportConfig, ReportFormatter, ReportGenerator,
    Scenario, TextFormatter,
};
use hardener_core::{Context, PluginRegistry};
use hardener_plugins::*;
use std::fs;
use std::io::{self, Write};

use crate::cli::OutputFormat as CliOutputFormat;

pub async fn run(
    scenario: Option<String>,
    framework: Option<String>,
    report_format: String,
    output: Option<String>,
    _cli_format: CliOutputFormat,
    quiet: bool,
) -> Result<()> {
    // Determine scenario/frameworks
    let scenario = if let Some(fw) = framework {
        let framework = parse_framework(&fw)?;
        Scenario::Custom(vec![framework])
    } else if let Some(sc) = scenario {
        parse_scenario(&sc)?
    } else {
        // Interactive mode - for now default to Server
        if !quiet {
            println!("No scenario specified, using 'server' (CIS + STIG)");
            println!("Use --scenario or --framework to specify. Run 'hardener
  report --help' for options.\n");
        }
        Scenario::Server
    };

    // Determine output format
    let output_format = match report_format.to_lowercase().as_str() {
        "json" => OutputFormat::Json,
        "text" | "txt" => OutputFormat::Text,
        _ => {
            return Err(anyhow!(
                  "Unsupported format '{}'. Use 'text' or 'json'.",
                  report_format
              ))
        }
    };

    // Build config
    let config = ReportConfig {
        scenario,
        formats: vec![output_format],
        output_dir: None,
    };

    if !quiet {
        println!("Running security scan...");
    }

    // Run scan to get findings
    let findings = run_scan(quiet)?;

    if !quiet {
        println!("Generating compliance report...\n");
    }

    // Generate reports
    let generator = ReportGenerator::new(config);
    let reports = generator.generate(&findings);

    // Format output
    let formatted = match output_format {
        OutputFormat::Text => {
            let formatter = TextFormatter::new();
            formatter.format_all(&reports)
        }
        OutputFormat::Json => {
            let formatter = JsonFormatter::pretty();
            formatter.format_all(&reports)
        }
        _ => {
            let formatter = TextFormatter::new();
            formatter.format_all(&reports)
        }
    };

    // Output result
    if let Some(path) = output {
        fs::write(&path, &formatted)?;
        if !quiet {
            println!("Report saved to: {}", path);
        }
    } else {
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "{}", formatted)?;
    }

    Ok(())
}

fn run_scan(quiet: bool) -> Result<Vec<hardener_core::plugin::Finding>> {
    let registry = create_plugin_registry();
    let ctx = Context::new();

    let plugins = registry.list()?;
    let mut all_findings = Vec::new();

    for metadata in &plugins {
        if !quiet {
            eprint!("  Scanning {}... ", metadata.plugin_name);
        }

        if let Ok(Some(plugin)) = registry.get(&metadata.plugin_id) {
            match plugin.scan(&ctx) {
                Ok(result) => {
                    let count = result.scan_findings.len();
                    all_findings.extend(result.scan_findings);
                    if !quiet {
                        eprintln!("{} finding(s)", count);
                    }
                }
                Err(e) => {
                    if !quiet {
                        eprintln!("error: {}", e);
                    }
                }
            }
        }
    }

    Ok(all_findings)
}

fn create_plugin_registry() -> PluginRegistry {
    let registry = PluginRegistry::new();
    let _ = registry.register(Box::new(AuditHardeningPlugin::new()));
    let _ = registry.register(Box::new(FirewallHardeningPlugin::new()));
    let _ = registry.register(Box::new(KernelHardeningPlugin::new()));
    let _ = registry.register(Box::new(MacHardeningPlugin::new()));
    let _ = registry.register(Box::new(PamHardeningPlugin::new()));
    let _ = registry.register(Box::new(PermissionsHardeningPlugin::new()));
    let _ = registry.register(Box::new(ServicesHardeningPlugin::new()));
    let _ = registry.register(Box::new(SshHardeningPlugin::new()));
    registry
}

fn parse_scenario(s: &str) -> Result<Scenario> {
    match s.to_lowercase().as_str() {
        "server" => Ok(Scenario::Server),
        "workstation" => Ok(Scenario::Workstation),
        "government" | "gov" => Ok(Scenario::Government),
        "healthcare" | "health" => Ok(Scenario::Healthcare),
        "financial" | "finance" => Ok(Scenario::Financial),
        "gdpr" => Ok(Scenario::Gdpr),
        "all" => Ok(Scenario::All),
        _ => Err(anyhow!(
              "Unknown scenario '{}'. Valid options: server, workstation,
  government, healthcare, financial, gdpr, all",
              s
          )),
    }
}

fn parse_framework(s: &str) -> Result<ComplianceFramework> {
    match s.to_lowercase().as_str() {
        "cis" => Ok(ComplianceFramework::CIS),
        "stig" => Ok(ComplianceFramework::STIG),
        "nist" => Ok(ComplianceFramework::NIST),
        "pcidss" | "pci-dss" | "pci" => Ok(ComplianceFramework::PCIDSS),
        "hipaa" => Ok(ComplianceFramework::HIPAA),
        "gdpr" => Ok(ComplianceFramework::GDPR),
        "iso27001" | "iso" => Ok(ComplianceFramework::ISO27001),
        _ => Err(anyhow!(
              "Unknown framework '{}'. Valid options: cis, stig, nist, pcidss,
  hipaa, gdpr, iso27001",
              s
          )),
    }
}
