//! Compliance report generation command.

use crate::cli::OutputFormat as CliOutputFormat;
use anyhow::{Result, anyhow};
use chrono::Local;
use hardener_common::types::ComplianceFramework;
use hardener_compliance::{
    JsonFormatter, OutputFormat, ReportConfig, ReportFormatter, ReportGenerator, Scenario,
    TextFormatter,
};
use hardener_core::{Context, Finding, PluginMetadata, executor::SystemExecutor};
use hardener_plugins::create_plugin_registry;
use hardener_scheduler::db::ScanFinding;
use std::{fs, io, io::Write, sync::Arc};

pub async fn run(
    scenario: Option<String>,
    framework: Option<String>,
    report_format: String,
    output: Option<String>,
    cli_format: CliOutputFormat,
    quiet: bool,
    executor: Arc<dyn SystemExecutor>,
) -> Result<()> {
    // Determine scenario/frameworks (shared with `batch report`).
    let scenario = resolve_scenario(framework, scenario, quiet)?;

    // Determine output format
    let output_format = match report_format.to_lowercase().as_str() {
        "json" => OutputFormat::Json,
        "text" | "txt" => OutputFormat::Text,
        "csv" => OutputFormat::Csv,
        "html" => OutputFormat::Html,
        "pdf" => OutputFormat::Pdf,
        _ => {
            return Err(anyhow!(
                "Unsupported format '{}'. Use 'TEXT', 'JSON', 'CSV', 'HTML' or 'PDF'.",
                report_format
            ));
        }
    };

    // Build config
    let config = ReportConfig {
        scenario,
        formats: vec![output_format],
        output_dir: None,
    };

    if !quiet {
        eprintln!("Running security scan...");
    }

    // Run scan to get findings
    let findings = run_scan(quiet, executor, &cli_format).await?;

    if !quiet {
        eprintln!("Generating compliance report...");
    }

    // Generate reports. The coverage set is what the plugins actually assess —
    // it tells the generator which controls may report Pass/Fail vs ManualReview.
    let generator = ReportGenerator::new(config, hardener_plugins::compliance_coverage());
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
        OutputFormat::Csv => {
            let formatter = hardener_compliance::output::CsvFormatter::new();
            formatter.format_all(&reports)
        }
        OutputFormat::Html => {
            let formatter = hardener_compliance::output::HtmlFormatter::new();
            formatter.format_all(&reports)
        }
        OutputFormat::Pdf => {
            let formatter = hardener_compliance::output::PdfFormatter::new();
            formatter.format_all(&reports)
        }
    };

    // Output result
    if let Some(path) = output {
        // Use provided path, adding extension if missing
        let final_path = if std::path::Path::new(&path).extension().is_none() {
            format!("{}.{}", path, output_format.extension())
        } else {
            path
        };

        if output_format == OutputFormat::Pdf {
            // PDF is binary - convert back to bytes
            let bytes = hardener_compliance::output::PdfFormatter::new().format_bytes(&reports[0]);
            fs::write(&final_path, bytes)?;
        } else {
            fs::write(&final_path, &formatted)?;
        }
        if !quiet {
            eprintln!("Report saved to: {}", final_path);
        }
    } else if output_format == OutputFormat::Pdf {
        // PDF requires file output - generate timestamped filename
        let timestamp = Local::now().format("%Y%m%d-%H%M%S");
        let filename = format!("compliance-report-{}.pdf", timestamp);

        let bytes = hardener_compliance::output::PdfFormatter::new().format_bytes(&reports[0]);
        fs::write(&filename, bytes)?;
        if !quiet {
            eprintln!("Report saved to: {}", filename);
        }
    } else {
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "{}", formatted)?;
    }

    Ok(())
}

/// Scans every plugin and returns findings grouped by their source plugin.
///
/// Keeping the `(PluginMetadata, Vec<Finding>)` pairs preserves `plugin_id`,
/// which history persistence needs. `run_scan` flattens this for callers that
/// only want the findings.
pub async fn scan_grouped(
    quiet: bool,
    executor: Arc<dyn SystemExecutor>,
    cli_format: &CliOutputFormat,
) -> Result<Vec<(PluginMetadata, Vec<Finding>)>> {
    let registry = create_plugin_registry();
    let ctx = Context::with_executor(executor);

    let plugins = registry.list()?;
    let mut grouped = Vec::new();
    let show_progress = !quiet && *cli_format == CliOutputFormat::Text;

    for metadata in &plugins {
        if show_progress {
            eprint!("  Scanning {}... ", metadata.plugin_name);
        }
        if let Ok(Some(plugin)) = registry.get(&metadata.plugin_id) {
            match plugin.scan(&ctx).await {
                Ok(result) => {
                    let count = result.scan_findings.len();
                    grouped.push((metadata.clone(), result.scan_findings));
                    if show_progress {
                        eprintln!("{} finding(s)", count);
                    }
                }
                Err(e) => {
                    if show_progress {
                        eprintln!("error: {}", e);
                    }
                }
            }
        }
    }

    Ok(grouped)
}

/// Scans every plugin and returns all findings, flattened across plugins.
pub async fn run_scan(
    quiet: bool,
    executor: Arc<dyn SystemExecutor>,
    cli_format: &CliOutputFormat,
) -> Result<Vec<Finding>> {
    Ok(scan_grouped(quiet, executor, cli_format)
        .await?
        .into_iter()
        .flat_map(|(_, findings)| findings)
        .collect())
}

/// Converts a core `Finding` + plugin metadata into a scheduler `ScanFinding`.
///
/// Shared by the single-host `scan` and multi-host `batch` persistence paths.
pub(crate) fn finding_to_scan_finding(meta: &PluginMetadata, finding: &Finding) -> ScanFinding {
    ScanFinding {
        plugin_id: meta.plugin_id.to_string(),
        finding_id: finding.finding_id.clone(),
        severity: format!("{:?}", finding.finding_severity),
        title: finding.finding_title.clone(),
        description: Some(finding.finding_description.clone()),
        current_value: Some(finding.finding_current_value.clone()),
        recommended_value: Some(finding.finding_recommended_value.clone()),
        category: Some(format!("{:?}", finding.finding_category)),
        compliance_mappings: if finding.finding_compliance.is_empty() {
            None
        } else {
            Some(
                finding
                    .finding_compliance
                    .iter()
                    .map(|c| format!("{} {}", c.compliance_framework, c.compliance_control_id))
                    .collect(),
            )
        },
    }
}

/// Resolves the scenario to assess from the `--framework`/`--scenario` flags,
/// defaulting to `server` (CIS + STIG) when neither is given. Shared by the
/// single-host `report` and multi-host `batch report` commands so the two can
/// never disagree on what a framework name means.
pub(crate) fn resolve_scenario(
    framework: Option<String>,
    scenario: Option<String>,
    quiet: bool,
) -> Result<Scenario> {
    if let Some(fw) = framework {
        Ok(Scenario::Custom(vec![parse_framework(&fw)?]))
    } else if let Some(sc) = scenario {
        parse_scenario(&sc)
    } else {
        if !quiet {
            eprintln!("No scenario specified, using 'server' (CIS + STIG)");
            eprintln!(
                "Use --scenario or --framework to specify. Run 'hardener report --help' for options.\n"
            );
        }
        Ok(Scenario::Server)
    }
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
            "Unknown scenario '{}'. Valid options: server, workstation, government, healthcare, financial, gdpr, all",
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
            "Unknown framework '{}'. Valid options: cis, stig, nist, pcidss, hipaa, gdpr, iso27001",
            s
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hardener_core::MockExecutor;
    use std::sync::Arc;

    #[tokio::test]
    async fn scan_grouped_keeps_plugin_grouping_and_run_scan_flattens() {
        let exec = Arc::new(MockExecutor::new());
        let grouped = scan_grouped(true, exec.clone(), &CliOutputFormat::Json)
            .await
            .unwrap();
        // Every group carries its plugin metadata (so plugin_id is preserved).
        for (meta, _findings) in &grouped {
            assert!(!meta.plugin_id.as_str().is_empty(), "group has a plugin id");
        }
        // run_scan returns the same findings, flattened.
        let flat = run_scan(true, exec, &CliOutputFormat::Json).await.unwrap();
        let grouped_total: usize = grouped.iter().map(|(_, f)| f.len()).sum();
        assert_eq!(flat.len(), grouped_total, "run_scan flattens scan_grouped");
    }
}
