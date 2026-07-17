//! Interactive compliance report wizard.
//!
//! Provides a guided CLI experience for generating compliance reports.

use super::report::run_scan;
use crate::cli::OutputFormat as CliOutputFormat;
use anyhow::{Result, anyhow};
use chrono::Local;
use colored::Colorize;
use dialoguer::{Confirm, MultiSelect, Select, theme::ColorfulTheme};
use hardener_common::types::{ComplianceFramework, ComplianceProfile};
use hardener_compliance::{
    JsonFormatter, OutputFormat, ReportConfig, ReportFormatter, ReportGenerator, Scenario,
    TextFormatter,
    output::{CsvFormatter, HtmlFormatter, PdfFormatter},
};
use hardener_core::{LocalExecutor, SystemExecutor};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

/// Wizard state tracking user selections.
#[derive(Debug, Default)]
struct WizardState {
    scenario: Option<Scenario>,
    output_formats: Vec<OutputFormat>,
    output_path: Option<PathBuf>,
}

/// Framework metadata for display.
struct FrameworkInfo {
    framework: ComplianceFramework,
    name: &'static str,
    description: &'static str,
}

const FRAMEWORKS: &[FrameworkInfo] = &[
    FrameworkInfo {
        framework: ComplianceFramework::CIS,
        name: "CIS",
        description: "Center for Internet Security Benchmarks",
    },
    FrameworkInfo {
        framework: ComplianceFramework::STIG,
        name: "STIG",
        description: "DISA Security Technical Implementation Guides",
    },
    FrameworkInfo {
        framework: ComplianceFramework::NIST,
        name: "NIST 800-53",
        description: "US Federal security controls",
    },
    FrameworkInfo {
        framework: ComplianceFramework::PCIDSS,
        name: "PCI-DSS",
        description: "Payment Card Industry Data Security Standard",
    },
    FrameworkInfo {
        framework: ComplianceFramework::HIPAA,
        name: "HIPAA",
        description: "Health Insurance Portability & Accountability Act",
    },
    FrameworkInfo {
        framework: ComplianceFramework::GDPR,
        name: "GDPR",
        description: "EU General Data Protection Regulation (Article 32)",
    },
    FrameworkInfo {
        framework: ComplianceFramework::SOC2,
        name: "SOC 2",
        description: "AICPA Trust Services Criteria",
    },
    FrameworkInfo {
        framework: ComplianceFramework::NIST800171,
        name: "NIST 800-171",
        description: "Protection of Controlled Unclassified Information",
    },
];

/// Scenario metadata for display.
struct ScenarioInfo {
    name: &'static str,
    description: &'static str,
    frameworks: &'static str,
}

const SCENARIOS: &[ScenarioInfo] = &[
    ScenarioInfo {
        name: "Server",
        description: "Production server hardening",
        frameworks: "CIS, STIG",
    },
    ScenarioInfo {
        name: "Workstation",
        description: "Desktop/laptop security",
        frameworks: "CIS",
    },
    ScenarioInfo {
        name: "Government",
        description: "Government compliance",
        frameworks: "STIG, NIST 800-53, NIST 800-171",
    },
    ScenarioInfo {
        name: "Healthcare",
        description: "Healthcare systems",
        frameworks: "HIPAA, NIST 800-53",
    },
    ScenarioInfo {
        name: "Financial",
        description: "Payment processing",
        frameworks: "PCI-DSS, CIS",
    },
    ScenarioInfo {
        name: "GDPR",
        description: "EU data protection",
        frameworks: "GDPR",
    },
    ScenarioInfo {
        name: "All",
        description: "Comprehensive check",
        frameworks: "All frameworks",
    },
    ScenarioInfo {
        name: "Custom",
        description: "Select frameworks manually",
        frameworks: "Your choice",
    },
];

/// Run the interactive report wizard.
pub async fn run(quiet: bool) -> Result<()> {
    if quiet {
        return Err(anyhow!(
            "Interactive wizard cannot run in quiet mode. Remove --quiet flag."
        ));
    }

    // Print welcome banner
    print_welcome();

    // Step 1: Select mode (preset scenario vs custom)
    let state = wizard_flow()?;

    // Step 2: Confirm selections
    if !confirm_selections(&state)? {
        println!("\n{}", "Report generation cancelled.".yellow());
        return Ok(());
    }

    // Step 3: Run scan
    println!("\n{}", "Running security scan...".cyan());
    let executor: Arc<dyn SystemExecutor> = Arc::new(LocalExecutor::new());
    let findings = run_scan(false, executor, &CliOutputFormat::Text).await?;
    println!(
        "{}",
        format!(
            "Found {} total findings across all plugins.",
            findings.len()
        )
        .dimmed()
    );

    // Step 4: Generate reports
    println!("\n{}", "Generating compliance reports...".cyan());

    let scenario = state
        .scenario
        .clone()
        .ok_or_else(|| anyhow!("No scenario selected"))?;

    let config = ReportConfig {
        scenario,
        formats: state.output_formats.clone(),
        output_dir: None,
        profile: ComplianceProfile::default(),
    };

    let generator = ReportGenerator::new(config, hardener_plugins::compliance_coverage());
    let reports = generator.generate(&findings);

    // Step 5: Output reports
    output_reports(&reports, &state)?;

    // Step 6: Show summary
    print_summary(&reports, &state);

    Ok(())
}

fn print_welcome() {
    println!();
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗"
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "║       Linux System Hardener - Report Wizard               ║"
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝"
            .cyan()
            .bold()
    );
    println!();
    println!(
        "{}",
        "This wizard will help you generate a compliance report.".dimmed()
    );
    println!();
}

fn wizard_flow() -> Result<WizardState> {
    let scenario = Some(select_scenario()?);
    let output_formats = select_output_formats()?;
    let output_path = select_output_path()?;

    Ok(WizardState {
        scenario,
        output_formats,
        output_path,
    })
}

fn select_scenario() -> Result<Scenario> {
    println!("{}", "Step 1: Select Compliance Scenario".bold());
    println!(
        "{}",
        "Choose a preset scenario or select frameworks manually.".dimmed()
    );
    println!();

    let theme = ColorfulTheme::default();

    // Build display options
    let options: Vec<String> = SCENARIOS
        .iter()
        .map(|s| format!("{:<12} - {} ({})", s.name, s.description, s.frameworks))
        .collect();

    let selection = Select::with_theme(&theme)
        .with_prompt("Select scenario")
        .items(&options)
        .default(0)
        .interact()?;

    let scenario = match selection {
        0 => Scenario::Server,
        1 => Scenario::Workstation,
        2 => Scenario::Government,
        3 => Scenario::Healthcare,
        4 => Scenario::Financial,
        5 => Scenario::Gdpr,
        6 => Scenario::All,
        7 => loop {
            let frameworks = select_frameworks()?;
            if !frameworks.is_empty() {
                break Scenario::Custom(frameworks);
            }
            println!(
                "{}",
                "At least one framework must be selected. Try again.".yellow()
            );
        },
        _ => Scenario::Server,
    };

    println!();
    Ok(scenario)
}

fn select_frameworks() -> Result<Vec<ComplianceFramework>> {
    println!();
    println!("{}", "Select frameworks to include:".dimmed());

    let theme = ColorfulTheme::default();

    let options: Vec<String> = FRAMEWORKS
        .iter()
        .map(|f| format!("{:<12} - {}", f.name, f.description))
        .collect();

    let selections = MultiSelect::with_theme(&theme)
        .with_prompt("Select frameworks (Space to toggle, Enter to confirm)")
        .items(&options)
        .interact()?;

    let frameworks: Vec<ComplianceFramework> = selections
        .iter()
        .map(|&i| FRAMEWORKS[i].framework)
        .collect();

    Ok(frameworks)
}

fn select_output_formats() -> Result<Vec<OutputFormat>> {
    println!("{}", "Step 2: Select Output Format(s)".bold());
    println!(
        "{}",
        "You can generate multiple formats simultaneously.".dimmed()
    );
    println!();

    let theme = ColorfulTheme::default();

    let options = vec![
        "Text   - Human-readable terminal output",
        "JSON   - Machine-readable for automation",
        "CSV    - Spreadsheet-friendly format",
        "HTML   - Styled web report with summary",
        "PDF    - Portable document for printing/archiving",
    ];

    let defaults = vec![true, false, false, false, false]; // Text selected by default

    let selections = MultiSelect::with_theme(&theme)
        .with_prompt("Select format(s) (Space to toggle, Enter to confirm)")
        .items(&options)
        .defaults(&defaults)
        .interact()?;

    if selections.is_empty() {
        return Err(anyhow!("At least one output format must be selected."));
    }

    let formats: Vec<OutputFormat> = selections
        .iter()
        .map(|&i| match i {
            0 => OutputFormat::Text,
            1 => OutputFormat::Json,
            2 => OutputFormat::Csv,
            3 => OutputFormat::Html,
            4 => OutputFormat::Pdf,
            _ => OutputFormat::Text,
        })
        .collect();

    println!();
    Ok(formats)
}

fn select_output_path() -> Result<Option<PathBuf>> {
    println!("{}", "Step 3: Output Destination".bold());
    println!();

    let theme = ColorfulTheme::default();

    let save_to_file = Confirm::with_theme(&theme)
        .with_prompt("Save report(s) to file?")
        .default(false)
        .interact()?;

    if !save_to_file {
        println!("{}", "Report will be displayed in terminal.".dimmed());
        println!();
        return Ok(None);
    }

    // Get output path
    let input: String = dialoguer::Input::with_theme(&theme)
        .with_prompt("Enter output directory or file path")
        .default("./compliance-report".to_string())
        .interact_text()?;

    println!();
    Ok(Some(PathBuf::from(input)))
}

fn confirm_selections(state: &WizardState) -> Result<bool> {
    println!("{}", "═══════════════════════════════════════".cyan());
    println!("{}", "Review Your Selections".bold());
    println!("{}", "═══════════════════════════════════════".cyan());
    println!();

    // Show scenario
    if let Some(ref scenario) = state.scenario {
        let frameworks = scenario.frameworks();
        let framework_names: Vec<&str> = frameworks.iter().map(|f| f.full_name()).collect();

        println!("  {} {}", "Scenario:".bold(), scenario.name());
        println!("  {} {}", "Frameworks:".bold(), framework_names.join(", "));
    }

    // Show formats
    let format_names: Vec<&str> = state
        .output_formats
        .iter()
        .map(|f| match f {
            OutputFormat::Text => "Text",
            OutputFormat::Json => "JSON",
            OutputFormat::Csv => "CSV",
            OutputFormat::Html => "HTML",
            OutputFormat::Pdf => "PDF",
        })
        .collect();
    println!("  {} {}", "Formats:".bold(), format_names.join(", "));

    // Show output
    match &state.output_path {
        Some(path) => println!("  {} {}", "Output:".bold(), path.display()),
        None => println!("  {} stdout", "Output:".bold()),
    }

    println!();

    let theme = ColorfulTheme::default();
    let confirmed = Confirm::with_theme(&theme)
        .with_prompt("Proceed with report generation?")
        .default(true)
        .interact()?;

    Ok(confirmed)
}

fn output_reports(
    reports: &[hardener_compliance::ComplianceReport],
    state: &WizardState,
) -> Result<()> {
    for format in &state.output_formats {
        let formatted = match format {
            OutputFormat::Text => {
                let formatter = TextFormatter::new();
                formatter.format_all(reports)
            }
            OutputFormat::Json => {
                let formatter = JsonFormatter::pretty();
                formatter.format_all(reports)
            }
            OutputFormat::Csv => {
                let formatter = CsvFormatter::new();
                formatter.format_all(reports)
            }
            OutputFormat::Html => {
                let formatter = HtmlFormatter::new();
                formatter.format_all(reports)
            }
            OutputFormat::Pdf => {
                let formatter = PdfFormatter::new();
                formatter.format_all(reports)
            }
        };

        match &state.output_path {
            Some(base_path) => {
                let path = if state.output_formats.len() == 1 {
                    // Single format - use path as-is or add extension
                    let mut p = base_path.clone();
                    if p.extension().is_none() {
                        p.set_extension(format.extension());
                    }
                    p
                } else {
                    // Multiple formats - add format suffix
                    let stem = base_path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("report");
                    let parent = base_path.parent().unwrap_or(std::path::Path::new("."));
                    parent.join(format!("{}.{}", stem, format.extension()))
                };

                // Create parent directory if needed
                if let Some(parent) = path.parent()
                    && !parent.exists()
                {
                    fs::create_dir_all(parent)?;
                }

                if *format == OutputFormat::Pdf {
                    let bytes = PdfFormatter::new().format_bytes(&reports[0]);
                    fs::write(&path, bytes)?;
                } else {
                    fs::write(&path, &formatted)?;
                }
                println!(
                    "  {} Saved {} report to: {}",
                    "✓".green(),
                    format_name(format),
                    path.display()
                );
            }
            None => {
                // For PDF, generate timestamped file since it can't go to stdout
                if *format == OutputFormat::Pdf {
                    let timestamp = Local::now().format("%Y%m%d-%H%M%S");
                    let filename = format!("compliance-report-{}.pdf", timestamp);
                    let bytes = PdfFormatter::new().format_bytes(&reports[0]);
                    fs::write(&filename, bytes)?;
                    println!("  {} Saved PDF report to: {}", "✓".green(), filename);
                    continue;
                }
                // Print text formats to stdout
                if state.output_formats.len() > 1 {
                    println!(
                        "\n{}\n",
                        format!("═══ {} Report ═══", format_name(format)).cyan()
                    );
                }
                let mut stdout = io::stdout().lock();
                writeln!(stdout, "{}", formatted)?;
            }
        }
    }

    Ok(())
}

fn format_name(format: &OutputFormat) -> &'static str {
    match format {
        OutputFormat::Text => "Text",
        OutputFormat::Json => "JSON",
        OutputFormat::Csv => "CSV",
        OutputFormat::Html => "HTML",
        OutputFormat::Pdf => "PDF",
    }
}

fn print_summary(reports: &[hardener_compliance::ComplianceReport], state: &WizardState) {
    println!();
    println!("{}", "═══════════════════════════════════════".green());
    println!("{}", "Report Generation Complete".green().bold());
    println!("{}", "═══════════════════════════════════════".green());
    println!();

    for report in reports {
        let summary = &report.report_summary;
        let total = summary.summary_total_controls;
        let passing = summary.summary_passing;
        let score = if total > 0 {
            (passing as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        let score_color = if score >= 80.0 {
            score.to_string().green()
        } else if score >= 60.0 {
            score.to_string().yellow()
        } else {
            score.to_string().red()
        };

        println!(
            "  {} {}: {:.1}% ({}/{} controls passing)",
            framework_icon(&report.report_framework),
            framework_display_name(&report.report_framework),
            score_color,
            passing,
            total
        );
    }

    println!();

    if state.output_path.is_some() {
        println!(
            "{}",
            "Reports have been saved to the specified location.".dimmed()
        );
    }
}

fn framework_icon(framework: &ComplianceFramework) -> &'static str {
    match framework {
        ComplianceFramework::CIS => "🛡️",
        ComplianceFramework::STIG => "🏛️",
        ComplianceFramework::NIST => "📋",
        ComplianceFramework::PCIDSS => "💳",
        ComplianceFramework::HIPAA => "🏥",
        ComplianceFramework::GDPR => "🇪🇺",
        ComplianceFramework::ISO27001 => "🌐",
        ComplianceFramework::SOC2 => "🔏",
        ComplianceFramework::NIST800171 => "🗂️",
    }
}

fn framework_display_name(framework: &ComplianceFramework) -> &'static str {
    framework.full_name()
}
