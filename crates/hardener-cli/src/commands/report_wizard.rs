//! Interactive compliance report wizard.
//!
//! Provides a guided CLI experience for generating compliance reports.

use super::report::run_scan_for_report;
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
use hardener_core::{ConfigLoader, SystemExecutor};
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
        framework: ComplianceFramework::ISO27001,
        name: "ISO 27001",
        description: "ISO/IEC 27001:2022 Annex A information security controls",
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
    FrameworkInfo {
        framework: ComplianceFramework::FedRAMP,
        name: "FedRAMP",
        description: "FedRAMP Moderate baseline (Rev 5)",
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
        frameworks: "STIG, NIST 800-53, NIST 800-171, FedRAMP",
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
///
/// Takes the executor the caller already built rather than making its own, so
/// `--ssh` reaches this surface as it reaches every other. A wizard that
/// scanned the controller after the CLI had announced a connection to a remote
/// would hand back a compliance report about the wrong machine, and nothing in
/// the report names a host to give it away.
///
/// `profile` is `--profile` as the operator gave it, and it is parsed here,
/// before the first prompt: `hardener report` honours the flag and falls back
/// to detection, so a wizard that detected regardless would score the same host
/// differently from the surface beside it, and a profile name that cannot be
/// parsed should be refused before the operator has answered five questions.
pub async fn run(
    quiet: bool,
    executor: Arc<dyn SystemExecutor>,
    profile: Option<String>,
) -> Result<()> {
    if quiet {
        return Err(anyhow!(
            "Interactive wizard cannot run in quiet mode. Remove --quiet flag."
        ));
    }

    let profile_override = profile
        .as_deref()
        .map(super::report::parse_profile)
        .transpose()?;

    // Print welcome banner
    print_welcome();

    // Step 1: Select mode (preset scenario vs custom)
    let state = wizard_flow()?;

    // Step 2: Confirm selections
    if !confirm_selections(&state)? {
        eprintln!("\n{}", "Report generation cancelled.".yellow());
        return Ok(());
    }

    // Step 3: Run scan
    eprintln!("\n{}", "Running security scan...".cyan());
    // The wizard must still honour the operator's config: scoring the same
    // host differently from `hardener report` would make one of the two
    // surfaces wrong. Invalid config is a hard error here too (report.rs
    // ~76-80).
    //
    // **It honours the default sources only.** `--config` is a global flag, so
    // clap accepts `hardener --config X report --interactive`, but `main.rs`
    // never passes `cli.config` down this path and `ConfigLoader::new()` below
    // takes no named file. A path typed there is silently dropped, and the
    // wizard scores against the system and user config instead. That is the
    // documented behaviour (configuration.md and cli.md both list this command
    // among those that accept the flag without acting on it), not an oversight
    // to fix here, but the comment above read as though the operator's own
    // `--config` reached this call, and it does not.
    let hardener_config = ConfigLoader::new()
        .load()
        .map_err(|e| anyhow!("Config error: {}", e))?;
    let (results, skipped) = run_scan_for_report(
        false,
        executor.clone(),
        &CliOutputFormat::Text,
        &hardener_config,
    )
    .await?;
    // The wizard prints a count and lists what could not be checked, which is
    // the flattened view. The generator below still takes the raw results and
    // flattens them itself, so this is a display copy and never a score input.
    let (findings, unchecked) = hardener_compliance::scan_evidence::flatten(
        &hardener_plugins::plugin_inventory(),
        &results,
        &skipped,
    );
    eprintln!(
        "{}",
        format!(
            "Found {} total findings across all plugins.",
            findings.len()
        )
        .dimmed()
    );

    // Step 4: Generate reports
    eprintln!("\n{}", "Generating compliance reports...".cyan());

    let config = wizard_report_config(&state, executor.as_ref(), profile_override).await?;

    // Said on the page, because the scoring depends on it and until now no
    // wizard output named it at all: a report scored against the RHEL 10
    // identifiers looks exactly like one scored against the generic set.
    eprintln!("{}", format!("Profile: {}", config.profile).dimmed());

    let generator = ReportGenerator::new(
        config,
        hardener_plugins::plugin_inventory(),
        hardener_config.compliance.clone(),
    );
    let reports = generator.generate(&results, &skipped);

    // Step 5: Output reports
    output_reports(&reports, &state)?;

    // Step 6: Show summary
    print_summary(&reports, &state, &unchecked);

    Ok(())
}

/// The report configuration one wizard run produces.
///
/// The profile is resolved from the scanned host through the executor, exactly
/// as `hardener report` resolves it. It used to be `ComplianceProfile::default()`,
/// which is `Generic`, so the wizard scored a RHEL 10 host against the generic
/// identifier set while the non-interactive command scored the same host
/// against the RHEL 10 one. Two surfaces disagreeing about one host means one
/// of them is wrong, and the operator has nothing on the page to tell them
/// which.
///
/// Split out because the wizard's own flow is interactive and cannot be
/// driven from a test, while this, the part of it that has an answer worth
/// asserting, can.
async fn wizard_report_config(
    state: &WizardState,
    executor: &dyn SystemExecutor,
    profile_override: Option<ComplianceProfile>,
) -> Result<ReportConfig> {
    let scenario = state
        .scenario
        .clone()
        .ok_or_else(|| anyhow!("No scenario selected"))?;

    let profile = match profile_override {
        Some(profile) => profile,
        None => super::batch::detect_host_profile(executor).await,
    };

    Ok(ReportConfig {
        scenario,
        formats: state.output_formats.clone(),
        output_dir: None,
        profile,
    })
}

/// The wizard's opening banner.
fn print_welcome() {
    eprintln!();
    eprintln!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗"
            .cyan()
            .bold()
    );
    eprintln!(
        "{}",
        "║       Linux Hardener - Report Wizard               ║"
            .cyan()
            .bold()
    );
    eprintln!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝"
            .cyan()
            .bold()
    );
    eprintln!();
    eprintln!(
        "{}",
        "This wizard will help you generate a compliance report.".dimmed()
    );
    eprintln!();
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
    eprintln!("{}", "Step 1: Select Compliance Scenario".bold());
    eprintln!(
        "{}",
        "Choose a preset scenario or select frameworks manually.".dimmed()
    );
    eprintln!();

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
            eprintln!(
                "{}",
                "At least one framework must be selected. Try again.".yellow()
            );
        },
        _ => Scenario::Server,
    };

    eprintln!();
    Ok(scenario)
}

fn select_frameworks() -> Result<Vec<ComplianceFramework>> {
    eprintln!();
    eprintln!("{}", "Select frameworks to include:".dimmed());

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
    eprintln!("{}", "Step 2: Select Output Format(s)".bold());
    eprintln!(
        "{}",
        "You can generate multiple formats simultaneously.".dimmed()
    );
    eprintln!();

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

    eprintln!();
    Ok(formats)
}

fn select_output_path() -> Result<Option<PathBuf>> {
    eprintln!("{}", "Step 3: Output Destination".bold());
    eprintln!();

    let theme = ColorfulTheme::default();

    let save_to_file = Confirm::with_theme(&theme)
        .with_prompt("Save report(s) to file?")
        .default(false)
        .interact()?;

    if !save_to_file {
        eprintln!("{}", "Report will be displayed in terminal.".dimmed());
        eprintln!();
        return Ok(None);
    }

    // Get output path
    let input: String = dialoguer::Input::with_theme(&theme)
        .with_prompt("Enter output directory or file path")
        .default("./compliance-report".to_string())
        .interact_text()?;

    eprintln!();
    Ok(Some(resolve_output_path(&input)))
}

/// Expands a leading `~` or `~/` to the user's home directory.
///
/// Falls back to the `HOME` environment variable if `dirs::home_dir()` is
/// unavailable, and leaves the input untouched if neither source resolves.
fn expand_tilde(input: &str) -> PathBuf {
    let home_relative = input.strip_prefix("~/");
    if input != "~" && home_relative.is_none() {
        return PathBuf::from(input);
    }

    let home = dirs::home_dir().or_else(|| std::env::var_os("HOME").map(PathBuf::from));
    match (home, home_relative) {
        (Some(home), Some(rest)) => home.join(rest),
        (Some(home), None) => home,
        (None, _) => PathBuf::from(input),
    }
}

/// Resolves the wizard's raw output-path input into a base file path.
///
/// Expands a leading `~`, then treats the result as a directory (joining a
/// default `compliance-report` filename) when the raw input ends with `/`
/// or the expanded path is an existing directory. Otherwise the expanded
/// path is returned unchanged, ready for the caller's own extension logic.
fn resolve_output_path(input: &str) -> PathBuf {
    let expanded = expand_tilde(input);
    if input.ends_with('/') || expanded.is_dir() {
        return expanded.join("compliance-report");
    }
    expanded
}

fn confirm_selections(state: &WizardState) -> Result<bool> {
    eprintln!("{}", "═══════════════════════════════════════".cyan());
    eprintln!("{}", "Review Your Selections".bold());
    eprintln!("{}", "═══════════════════════════════════════".cyan());
    eprintln!();

    // Show scenario
    if let Some(ref scenario) = state.scenario {
        let frameworks = scenario.frameworks();
        let framework_names: Vec<&str> = frameworks.iter().map(|f| f.full_name()).collect();

        eprintln!("  {} {}", "Scenario:".bold(), scenario.name());
        eprintln!("  {} {}", "Frameworks:".bold(), framework_names.join(", "));
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
    eprintln!("  {} {}", "Formats:".bold(), format_names.join(", "));

    // Show output
    match &state.output_path {
        Some(path) => eprintln!("  {} {}", "Output:".bold(), path.display()),
        None => eprintln!("  {} stdout", "Output:".bold()),
    }

    eprintln!();

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
                    // Single format - use path as-is or add extension.
                    //
                    // Same contradiction `hardener report --output` refuses: the
                    // extension is added when absent and, before this, never
                    // checked when present, so answering `report.json` and then
                    // picking Text saved a text report into `report.json` and
                    // said "Saved Text report to". Refused here through the same
                    // check, so the wizard and the flag cannot disagree.
                    super::report::refuse_extension_that_contradicts(base_path, *format)?;
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
                    let bytes = PdfFormatter::new().format_all_bytes(reports);
                    fs::write(&path, bytes)?;
                } else {
                    fs::write(&path, &formatted)?;
                }
                eprintln!(
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
                    let bytes = PdfFormatter::new().format_all_bytes(reports);
                    fs::write(&filename, bytes)?;
                    eprintln!("  {} Saved PDF report to: {}", "✓".green(), filename);
                    continue;
                }
                // Print text formats to stdout
                if state.output_formats.len() > 1 {
                    eprintln!(
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

fn print_summary(
    reports: &[hardener_compliance::ComplianceReport],
    state: &WizardState,
    unchecked: &[hardener_types::UncheckedCheck],
) {
    eprintln!();
    eprintln!("{}", "═══════════════════════════════════════".green());
    eprintln!("{}", "Report Generation Complete".green().bold());
    eprintln!("{}", "═══════════════════════════════════════".green());
    eprintln!();

    for report in reports {
        let summary = &report.report_summary;
        let total = summary.summary_total_controls;
        let passing = summary.summary_passing;
        let score = if total > 0 {
            (passing as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        let score_text = format_score(score);
        let score_color = if score >= 80.0 {
            score_text.green()
        } else if score >= 60.0 {
            score_text.yellow()
        } else {
            score_text.red()
        };

        eprintln!(
            "  {} {}: {}% ({}/{} controls passing)",
            framework_icon(&report.report_framework),
            framework_display_name(&report.report_framework),
            score_color,
            passing,
            total
        );
    }

    eprintln!();

    if let Some(note) = hardener_types::unchecked_summary(unchecked) {
        eprintln!("{}", note.dimmed());
    }

    if state.output_path.is_some() {
        eprintln!(
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
        ComplianceFramework::FedRAMP => "🏛️",
    }
}

fn framework_display_name(framework: &ComplianceFramework) -> &'static str {
    framework.full_name()
}

/// Renders a compliance score to one decimal place before colouring.
///
/// Colouring a string with `colored` and then applying `{:.1}` in a
/// `println!` template truncates the coloured string to one character wide
/// instead of formatting the number, so the number must be formatted first.
fn format_score(score: f64) -> String {
    format!("{score:.1}")
}

#[cfg(test)]
mod tests;
