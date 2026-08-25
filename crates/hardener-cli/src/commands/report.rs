//! Compliance report generation command.

use crate::cli::OutputFormat as CliOutputFormat;
use anyhow::{Result, anyhow};
use chrono::Local;
use hardener_common::types::{ComplianceFramework, ComplianceProfile};
use hardener_compliance::{
    JsonFormatter, OutputFormat, ReportConfig, ReportFormatter, ReportGenerator, Scenario,
    TextFormatter, profile_label,
};
use hardener_core::{
    Context, Finding, HardenerConfig, PluginMetadata, ScanResult, executor::SystemExecutor,
};
use hardener_plugins::create_plugin_registry;
use hardener_scheduler::db::ScanFinding;
use hardener_types::PluginId;
use std::{fs, io, io::Write, path::PathBuf, sync::Arc};

/// Decides which format the report body is rendered in.
///
/// `--report-format` wins whenever it is given, including when it names the
/// default. When it is absent the global `-f/--format` decides, so `report
/// --format json` returns JSON the way it does for `scan`, `plugins`,
/// `checkpoint list` and `history list`.
///
/// It did not, before #160. `--report-format` carried a clap `default_value`,
/// so the command could not tell "the user asked for text" from "the user asked
/// for nothing", and the global flag reached only the progress rendering, which
/// it suppressed. `report --format json` therefore exited 0, printed no
/// progress, and emitted the text report: the invocation that looked most like
/// machine mode was the one that produced prose. A CI job grepping that output
/// for `"control_status": "Fail"` finds nothing and calls the host clean.
///
/// Extracted from `run` so the decision can be tested without standing up a
/// scan; `run` reaches this point only after eight plugins have executed.
fn resolve_output_format(
    report_format: Option<&str>,
    cli_format: CliOutputFormat,
) -> Result<OutputFormat> {
    let Some(value) = report_format else {
        // No round trip through a string: the global flag is already an
        // `OutputFormat`, narrowed to Text or Json at parse time by
        // `GlobalFormat`.
        return Ok(cli_format);
    };

    match value.to_lowercase().as_str() {
        "json" => Ok(OutputFormat::Json),
        "text" | "txt" => Ok(OutputFormat::Text),
        "csv" => Ok(OutputFormat::Csv),
        "html" => Ok(OutputFormat::Html),
        "pdf" => Ok(OutputFormat::Pdf),
        _ => Err(anyhow!(
            "Unsupported format '{}'. Use 'TEXT', 'JSON', 'CSV', 'HTML' or 'PDF'.",
            value
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    scenario: Option<String>,
    framework: Option<String>,
    profile: Option<String>,
    report_format: Option<String>,
    output: Option<String>,
    cli_format: CliOutputFormat,
    quiet: bool,
    executor: Arc<dyn SystemExecutor>,
    config_path: Option<&PathBuf>,
) -> Result<()> {
    // Determine scenario/frameworks (shared with `batch report`).
    let scenario = resolve_scenario(framework, scenario, quiet)?;

    // An explicit --profile wins; otherwise the scanned system decides, read
    // through the scan executor so a `--ssh` target resolves from ITS
    // os-release, not the controller's. Failure falls back to Generic.
    let profile = match profile {
        Some(value) => parse_profile(&value)?,
        None => super::batch::detect_host_profile(executor.as_ref()).await,
    };
    if !quiet && profile != ComplianceProfile::Generic {
        eprintln!("Profile: {}", profile_line(profile, &scenario));
    }

    let output_format = resolve_output_format(report_format.as_deref(), cli_format)?;

    // Judged before the scan, not at the point of writing: this is an argument
    // contradicting an argument, and running eight plugins, or a whole remote
    // scan under `--ssh`, before saying so wastes everything it cost. `history
    // export` judges its own path before it opens the database for the same
    // reason.
    if let Some(path) = output.as_deref() {
        refuse_extension_that_contradicts(std::path::Path::new(path), output_format)?;
    }

    // Build config
    let config = ReportConfig {
        scenario,
        formats: vec![output_format],
        output_dir: None,
        profile,
    };

    if !quiet {
        eprintln!("Running security scan...");
    }

    // Load the real plugin configuration (directives + exceptions) so the
    // report reflects config the same way `scan`/`apply` do. Report has no
    // audit mode, so a `--config` path is always honoured (missing/invalid
    // is a hard error, matching `scan`'s `load_config`).
    let hardener_config = super::config_loader(config_path)
        .load()
        .map_err(|e| anyhow!("Config error: {}", e))?;

    // Run the scan. The results travel as they came back: the generator
    // flattens them itself, so nothing here has to remember to.
    let (results, skipped) =
        run_scan_for_report(quiet, executor, &cli_format, &hardener_config).await?;

    if !quiet {
        eprintln!("Generating compliance report...");
    }

    // Generate reports. The coverage set is what the plugins actually assess,
    // it tells the generator which controls may report Pass/Fail vs ManualReview.
    // The same configuration supplies the operator's declared-not-applicable
    // set, so a control excluded in `[compliance]` leaves the denominator here
    // rather than counting as unassessed.
    let generator = ReportGenerator::new(
        config,
        hardener_plugins::plugin_inventory(),
        hardener_config.compliance.clone(),
    );
    let reports = generator.generate(&results, &skipped);

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
            let bytes = hardener_compliance::output::PdfFormatter::new().format_all_bytes(&reports);
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

        let bytes = hardener_compliance::output::PdfFormatter::new().format_all_bytes(&reports);
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

/// Refuses an `--output` path whose extension names a document other than the
/// one `--report-format` selected.
///
/// The extension was added when absent and never checked when present, and
/// `--report-format` defaults to `text`, so `report --output report.json` wrote
/// a human text report into a file named `.json` and exited 0 saying it had
/// saved a report. Unlike `history export`, which has one serialisation and
/// refuses any foreign document, this command really does render five formats,
/// so the honest answer is to make the path and the format agree rather than to
/// pick one for the operator: choosing from the extension would silently
/// override an explicit `--report-format`, and there is no way to tell an
/// explicit `--report-format text` from the default.
pub(crate) fn refuse_extension_that_contradicts(
    path: &std::path::Path,
    selected: OutputFormat,
) -> anyhow::Result<()> {
    let Some(named) = path
        .extension()
        .and_then(|e| e.to_str())
        .and_then(OutputFormat::from_extension)
    else {
        return Ok(());
    };
    if named == selected {
        return Ok(());
    }
    // The flag is not named: `report` selects with `--report-format` and the
    // `batch` verbs, which share this check, select with the global `--format`.
    // Naming one of them would be wrong for the other half of the callers.
    anyhow::bail!(
        "--output {} names a {} document, but the selected format is {}. \
         Give the path the extension of the format you chose, or none at all, \
         or choose {}.",
        path.display(),
        named.extension(),
        selected.extension(),
        named.extension(),
    )
}

/// One scan pass: what ran, and what the config stopped from running.
///
/// Both halves matter to a compliance report. Returning only the first would
/// leave a disabled plugin indistinguishable from one that found nothing.
pub struct GroupedScan {
    /// Each plugin that ran, paired with its result.
    pub results: Vec<(PluginMetadata, ScanResult)>,
    /// Plugins the config disabled, which therefore assessed nothing.
    pub skipped: Vec<PluginMetadata>,
}

impl GroupedScan {
    /// The pair `ReportGenerator::generate` takes: the results as they came
    /// back, and the ids of the plugins the config disabled.
    ///
    /// The metadata pairing above is for the renderers, which print a plugin's
    /// name beside its rows. A report does not need it: the generator holds the
    /// whole plugin inventory and resolves metadata by id, which is what lets
    /// it take raw results and do its own flatten.
    pub fn evidence(&self) -> (Vec<ScanResult>, Vec<PluginId>) {
        (
            self.results.iter().map(|(_, r)| r.clone()).collect(),
            self.skipped.iter().map(|m| m.plugin_id.clone()).collect(),
        )
    }
}

/// Scans every enabled plugin and returns each plugin's result alongside its
/// metadata.
///
/// Pairing the whole `ScanResult` with its `PluginMetadata` preserves
/// `plugin_id`, which history persistence needs, the unchecked entries the
/// desktop deep-scan flow consumes, and `scan_success`/`scan_error`, which a
/// bare findings triple could not carry. A plugin that failed must stay
/// distinguishable from one that found nothing all the way to the renderer.
pub async fn scan_grouped(
    quiet: bool,
    executor: Arc<dyn SystemExecutor>,
    cli_format: &CliOutputFormat,
    config: &HardenerConfig,
) -> Result<GroupedScan> {
    let registry = create_plugin_registry();
    let ctx = Context::with_executor(executor);

    let plugins = registry.list()?;
    let show_progress = !quiet && *cli_format == CliOutputFormat::Text;

    // `scan` honours the config's plugin selection and this path did not, so
    // `report` ran plugins the operator had turned off. The skipped half is
    // carried out of here rather than dropped: a plugin that never ran has
    // assessed nothing, and the generator reads coverage statically, so
    // silence about it passes every control it covers.
    let (enabled, skipped): (Vec<_>, Vec<_>) = plugins
        .iter()
        .cloned()
        .partition(|metadata| config.is_plugin_enabled(metadata.plugin_id.as_str()));

    let handles: Vec<_> = enabled
        .iter()
        .filter_map(|metadata| {
            registry
                .get(&metadata.plugin_id)
                .ok()
                .flatten()
                .map(|plugin| (metadata.clone(), plugin))
        })
        .collect();

    // Plugins are independent, scan them concurrently. join_all yields
    // results in input order, so groups stay in registry (plugin-id) order.
    let scans = futures::future::join_all(handles.iter().map(|(metadata, plugin)| {
        plugin.scan(&ctx, config.get_plugin_config(metadata.plugin_id.as_str()))
    }))
    .await;

    let mut grouped = Vec::new();
    for ((metadata, _), scan) in handles.iter().zip(scans) {
        match scan {
            Ok(result) => {
                if show_progress {
                    eprintln!(
                        "  Scanned {}: {} finding(s)",
                        metadata.plugin_name,
                        result.scan_findings.len()
                    );
                }
                grouped.push((metadata.clone(), result));
            }
            Err(e) => {
                if show_progress {
                    eprintln!("  Scanned {}: error: {}", metadata.plugin_name, e);
                }
                // Dropping the plugin here is what let a failed scan read as a
                // clean one: absent from the group list, it contributes no
                // findings, and the generator passes every control it covers.
                grouped.push((
                    metadata.clone(),
                    hardener_plugins::failed_scan(&metadata.plugin_id, &e.to_string()),
                ));
            }
        }
    }

    Ok(GroupedScan {
        results: grouped,
        skipped,
    })
}

/// Scans every plugin and returns the evidence a compliance report is scored
/// from: each plugin's result, and the ids of the plugins the config disabled.
///
/// It used to return an already-flattened `(findings, unchecked)` pair, which
/// meant every caller had to reach the flatten to be correct and one of them
/// did not. `ReportGenerator::generate` does the flatten now, so what travels
/// here is what the scan actually produced.
pub async fn run_scan_for_report(
    quiet: bool,
    executor: Arc<dyn SystemExecutor>,
    cli_format: &CliOutputFormat,
    config: &HardenerConfig,
) -> Result<(Vec<ScanResult>, Vec<PluginId>)> {
    Ok(scan_grouped(quiet, executor, cli_format, config)
        .await?
        .evidence())
}

/// Converts a core `Finding` + plugin metadata into a scheduler `ScanFinding`.
///
/// Shared by the single-host `scan` and multi-host `batch` persistence paths.
pub(crate) fn finding_to_scan_finding(meta: &PluginMetadata, finding: &Finding) -> ScanFinding {
    ScanFinding {
        plugin_id: meta.plugin_id.to_string(),
        finding_id: finding.finding_id.clone(),
        severity: finding.finding_severity.to_string(),
        title: finding.finding_title.clone(),
        description: Some(finding.finding_description.clone()),
        current_value: Some(finding.finding_current_value.clone()),
        recommended_value: Some(finding.finding_recommended_value.clone()),
        category: Some(finding.finding_category.to_string()),
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
        return Ok(Scenario::Custom(vec![parse_framework(&fw)?]));
    }
    if let Some(sc) = scenario {
        return parse_scenario(&sc);
    }
    if !quiet {
        eprintln!("No scenario specified, using 'server' (CIS + STIG)");
        eprintln!(
            "Use --scenario or --framework to specify. Run 'hardener report --help' for options.\n"
        );
    }
    Ok(Scenario::Server)
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
    ComplianceFramework::from_id(s).ok_or_else(|| {
        anyhow!(
            "Unknown framework '{}'. Valid options: cis, stig, nist, pcidss, hipaa, gdpr, iso27001, soc2, 800-171, fedramp",
            s
        )
    })
}

/// Parses an explicit `--profile` value. Shared by the single-host `report`
/// and multi-host `batch report` commands.
pub(crate) fn parse_profile(s: &str) -> Result<ComplianceProfile> {
    s.parse::<ComplianceProfile>().map_err(|e| anyhow!(e))
}

/// Names a non-generic profile for the progress line, using the identifier
/// scheme labels of the frameworks in scope where they exist and the plain
/// profile name otherwise.
fn profile_line(profile: ComplianceProfile, scenario: &Scenario) -> String {
    let labels: Vec<&str> = scenario
        .frameworks()
        .iter()
        .filter_map(|framework| profile_label(profile, *framework))
        .collect();
    if labels.is_empty() {
        profile.to_string()
    } else {
        format!("{} identifiers", labels.join(" + "))
    }
}

#[cfg(test)]
mod tests;
