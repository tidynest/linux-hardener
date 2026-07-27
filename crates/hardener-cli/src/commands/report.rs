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
    ConfigLoader, Context, Finding, HardenerConfig, PluginMetadata, ScanResult,
    executor::SystemExecutor, plugin::UncheckedCheck,
};
use hardener_plugins::create_plugin_registry;
use hardener_scheduler::db::ScanFinding;
use std::{fs, io, io::Write, path::PathBuf, sync::Arc};

#[allow(clippy::too_many_arguments)]
pub async fn run(
    scenario: Option<String>,
    framework: Option<String>,
    profile: Option<String>,
    report_format: String,
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
        profile,
    };

    if !quiet {
        eprintln!("Running security scan...");
    }

    // Load the real plugin configuration (directives + exceptions) so the
    // report reflects config the same way `scan`/`apply` do. Report has no
    // audit mode, so a `--config` path is always honoured (missing/invalid
    // is a hard error, matching `scan`'s `load_config`).
    let mut loader = ConfigLoader::new();
    if let Some(path) = config_path {
        loader = loader.with_cli_config(path.clone());
    }
    let hardener_config = loader.load().map_err(|e| anyhow!("Config error: {}", e))?;

    // Run scan to get findings and the checks the current privilege level
    // could not evaluate.
    let (findings, unchecked) =
        run_scan_with_unchecked(quiet, executor, &cli_format, &hardener_config).await?;

    if !quiet {
        eprintln!("Generating compliance report...");
    }

    // Generate reports. The coverage set is what the plugins actually assess,
    // it tells the generator which controls may report Pass/Fail vs ManualReview.
    let generator = ReportGenerator::new(config, hardener_plugins::compliance_coverage());
    let reports = generator.generate(&findings, &unchecked);

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

/// Scans every plugin and returns findings and unchecked checks, each
/// flattened across plugins. The compliance report generator needs both: a
/// control whose covering check landed in `unchecked` must never auto-pass
/// on the mere absence of a finding.
///
/// A plugin whose scan did not complete, and one the config never let run,
/// each contribute an unchecked entry of their own, because the generator reads
/// coverage statically: without one, the controls that plugin covers would pass
/// on the very silence its absence caused.
pub async fn run_scan_with_unchecked(
    quiet: bool,
    executor: Arc<dyn SystemExecutor>,
    cli_format: &CliOutputFormat,
    config: &HardenerConfig,
) -> Result<(Vec<Finding>, Vec<UncheckedCheck>)> {
    let grouped = scan_grouped(quiet, executor, cli_format, config).await?;
    Ok(flatten_scans(&grouped.results, &grouped.skipped))
}

/// Flattens grouped scan results into the findings and unchecked lists the
/// compliance generator consumes.
///
/// The implementation lives in `hardener_plugins::scan_outcome`, next to the
/// coverage table it depends on, because the desktop needs the same rule and a
/// second copy here is how it came to be applied in one place and not the
/// other.
pub(crate) fn flatten_scans(
    grouped: &[(PluginMetadata, ScanResult)],
    skipped: &[PluginMetadata],
) -> (Vec<Finding>, Vec<UncheckedCheck>) {
    hardener_plugins::flatten_scans(grouped, skipped)
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
mod tests {
    use super::*;
    use hardener_common::types::{ControlStatus, FindingCategory, PluginId, Severity};
    use hardener_core::{MockExecutor, PolicyException};
    use std::sync::Arc;

    #[test]
    fn finding_to_scan_finding_uses_display_strings() {
        let meta = PluginMetadata {
            plugin_category: FindingCategory::FileSystem,
            plugin_description: "test".to_string(),
            plugin_id: PluginId::new("test-plugin"),
            plugin_name: "Test".to_string(),
            plugin_version: "0.0.0".to_string(),
        };
        let finding = Finding {
            finding_id: "TEST-001".to_string(),
            finding_category: FindingCategory::FileSystem,
            finding_severity: Severity::Critical,
            finding_title: "title".to_string(),
            finding_description: "description".to_string(),
            finding_explanation: "explanation".to_string(),
            finding_impact: "impact".to_string(),
            finding_current_value: "current".to_string(),
            finding_recommended_value: "recommended".to_string(),
            finding_remediation_steps: vec![],
            finding_compliance: vec![],
            finding_policy_exception: None,
        };

        let row = finding_to_scan_finding(&meta, &finding);

        assert_eq!(
            row.severity, "CRITICAL",
            "severity must persist via Display, not Debug"
        );
        assert_eq!(
            row.category.as_deref(),
            Some("File System"),
            "category must persist via Display, not Debug"
        );
    }

    #[test]
    fn parse_profile_accepts_known_values_and_rejects_unknown() {
        assert_eq!(parse_profile("rhel10").unwrap(), ComplianceProfile::Rhel10);
        assert_eq!(
            parse_profile("generic").unwrap(),
            ComplianceProfile::Generic
        );
        let err = parse_profile("rhel9").unwrap_err().to_string();
        assert!(err.contains("Valid options: generic, rhel10"), "{err}");
    }

    #[test]
    fn profile_line_prefers_framework_labels() {
        // Frameworks with a labelled RHEL 10 scheme name it outright.
        let stig = Scenario::Custom(vec![ComplianceFramework::STIG]);
        assert_eq!(
            profile_line(ComplianceProfile::Rhel10, &stig),
            "DISA RHEL 10 STIG V1R1 identifiers"
        );
        // Profile-invariant frameworks fall back to the plain profile name.
        let nist = Scenario::Custom(vec![ComplianceFramework::NIST]);
        assert_eq!(profile_line(ComplianceProfile::Rhel10, &nist), "rhel10");
    }

    #[tokio::test]
    async fn scan_grouped_keeps_plugin_grouping_and_flattening_matches() {
        let exec = Arc::new(MockExecutor::new());
        let default_config = HardenerConfig::default();
        let grouped = scan_grouped(true, exec.clone(), &CliOutputFormat::Json, &default_config)
            .await
            .unwrap();
        // Every group carries its plugin metadata (so plugin_id is preserved).
        for (meta, _result) in &grouped.results {
            assert!(!meta.plugin_id.as_str().is_empty(), "group has a plugin id");
        }
        // Every registered plugin appears, including any whose scan failed:
        // dropping one is what let a failure read as a clean result. The
        // default config enables them all, so nothing is skipped here.
        assert_eq!(
            grouped.results.len(),
            create_plugin_registry().list().unwrap().len(),
            "no plugin may be missing from the grouped results"
        );
        assert!(
            grouped.skipped.is_empty(),
            "default config disables nothing"
        );

        // run_scan_with_unchecked returns the same findings and unchecked
        // entries, each flattened across plugins, plus one synthesised
        // unchecked entry per plugin whose scan did not complete.
        let (findings, unchecked) =
            run_scan_with_unchecked(true, exec, &CliOutputFormat::Json, &default_config)
                .await
                .unwrap();
        let grouped_findings: usize = grouped
            .results
            .iter()
            .map(|(_, r)| r.scan_findings.len())
            .sum();
        let grouped_unchecked: usize = grouped
            .results
            .iter()
            .map(|(_, r)| r.scan_unchecked.len())
            .sum();
        let failed = grouped
            .results
            .iter()
            .filter(|(_, r)| !r.scan_success)
            .count();
        assert_eq!(findings.len(), grouped_findings, "findings flatten");
        assert_eq!(
            unchecked.len(),
            grouped_unchecked + failed,
            "unchecked flatten, plus one entry per incomplete scan"
        );
        // The bare MockExecutor has no fixture data, so this exercises the
        // failure path rather than asserting a vacuous equality.
        assert!(failed > 0, "expected at least one plugin scan to fail here");
    }

    /// A plugin whose scan did not complete must not hand its controls a Pass.
    ///
    /// The generator decides Pass from static plugin-declared coverage plus the
    /// absence of a finding. A failed scan produces no findings, so without the
    /// failure reaching the report the two are indistinguishable and every
    /// control that plugin covers passes on evidence nobody collected. This is
    /// the compliance-report face of the same conflation `scan` hit: silence
    /// standing for both "verified" and "never checked".
    #[tokio::test]
    async fn a_failed_plugin_scan_cannot_pass_its_compliance_controls() {
        // No sshd_config on this executor, so the ssh plugin's scan reports
        // scan_success = false and returns no findings.
        let executor: Arc<dyn SystemExecutor> = Arc::new(MockExecutor::new());
        let report_config = ReportConfig {
            scenario: Scenario::Custom(vec![ComplianceFramework::CIS]),
            formats: vec![OutputFormat::Json],
            output_dir: None,
            profile: ComplianceProfile::default(),
        };

        let (findings, unchecked) = run_scan_with_unchecked(
            true,
            executor,
            &CliOutputFormat::Json,
            &HardenerConfig::default(),
        )
        .await
        .unwrap();

        let report = ReportGenerator::new(report_config, hardener_plugins::compliance_coverage())
            .generate(&findings, &unchecked)
            .into_iter()
            .next()
            .expect("one report");
        let control = report
            .report_controls
            .iter()
            .find(|c| c.control_id == "5.2.10")
            .expect("CIS 5.2.10 is covered by the ssh plugin");

        assert_ne!(
            control.control_status,
            ControlStatus::Pass,
            "CIS 5.2.10 passed on a host whose ssh scan never completed"
        );
        assert_eq!(
            control.control_status,
            ControlStatus::ManualReview,
            "a control whose covering scan failed is exactly the manual-review case"
        );
    }

    #[test]
    fn every_canonical_framework_id_parses() {
        // Guards the shared enum ids against drift: the UI builds its picker
        // and auto-report requests from ComplianceFramework::ALL, so every
        // canonical id must stay accepted by the CLI parser.
        for framework in ComplianceFramework::ALL {
            assert_eq!(
                parse_framework(framework.id()).unwrap(),
                framework,
                "canonical id '{}' must parse to its framework",
                framework.id()
            );
        }
    }

    #[test]
    fn parse_framework_accepts_legacy_aliases() {
        // Every spelling the flag historically accepted must keep working
        // now that parsing delegates to ComplianceFramework::from_id.
        for (alias, expected) in [
            ("pcidss", ComplianceFramework::PCIDSS),
            ("pci-dss", ComplianceFramework::PCIDSS),
            ("pci", ComplianceFramework::PCIDSS),
            ("iso", ComplianceFramework::ISO27001),
            ("soc-2", ComplianceFramework::SOC2),
            ("nist800171", ComplianceFramework::NIST800171),
            ("nist-800-171", ComplianceFramework::NIST800171),
            ("fed-ramp", ComplianceFramework::FedRAMP),
            ("PCI-DSS", ComplianceFramework::PCIDSS),
        ] {
            assert_eq!(
                parse_framework(alias).unwrap(),
                expected,
                "alias '{alias}' must still parse"
            );
        }
    }

    #[test]
    fn parse_framework_rejects_unknown() {
        let err = parse_framework("nonsense").unwrap_err().to_string();
        assert!(err.contains("Unknown framework 'nonsense'"), "{err}");
    }

    /// Proves the report scan path is config-aware end to end: a config that
    /// excepts a known finding changes the mapped control's outcome, which
    /// `PluginConfig::default()` (Task 1's placeholder) could never do.
    #[tokio::test]
    async fn report_scan_path_honours_config_exceptions() {
        // A genuine CIS 1.5.1 violation: ASLR disabled. No other plugin has
        // fixture data on this MockExecutor; scan_grouped tolerates and skips
        // a plugin whose scan errors, so only this finding is at play.
        let executor: Arc<dyn SystemExecutor> =
            Arc::new(MockExecutor::new().with_file("/proc/sys/kernel/randomize_va_space", "0"));
        let coverage = hardener_plugins::compliance_coverage();
        let report_config = ReportConfig {
            scenario: Scenario::Custom(vec![ComplianceFramework::CIS]),
            formats: vec![OutputFormat::Json],
            output_dir: None,
            profile: ComplianceProfile::default(),
        };

        // Baseline: an unexcepted violation fails the control.
        let (findings, unchecked) = run_scan_with_unchecked(
            true,
            executor.clone(),
            &CliOutputFormat::Json,
            &HardenerConfig::default(),
        )
        .await
        .unwrap();
        let report = ReportGenerator::new(report_config.clone(), coverage.clone())
            .generate(&findings, &unchecked)
            .into_iter()
            .next()
            .expect("one report");
        let control = report
            .report_controls
            .iter()
            .find(|c| c.control_id == "1.5.1")
            .expect("CIS 1.5.1 is covered by the kernel plugin");
        assert_eq!(
            control.control_status,
            ControlStatus::Fail,
            "an unexcepted ASLR violation must fail CIS 1.5.1"
        );

        // A real config excepting the exact finding the kernel plugin reports.
        let mut config = HardenerConfig::default();
        config.kernel.exceptions.insert(
            "kernel.randomize_va_space".to_string(),
            PolicyException {
                value: "0".to_string(),
                allowed: true,
                reason: "test exception".to_string(),
                approved_by: None,
                approved_date: None,
                ticket: None,
                expires: None,
            },
        );

        let (findings, unchecked) =
            run_scan_with_unchecked(true, executor, &CliOutputFormat::Json, &config)
                .await
                .unwrap();
        let report = ReportGenerator::new(report_config, coverage)
            .generate(&findings, &unchecked)
            .into_iter()
            .next()
            .expect("one report");
        let control = report
            .report_controls
            .iter()
            .find(|c| c.control_id == "1.5.1")
            .expect("CIS 1.5.1 remains covered");
        assert_eq!(
            control.control_status,
            ControlStatus::Pass,
            "an excepted finding must not fail its mapped control"
        );
    }
}
