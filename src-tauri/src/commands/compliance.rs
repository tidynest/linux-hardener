//! Split from the former flat `commands.rs` along the seams its test files
//! had already named. Shared plumbing lives in the parent; each domain here
//! keeps its own commands and their private helpers.

use super::*;

/// Parses framework name strings into `ComplianceFramework` enum values.
/// Unknown spellings are silently dropped rather than surfaced as errors,
/// matching the existing GUI contract for these call sites.
pub(crate) fn parse_frameworks(frameworks: &[String]) -> Vec<ComplianceFramework> {
    frameworks
        .iter()
        .filter_map(|f| ComplianceFramework::from_id(f))
        .collect()
}

/// The frameworks a report request names, refused when it names none the
/// tool knows. `parse_frameworks` drops unknown spellings by contract, so the
/// refusal sits on its result rather than its input; an empty result used to
/// run the generator over zero frameworks and return an empty list or write a
/// contentless export. The two causes get two sentences, because "select
/// something" and "nothing you sent is a framework" are different remedies.
/// The compliance tab disables both buttons on an empty selection, so this is
/// the second door, reachable by any other caller of the commands.
pub(crate) fn selected_frameworks(
    frameworks: &[String],
) -> Result<Vec<ComplianceFramework>, String> {
    let parsed = parse_frameworks(frameworks);
    if !parsed.is_empty() {
        return Ok(parsed);
    }
    if frameworks.is_empty() {
        return Err("No framework selected.".to_string());
    }
    Err(sanitise_error(&format!(
        "No known framework in the selection: {}",
        frameworks.join(", ")
    )))
}

/// Parses a format string into an `OutputFormat`.
pub(crate) fn parse_output_format(format: &str) -> Result<OutputFormat, String> {
    match format.to_lowercase().as_str() {
        "text" | "txt" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        "csv" => Ok(OutputFormat::Csv),
        "html" => Ok(OutputFormat::Html),
        "pdf" => Ok(OutputFormat::Pdf),
        _ => Err(sanitise_error(&format!(
            "Unsupported format '{}'. Use text, json, csv, html, or pdf.",
            format
        ))),
    }
}

/// Scans all plugins and collects findings and unchecked checks for
/// compliance reporting. A control whose covering check landed in the
/// unchecked list must never auto-pass on the mere absence of a finding.
/// Honours the local system/user config (directives and exceptions), the
/// same as `run_scan`, so a compliance report matches a manual scan.
pub(crate) async fn collect_findings() -> Result<Vec<ScanResult>, String> {
    let ctx = Context::new();
    let registry = create_plugin_registry();
    let plugin_list = registry.list().map_err(safe_err)?;

    // Same loader `run_scan` uses for its no-custom-path case: this call site
    // has no config_path of its own, so system/user config applies, falling
    // back to defaults rather than failing a background compliance refresh.
    let config = ConfigLoader::new().load().unwrap_or_default();

    let mut results = Vec::new();
    for metadata in plugin_list {
        // A plugin the config disables contributes no result at all, and
        // `scan_evidence::flatten`, inside `ReportGenerator::generate`, reads
        // that absence as "not assessed" rather than as a clean pass.
        if !config.is_plugin_enabled(metadata.plugin_id.as_str()) {
            continue;
        }
        let Ok(Some(plugin)) = registry.get(&metadata.plugin_id) else {
            continue;
        };
        // A scan that errored used to be swallowed by an `if let Ok`, which is
        // indistinguishable from a plugin that found nothing.
        let outcome = plugin
            .scan(&ctx, config.get_plugin_config(metadata.plugin_id.as_str()))
            .await;
        results.push(recorded_scan(&metadata.plugin_id, outcome));
    }
    Ok(results)
}

/// One plugin's scan outcome as a result the caller can record either way.
///
/// A scan that errored becomes a failed result rather than being dropped.
/// Dropping it is indistinguishable from a plugin that found nothing, and the
/// two are scored differently: `scan_evidence::flatten` reads an absent plugin
/// as `NotCovered` and a failed one as `ScanIncomplete` carrying its reason. On
/// a remote host the `Err` arm is a transport failure part-way through, so the
/// distinction is between "this host has no firewall backend" and "the
/// connection dropped whilst asking".
pub(crate) fn recorded_scan<E: std::fmt::Display>(
    plugin_id: &PluginId,
    outcome: Result<ScanResult, E>,
) -> ScanResult {
    outcome.unwrap_or_else(|e| hardener_plugins::failed_scan(plugin_id, &e.to_string()))
}

// `flatten_scan_results` used to live here, wrapping
// `hardener_plugins::flatten_persisted_scans`. It kept its own copy of a rule
// the CLI had already corrected and so passed controls nobody assessed. The
// flatten is inside `ReportGenerator::generate` now, which takes raw scan
// results, so there is nothing left here to get wrong.

/// Decides whether a persisted scan session's results should stand as the
/// report source.
///
/// `None` covers both "no completed session exists" and "a completed
/// session exists but carries zero results" - the latter happens when
/// `persist_scan_results` logs a `store_results` failure but still marks
/// the session Completed (see its doc comment), so the session row exists
/// while `scan_results` is empty. Even a clean host produces one
/// `ScanResult` per plugin, so an empty result set is never a legitimate
/// full scan; treating it as "no session" sends the caller to the fresh-scan
/// fallback instead of scoring it into a false-green zero-finding report.
pub(crate) fn persisted_scan_source(
    persisted: Option<(ScanSession, Vec<ScanResult>)>,
) -> Option<Vec<ScanResult>> {
    match persisted {
        Some((_, results)) if !results.is_empty() => Some(results),
        Some(_) | None => None,
    }
}

/// Sources compliance inputs from the latest persisted completed scan
/// session, so reports and the score reflect the scan the user actually
/// ran - including a privileged deep scan's root-only results, which a
/// fresh in-process scan could never see. Falls back to a fresh
/// unprivileged scan when no completed session exists (fresh install,
/// compliance tab opened before any scan), a completed session has no
/// results (see `persisted_scan_source`), or the history database cannot
/// be read; a read failure is logged, never propagated. Neither path can
/// trigger a privilege prompt.
pub(crate) async fn latest_or_fresh_findings() -> Result<Vec<ScanResult>, String> {
    let persisted = match create_scan_history_manager().await {
        Ok(manager) => manager.get_latest_scan().await.map_err(safe_err),
        Err(e) => Err(e),
    };
    match persisted {
        Ok(persisted) => match persisted_scan_source(persisted) {
            Some(results) => Ok(results),
            None => collect_findings().await,
        },
        Err(e) => {
            error!("Scan history unavailable, compliance report falling back to a fresh scan: {e}");
            collect_findings().await
        }
    }
}

/// Resolves the compliance profile of the machine this desktop runs on:
/// the local report commands always assess the local system. Detection
/// failure falls back to `Generic`, never an error.
pub(crate) fn local_profile() -> ComplianceProfile {
    Distribution::detect()
        .ok()
        .map(|distro| resolve_profile(&distro))
        .unwrap_or_default()
}

/// Reads the operator's declared-not-applicable set for the local system.
///
/// Same loader and same fallback as the local scan path: the desktop has no
/// `--config` of its own, so system and user config apply, and an unreadable
/// config leaves the set empty rather than failing a report. An empty set only
/// ever costs score, never fabricates one.
pub(crate) fn local_exclusions() -> ComplianceConfig {
    ConfigLoader::new().load().unwrap_or_default().compliance
}

/// Generates compliance reports for the specified frameworks.
///
/// Takes a list of framework names and returns compliance reports built
/// from the latest persisted scan session (fresh-scan fallback).
#[tauri::command]
pub async fn generate_compliance_report(
    frameworks: Vec<String>,
) -> Result<Vec<ComplianceReport>, String> {
    // Refused before the findings are sourced: a fresh scan for a report
    // nobody asked a framework of is work done for a message.
    let parsed_frameworks = selected_frameworks(&frameworks)?;
    let results = latest_or_fresh_findings().await?;

    let config = ReportConfig {
        scenario: Scenario::Custom(parsed_frameworks),
        formats: vec![OutputFormat::Text],
        output_dir: None,
        profile: local_profile(),
    };

    let generator = ReportGenerator::new(
        config,
        hardener_plugins::plugin_inventory(),
        local_exclusions(),
    );
    Ok(generator.generate(&results, &[]))
}

/// Where an export is written, given the operator's path and the chosen format.
///
/// Three decisions, none of which needs a report, a scan or a filesystem, and
/// all three of which an operator sees the consequence of.
///
/// **A path whose extension names a different document is refused**, in the
/// wording of a window rather than of a flag. `hardener report` has refused
/// this since `refuse_extension_that_contradicts` was added, because writing a
/// text report into a file named `.json` and exiting 0 is a lie a consumer will
/// act on. The desktop reached the same fork in-process and wrote the bytes,
/// so choosing PDF and typing `audit.json` produced a PDF called `audit.json`
/// and reported it saved. Both now decide through
/// `OutputFormat::contradicted_by`, which is the only part of a refusal that
/// can be shared: the CLI's sentence names `--output` and this one has no flag
/// to name.
///
/// **An extension is appended only when the path has none**, matching
/// `report.rs`. A dated stem like `q3.2026.08` has extension `08`, names no
/// document, and is left alone rather than being read as a format.
///
/// **A path that was not given is built under Documents**, falling back to the
/// home directory and then to the working directory, with a local timestamp so
/// two exports in one session do not overwrite each other.
pub(crate) fn export_destination(
    output_path: Option<String>,
    output_format: OutputFormat,
    timestamp: &str,
) -> Result<String, String> {
    let Some(path) = output_path else {
        let dir = dirs::document_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let name = format!(
            "compliance-report-{timestamp}.{}",
            output_format.extension()
        );
        return Ok(dir.join(name).to_string_lossy().to_string());
    };

    let as_path = std::path::Path::new(&path);
    if let Some(named) = output_format.contradicted_by(as_path) {
        return Err(format!(
            "'{path}' names a {} file, but the chosen format is {}. \
             Give the file the {} extension, or none at all, or export as {}.",
            named.extension(),
            output_format.extension(),
            output_format.extension(),
            named.extension(),
        ));
    }

    if as_path.extension().is_none() {
        return Ok(format!("{path}.{}", output_format.extension()));
    }
    Ok(path)
}

/// Exports compliance reports to a file in the specified format.
///
/// Generates reports, formats them, and writes to the output path.
/// Returns the final file path used (extension may be appended).
#[tauri::command]
pub async fn export_compliance_report(
    frameworks: Vec<String>,
    format: String,
    output_path: Option<String>,
) -> Result<String, String> {
    for f in &frameworks {
        validate_ipc_string(f, "framework")?;
    }
    validate_ipc_string(&format, "format")?;
    if let Some(ref path) = output_path {
        validate_output_path(path)?;
    }

    let output_format = parse_output_format(&format)?;
    let parsed_frameworks = selected_frameworks(&frameworks)?;
    // Resolved before anything is rendered: a contradicting extension is
    // refused, and scanning a host to build a report nobody may write is work
    // done for a message.
    let final_path = export_destination(
        output_path,
        output_format,
        &chrono::Local::now().format("%Y%m%d-%H%M%S").to_string(),
    )?;

    // Same sourcing as generate_compliance_report: an exported report must
    // match the one on screen.
    let results = latest_or_fresh_findings().await?;

    let config = ReportConfig {
        scenario: Scenario::Custom(parsed_frameworks),
        formats: vec![output_format],
        output_dir: None,
        profile: local_profile(),
    };

    let generator = ReportGenerator::new(
        config,
        hardener_plugins::plugin_inventory(),
        local_exclusions(),
    );
    let reports = generator.generate(&results, &[]);

    // One arm per format, one render, one write. PDF used to be special-cased
    // around a `String` match that had already rendered it: `format_all` into a
    // lossy `String` which was then discarded, and `format_all_bytes` again for
    // the bytes written. Every formatter answers `format_all_bytes`, the four
    // text ones through the trait's default, so there is no case to except and
    // no arm left over to make unreachable.
    let bytes = match output_format {
        OutputFormat::Text => TextFormatter::new().format_all_bytes(&reports),
        OutputFormat::Json => JsonFormatter::pretty().format_all_bytes(&reports),
        OutputFormat::Csv => CsvFormatter::new().format_all_bytes(&reports),
        OutputFormat::Html => HtmlFormatter::new().format_all_bytes(&reports),
        OutputFormat::Pdf => PdfFormatter::new().format_all_bytes(&reports),
    };
    std::fs::write(&final_path, bytes)
        .map_err(|e| safe_err(format!("Failed to write report: {}", e)))?;

    Ok(final_path)
}
