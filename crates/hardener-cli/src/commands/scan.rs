use crate::cli::{OutputFormat, ScanMode, SeverityFilter};
use crate::output;
use anyhow::Result;
use hardener_common::types::Severity;
use hardener_core::{ConfigLoader, Context, HardenerConfig, PluginRegistry};
use std::path::PathBuf;

pub struct ScanOptions<'a> {
    pub plugin_filter: &'a [String],
    pub severity_filter: SeverityFilter,
    pub format: OutputFormat,
    pub quiet: bool,
    pub config_path: Option<&'a PathBuf>,
    pub audit: bool,
    pub compliance: bool,
    pub exit_code: bool,
}

pub async fn run(opts: ScanOptions<'_>) -> Result<()> {
    // Determine scan mode
    let mode = if opts.audit {
        ScanMode::Audit
    } else if opts.compliance {
        ScanMode::Compliance
    } else {
        ScanMode::Default
    };

    // Load config (ignored in audit mode)
    let _config = load_config(opts.config_path, mode)?;
    let registry = create_plugin_registry();
    let ctx = Context::new();

    let plugins = registry.list()?;
    let min_severity = severity_filter_to_severity(&opts.severity_filter);

    let mut all_results = Vec::new();

    for metadata in &plugins {
        // Skip if plugin filter is set and this plugin isn't in it
        if !opts.plugin_filter.is_empty()
            && !opts.plugin_filter
                .iter()
                .any(|p| p == metadata.plugin_id.as_str())
        {
            continue;
        }

        if !opts.quiet {
            output::status(&opts.format, &format!("Scanning: {}", metadata.plugin_name));
        }

        if let Ok(Some(plugin)) = registry.get(&metadata.plugin_id) {
            match plugin.scan(&ctx) {
                Ok(results) => {
                    // Filter findings by severity
                    let filtered_findings: Vec<_> = results
                        .scan_findings
                        .iter()
                        .filter(|f| f.finding_severity >= min_severity)
                        .cloned()
                        .collect();
                    all_results.push((metadata.clone(), filtered_findings));
                }
                Err(e) => {
                    output::error(
                        &opts.format,
                        &format!("Failed to scan {}: {e}", metadata.plugin_name),
                    );
                }
            }
        }
    }

    output::scan_results(&opts.format, &all_results, mode);

    // Handle exit code flag
    if opts.exit_code {
        let has_findings = all_results.iter().any(|(_, findings)| !findings.is_empty());
        if has_findings {
            std::process::exit(1);
        }
    }

    Ok(())
}

fn load_config(config_path: Option<&PathBuf>, mode: ScanMode) -> Result<HardenerConfig> {
    // In audit mode, ignore all config and use defaults
    if mode == ScanMode::Audit {
        return Ok(HardenerConfig::default());
    }

    let mut loader = ConfigLoader::new();
    if let Some(path) = config_path {
        loader = loader.with_cli_config(path.clone());
    }
    loader
        .load()
        .map_err(|e| anyhow::anyhow!("Config error: {}", e))
}

fn create_plugin_registry() -> PluginRegistry {
    use hardener_plugins::*;

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

fn severity_filter_to_severity(filter: &SeverityFilter) -> Severity {
    match filter {
        SeverityFilter::Info => Severity::Info,
        SeverityFilter::Low => Severity::Low,
        SeverityFilter::Medium => Severity::Medium,
        SeverityFilter::High => Severity::High,
        SeverityFilter::Critical => Severity::Critical,
    }
}
