//! Apply command: applies hardening changes with dry-run and checkpoint support.

use crate::cli::OutputFormat;
use crate::output;
use anyhow::{Result, bail};
use hardener_common::types::PluginId;
use hardener_core::{
    ApplyResult, Context, HardenerConfig, PluginMetadata, SystemExecutor, ValidationReport,
};
use hardener_plugins::create_plugin_registry;
use hardener_state::{ActionResult, ActionType, AuditLogger, CheckpointManager};
use std::sync::Arc;

use super::privilege::is_privileged;
use super::state::{get_audit_logger, get_checkpoint_manager};

/// Result of running `apply_host` for one executor target.
pub(crate) struct ApplyHostResult {
    pub results: Vec<(PluginMetadata, ApplyResult)>,
    pub validation_reports: Vec<ValidationReport>,
    pub had_failure: bool,
    /// Plugins the config disabled, returned rather than dropped so a caller
    /// can tell "nothing needed changing" apart from "nothing was allowed to
    /// run". Both otherwise render as a clean exit.
    pub skipped: Vec<PluginId>,
}

impl ApplyHostResult {
    /// Whether the config disabled every plugin the caller selected, leaving
    /// this run with nothing to do.
    ///
    /// One rule, because `apply` and `batch apply` both need it and a second
    /// copy is how the enablement check diverged in the first place. A plugin
    /// that actually ran leaves a result, a validation report, or a failure, so
    /// the absence of all three alongside a non-empty skip list is exactly the
    /// no-op case.
    pub fn nothing_ran(&self) -> bool {
        !self.skipped.is_empty()
            && self.results.is_empty()
            && self.validation_reports.is_empty()
            && !self.had_failure
    }

    /// The skipped plugin ids as an operator writes them in a config file.
    pub fn skipped_list(&self) -> String {
        self.skipped
            .iter()
            .map(|id| id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Core apply/validate loop over a single executor target.
///
/// Handles plugin iteration, disabled-plugin skipping, audit logging, and
/// result collection. Rendering and the CLI-level root gate live in `run`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn apply_host(
    executor: Arc<dyn SystemExecutor>,
    plugin_ids: &[PluginId],
    dry_run: bool,
    hardener_config: &HardenerConfig,
    checkpoint: Option<CheckpointManager>,
    audit: Option<AuditLogger>,
    format: &OutputFormat,
    quiet: bool,
) -> ApplyHostResult {
    // Built per call (not shared): deterministic + gives each concurrent batch-apply
    // host its own registry, since plugin instances aren't shared across tasks.
    let registry = create_plugin_registry();

    let mut ctx = match (dry_run, checkpoint) {
        (false, Some(mgr)) => Context::with_executor_and_checkpoint(executor, mgr),
        _ => Context::with_executor(executor),
    };
    if let Some(logger) = audit {
        ctx.set_audit_logger(logger);
    }

    let mut results = Vec::new();
    let mut validation_reports = Vec::new();
    let mut had_failure = false;
    let mut skipped = Vec::new();

    for plugin_id in plugin_ids {
        let Ok(Some(plugin)) = registry.get(plugin_id) else {
            had_failure = true;
            if !quiet {
                output::error(format, &format!("Plugin not found: {}", plugin_id.as_str()));
            }
            continue;
        };

        let id_str = plugin_id.as_str();
        // One predicate, shared with `scan`. This site used to carry its own
        // narrower copy reading only `[global] disabled_plugins`, so a plugin
        // its own section disabled, or one absent from a non-empty
        // `enabled_plugins`, was hardened by a command that had already
        // stopped showing it in a scan.
        if !hardener_config.is_plugin_enabled(id_str) {
            if !quiet {
                output::status(format, &format!("Skipping (disabled): {id_str}"));
            }
            skipped.push(plugin_id.clone());
            continue;
        }

        let plugin_config = hardener_config.get_plugin_config(id_str);
        let metadata = plugin.metadata();

        if !quiet {
            let verb = if dry_run { "Validating" } else { "Applying" };
            output::status(format, &format!("{verb}: {}", metadata.plugin_name));
        }

        if dry_run {
            match plugin.validate(&ctx, plugin_config).await {
                Ok(report) => {
                    // A dry run that could not validate is not a clean dry
                    // run. Without this, an unreadable config renders as
                    // "0 change(s) to apply" and exits 0, so the operator is
                    // told the host needs nothing when it was never read.
                    if report.has_blocking_issue() {
                        had_failure = true;
                    }
                    validation_reports.push(report);
                }
                Err(e) => {
                    had_failure = true;
                    if !quiet {
                        output::error(
                            format,
                            &format!("Validation failed for {}: {e}", metadata.plugin_name),
                        );
                    }
                }
            }
        } else {
            match plugin.apply(&mut ctx, plugin_config).await {
                Ok(result) => results.push((metadata, result)),
                Err(e) => {
                    had_failure = true;
                    if !quiet {
                        output::error(
                            format,
                            &format!("Failed to apply {}: {e}", metadata.plugin_name),
                        );
                    }
                }
            }
        }
    }

    if results.iter().any(|(_, r)| !r.apply_success) {
        had_failure = true;
    }

    if let Some(logger) = ctx.audit_logger() {
        let user = super::state::effective_user();
        for (metadata, result) in &results {
            let action_result = if result.apply_success {
                ActionResult::Success
            } else {
                ActionResult::Failure
            };
            let _ = logger
                .log_action(
                    ActionType::Apply,
                    user.clone(),
                    metadata.plugin_name.clone(),
                    action_result,
                )
                .await;
        }
    }

    ApplyHostResult {
        results,
        validation_reports,
        had_failure,
        skipped,
    }
}

pub async fn run(
    plugin_filter: &[String],
    all: bool,
    dry_run: bool,
    format: OutputFormat,
    quiet: bool,
    config_path: Option<&std::path::PathBuf>,
    executor: Arc<dyn SystemExecutor>,
) -> Result<()> {
    // Must be privileged (on the target session, local or remote) to apply changes
    if !dry_run && !is_privileged(executor.as_ref()).await {
        bail!(
            "Root privileges required to apply hardening changes. \
             Use sudo (or connect as root with --ssh) or --dry-run."
        );
    }

    if plugin_filter.is_empty() && !all {
        bail!("Specify plugins with --plugin or use --all to apply all plugins.");
    }

    // A path the operator named is load-bearing policy: it selects which
    // plugins write, the values they write and the violations deliberately left
    // alone, so failing over to defaults would harden this host against a
    // policy nobody asked for. Refuse instead, as `scan` and `report` already
    // do for the same flag. Without the flag a broken *default* config still
    // degrades to defaults, which is the behaviour that shipped.
    let hardener_config = match super::config_loader(config_path).load() {
        Ok(config) => config,
        Err(e) if config_path.is_some() => bail!("Config error: {e}"),
        Err(e) => {
            if !quiet {
                output::warning(&format, &format!("Config load failed, using defaults: {e}"));
            }
            HardenerConfig::default()
        }
    };

    let registry = create_plugin_registry();
    let plugins = registry.list()?;
    let plugin_ids: Vec<PluginId> = if all {
        plugins.iter().map(|m| m.plugin_id.clone()).collect()
    } else {
        super::plugin_filter::expand(&plugins, plugin_filter)?
    };

    if dry_run {
        output::info(&format, "Dry run - no changes will be made");
    }

    let checkpoint = if dry_run {
        None
    } else {
        Some(get_checkpoint_manager().await?)
    };
    let audit = get_audit_logger().await;
    let result = apply_host(
        executor,
        &plugin_ids,
        dry_run,
        &hardener_config,
        checkpoint,
        audit,
        &format,
        quiet,
    )
    .await;

    // Exiting 0 having hardened nothing is a positive claim about the host that
    // this run has not earned. `scan` already refuses the same situation.
    if result.nothing_ran() {
        bail!(
            "Config disabled every selected plugin ({}). Nothing was applied. \
             Remove them from [global] disabled_plugins, set enabled = true in \
             their own section, or select a plugin the config enables.",
            result.skipped_list()
        );
    }

    if dry_run {
        output::validation_reports(&format, &result.validation_reports);
    } else {
        output::apply_results(&format, &result.results);
    }

    if result.had_failure {
        bail!("One or more plugins failed to apply");
    }

    Ok(())
}

#[cfg(test)]
mod tests;
