//! Apply command: applies hardening changes with dry-run and checkpoint support.

use crate::cli::OutputFormat;
use crate::output;
use anyhow::{Result, bail};
use hardener_common::types::PluginId;
use hardener_core::{
    ApplyResult, ConfigLoader, Context, HardenerConfig, PluginMetadata, SystemExecutor,
    ValidationReport,
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

    for plugin_id in plugin_ids {
        let Ok(Some(plugin)) = registry.get(plugin_id) else {
            had_failure = true;
            if !quiet {
                output::error(format, &format!("Plugin not found: {}", plugin_id.as_str()));
            }
            continue;
        };

        let id_str = plugin_id.as_str();
        if !hardener_config.global.disabled_plugins.is_empty()
            && hardener_config
                .global
                .disabled_plugins
                .iter()
                .any(|d| d == id_str)
        {
            if !quiet {
                output::status(format, &format!("Skipping (disabled): {id_str}"));
            }
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
                Ok(report) => validation_reports.push(report),
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
    }
}

/// Expands a plugin filter (short names like "kernel" or full ids like
/// "kernel-hardening") against the available plugin metadata. Callers decide
/// what an empty filter means (all vs none), so this only maps the explicit list.
pub(crate) fn expand_plugin_ids(all: &[PluginMetadata], filter: &[String]) -> Vec<PluginId> {
    filter
        .iter()
        .filter_map(|f| {
            all.iter()
                .find(|p| {
                    p.plugin_id.as_str() == f || p.plugin_id.as_str().starts_with(&format!("{f}-"))
                })
                .map(|p| p.plugin_id.clone())
        })
        .collect()
}

pub async fn run(
    plugin_filter: &[String],
    all: bool,
    dry_run: bool,
    format: OutputFormat,
    quiet: bool,
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

    let hardener_config = match ConfigLoader::new().load() {
        Ok(config) => config,
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
        expand_plugin_ids(&plugins, plugin_filter)
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
mod tests {
    use super::*;
    use hardener_common::executor::{CommandOutput, MockExecutor};

    /// The gate must ask the executor, not the local process: a non-root
    /// test process talking to an executor that reports uid 1000 and denies
    /// passwordless sudo must bail with the privilege message, and that
    /// message must cover the remote (--ssh) case explicitly.
    #[tokio::test]
    async fn run_bails_with_privilege_message_when_executor_lacks_privilege() {
        let fail = CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 1,
        };
        let executor = Arc::new(
            MockExecutor::new()
                .with_command(
                    "id",
                    &["-u"],
                    CommandOutput {
                        stdout: "1000\n".into(),
                        stderr: String::new(),
                        exit_code: 0,
                    },
                )
                .with_command("sudo", &["-n", "true"], fail),
        );

        let err = run(&[], true, false, OutputFormat::Json, true, executor)
            .await
            .expect_err("non-privileged executor must not be allowed to apply");

        let message = err.to_string();
        assert!(
            message.contains("Root privileges required to apply hardening changes"),
            "unexpected message: {message}"
        );
        assert!(
            message.contains("--ssh"),
            "message should mention the remote case: {message}"
        );
    }

    #[tokio::test]
    async fn apply_host_dry_run_validates_without_mutation() {
        let executor = Arc::new(MockExecutor::new());
        let cfg = HardenerConfig::default();
        let registry = create_plugin_registry();
        let ids: Vec<_> = registry
            .list()
            .unwrap()
            .into_iter()
            .map(|m| m.plugin_id)
            .collect();

        let result = apply_host(
            executor,
            &ids,
            true,
            &cfg,
            None,
            None,
            &OutputFormat::Json,
            true,
        )
        .await;

        assert!(
            result.results.is_empty(),
            "dry-run must not produce apply results"
        );
        // Some plugins may error against a bare MockExecutor (missing files/commands);
        // assert we got at least one validation report and zero apply results.
        assert!(
            !result.validation_reports.is_empty(),
            "dry-run should validate at least one plugin (some plugins error on a bare MockExecutor)"
        );
    }
}
