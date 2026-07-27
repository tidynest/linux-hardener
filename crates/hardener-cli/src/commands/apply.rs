//! Apply command: applies hardening changes with dry-run and checkpoint support.

use crate::cli::OutputFormat;
use crate::output;
use anyhow::{Result, bail};
use hardener_common::types::{PluginId, Severity};
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
                    if blocking_validation_issue(&report) {
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

/// Whether a validation report carries an issue serious enough to fail the
/// dry run.
///
/// Critical and High only. Lower severities are advisory, and promoting them
/// would turn an informational note into a non-zero exit, which trains
/// operators to ignore the exit code entirely.
fn blocking_validation_issue(report: &ValidationReport) -> bool {
    report.validation_report_issues.iter().any(|issue| {
        matches!(
            issue.validation_issue_severity,
            Severity::Critical | Severity::High
        )
    })
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

    fn report_with(severity: Severity) -> ValidationReport {
        ValidationReport {
            validation_report_plugin_id: PluginId::new("ssh-hardening"),
            validation_report_is_valid: false,
            validation_report_issues: vec![hardener_core::ValidationIssue {
                validation_issue_severity: severity,
                validation_issue_message: "Failed to read /etc/ssh/sshd_config".to_string(),
                validation_issue_config_key: None,
            }],
            validation_report_estimated_changes: vec![],
            validation_report_compliant_count: 0,
            validation_report_exceptions: vec![],
        }
    }

    /// `--dry-run` on an unreadable config produced "0 change(s) to apply"
    /// and exit 0, which an operator reads as "this host needs nothing".
    /// A serious validation issue has to reach the exit code.
    #[test]
    fn a_serious_validation_issue_fails_the_dry_run() {
        assert!(blocking_validation_issue(&report_with(Severity::Critical)));
        assert!(blocking_validation_issue(&report_with(Severity::High)));
    }

    /// Advisory severities must not flip the exit code, or the signal becomes
    /// noise and operators learn to ignore it.
    #[test]
    fn an_advisory_validation_issue_does_not_fail_the_dry_run() {
        assert!(!blocking_validation_issue(&report_with(Severity::Medium)));
        assert!(!blocking_validation_issue(&report_with(Severity::Low)));
        assert!(!blocking_validation_issue(&report_with(Severity::Info)));

        let clean = ValidationReport {
            validation_report_issues: vec![],
            validation_report_is_valid: true,
            ..report_with(Severity::High)
        };
        assert!(!blocking_validation_issue(&clean));
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

    /// `apply` carried its own narrower copy of the enablement rule, reading
    /// only `[global] disabled_plugins`. A host whose config turned ssh off in
    /// its own section was hardened anyway, and `scan` on that same host had
    /// already stopped showing it.
    ///
    /// Neither outcome of running the plugin can pass here: a plugin that
    /// validates contributes a report, and one that errors against the bare
    /// MockExecutor sets `had_failure`. Only skipping it produces both.
    #[tokio::test]
    async fn a_section_disabled_plugin_is_skipped_by_apply() {
        let mut config = HardenerConfig::default();
        config.ssh.enabled = false;

        let result = apply_host(
            Arc::new(MockExecutor::new()),
            &[PluginId::new("ssh-hardening")],
            true,
            &config,
            None,
            None,
            &OutputFormat::Json,
            true,
        )
        .await;

        assert!(
            result.validation_reports.is_empty(),
            "a plugin its own section disables must never be validated"
        );
        assert!(
            !result.had_failure,
            "skipping a disabled plugin is not a failure"
        );
        // Named, not merely absent: `run` refuses to exit 0 when this accounts
        // for every plugin the operator selected.
        assert_eq!(result.skipped, vec![PluginId::new("ssh-hardening")]);
    }

    /// The `[global] enabled_plugins` allow-list is the other half of the same
    /// divergence: `scan` narrowed its selection by it while `apply` ignored it
    /// entirely, so the two commands disagreed about which plugins the config
    /// selects.
    #[tokio::test]
    async fn a_global_allow_list_narrows_apply_too() {
        let mut config = HardenerConfig::default();
        config.global.enabled_plugins = vec!["kernel-hardening".to_string()];

        let result = apply_host(
            Arc::new(MockExecutor::new()),
            &[PluginId::new("ssh-hardening")],
            true,
            &config,
            None,
            None,
            &OutputFormat::Json,
            true,
        )
        .await;

        assert!(
            result.validation_reports.is_empty(),
            "a plugin absent from a non-empty allow-list must never be validated"
        );
        assert!(!result.had_failure);
    }
}
