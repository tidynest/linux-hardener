//! Checkpoint commands: create, list, show, delete, and rollback operations.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, bail};
use hardener_core::{Context, SystemExecutor, executor::host_keys_for};
use hardener_state::{ActionType, AuditLogger, CheckpointId};
use hardener_types::RollbackResult;

use crate::cli::OutputFormat;
use crate::output;

use super::privilege::is_privileged;
use super::state::{get_checkpoint_manager, outcome_of, record_outcome};

pub async fn list(
    format: OutputFormat,
    _quiet: bool,
    executor: Arc<dyn SystemExecutor>,
    limit: usize,
    all: bool,
) -> Result<()> {
    let manager = get_checkpoint_manager().await?;
    // Every key this target has ever been filed under, so checkpoints taken
    // before the remote user was resolved stay visible. See `host_keys_for`.
    let host_keys = host_keys_for(executor.as_ref());

    // `list_checkpoints` returns newest-first (ORDER BY timestamp DESC); the
    // host filter preserves that order, so the renderer's cap keeps the newest.
    let checkpoints: Vec<_> = manager
        .list_checkpoints()
        .await?
        .into_iter()
        .filter(|c| host_keys.contains(&c.host_key))
        .collect();

    output::checkpoint_list(&format, &checkpoints, limit, all);
    Ok(())
}

pub async fn create(
    name: &str,
    format: OutputFormat,
    quiet: bool,
    executor: Arc<dyn SystemExecutor>,
    logger: Option<AuditLogger>,
) -> Result<()> {
    if !is_privileged(executor.as_ref()).await {
        bail!("Root privileges required to create checkpoints.");
    }

    create_with(
        get_checkpoint_manager().await?,
        name,
        format,
        quiet,
        executor,
        logger,
    )
    .await
}

/// [`create`] once the privilege gate has passed, on the manager it is given.
///
/// Split off so the manager is an argument, as the logger already is and for
/// the same reason: the name that resolves it answers with this user's own
/// checkpoint database, which a test must not write to.
pub(crate) async fn create_with(
    manager: hardener_state::CheckpointManager,
    name: &str,
    format: OutputFormat,
    quiet: bool,
    executor: Arc<dyn SystemExecutor>,
    logger: Option<AuditLogger>,
) -> Result<()> {
    // Collect common config file paths to snapshot
    let paths = collect_config_paths();

    if !quiet {
        output::status(&format, &format!("Creating checkpoint: {}", name));
    }

    // Recorded either way, as `delete` below does and for its reason: a
    // checkpoint that could not be taken is the attempt the trail most needs.
    let created = manager
        .create_checkpoint(executor.as_ref(), name, &paths)
        .await;
    if let Some(logger) = &logger {
        record_outcome(
            logger,
            ActionType::CheckpointCreate,
            name.to_string(),
            outcome_of(&created),
        )
        .await;
    }
    let checkpoint_id = created?;

    output::checkpoint_created(&format, &checkpoint_id);
    Ok(())
}

pub async fn delete(
    checkpoint_id: &str,
    format: OutputFormat,
    quiet: bool,
    logger: Option<AuditLogger>,
) -> Result<()> {
    let manager = get_checkpoint_manager().await?;
    let id = CheckpointId::new(checkpoint_id);

    if !quiet {
        output::status(&format, &format!("Deleting checkpoint: {checkpoint_id}"));
    }

    // Recorded either way, and before anything is printed. A delete that found
    // no such row is an operator action on the checkpoint store just as much as
    // one that succeeded, and it is the shape a probe takes: returning early on
    // the error would leave the attempt absent from the audit trail entirely,
    // which is the one place it needs to appear. `rollback` and `apply` already
    // log both outcomes.
    let outcome = manager.delete_checkpoint(&id).await;
    if let Some(logger) = &logger {
        record_outcome(
            logger,
            ActionType::CheckpointDelete,
            checkpoint_id.to_string(),
            outcome_of(&outcome),
        )
        .await;
    }
    outcome?;

    output::checkpoint_deleted(&format, &id);
    Ok(())
}

/// Reports the file rows no checkpoint owns, and removes them under `--execute`.
///
/// Reporting is the default because this deletes from the state database, and
/// the fleet verbs set the precedent that a destructive run is asked for
/// explicitly. A clean database is the expected answer: the schema declares the
/// foreign key and `init_db` turns enforcement on, so nothing reaching the
/// database through this tool can strand a row. What it repairs is a database
/// edited by something else, `sqlite3` included, which defaults that
/// enforcement off.
pub async fn repair(
    execute: bool,
    format: OutputFormat,
    quiet: bool,
    logger: Option<AuditLogger>,
) -> Result<()> {
    let manager = get_checkpoint_manager().await?;
    let found = manager.orphaned_file_states().await?;

    if !execute {
        output::checkpoint_repair(&format, found, None);
        return Ok(());
    }

    if !quiet {
        output::status(&format, "Removing orphaned file rows");
    }
    let removed = manager.remove_orphaned_file_states().await?;

    // Logged under the deletion action because that is what it is: rows leave
    // the state database. A run that removed nothing is still recorded, so the
    // trail says the database was inspected and found clean.
    if let Some(logger) = &logger {
        record_outcome(
            logger,
            ActionType::CheckpointDelete,
            format!("orphaned file rows: {removed}"),
            Ok(()),
        )
        .await;
    }

    output::checkpoint_repair(&format, found, Some(removed));
    Ok(())
}

/// Renders one checkpoint's metadata and the files it captured.
pub async fn show(checkpoint_id: &str, format: OutputFormat, _quiet: bool) -> Result<()> {
    let manager = get_checkpoint_manager().await?;
    let id = CheckpointId::new(checkpoint_id);

    let (checkpoint, file_states) = manager.get_checkpoint(&id).await?;

    output::checkpoint_details(&format, &checkpoint, &file_states);
    Ok(())
}

pub async fn rollback(
    checkpoint_id: &str,
    format: OutputFormat,
    quiet: bool,
    executor: Arc<dyn SystemExecutor>,
    logger: Option<AuditLogger>,
) -> Result<()> {
    if !is_privileged(executor.as_ref()).await {
        bail!("Root privileges required to rollback changes.");
    }

    rollback_with(
        get_checkpoint_manager().await?,
        checkpoint_id,
        format,
        quiet,
        executor,
        logger,
    )
    .await
}

/// [`rollback`] once the privilege gate has passed, on the manager it is
/// given. See [`create_with`] for why the manager is an argument.
pub(crate) async fn rollback_with(
    manager: hardener_state::CheckpointManager,
    checkpoint_id: &str,
    format: OutputFormat,
    quiet: bool,
    executor: Arc<dyn SystemExecutor>,
    logger: Option<AuditLogger>,
) -> Result<()> {
    let id = CheckpointId::new(checkpoint_id);

    if !quiet {
        output::status(
            &format,
            &format!("Rolling back to checkpoint: {checkpoint_id}"),
        );
    }

    // A rollback refused outright (no such checkpoint, another host's, a
    // signature that does not verify) has no result to report further down,
    // so it is recorded here. One that did run is recorded below, once the
    // reload has had its say.
    let rolled_back = manager.rollback(executor.as_ref(), &id).await;
    if let (Some(logger), Err(_)) = (&logger, &rolled_back) {
        record_outcome(
            logger,
            ActionType::Rollback,
            checkpoint_id.to_string(),
            outcome_of(&rolled_back),
        )
        .await;
    }
    let mut result = rolled_back?;

    let ctx = Context::with_executor(Arc::clone(&executor));
    let registry = hardener_plugins::create_plugin_registry();
    reload_restored_paths(&ctx, &registry, &mut result).await;

    output::rollback_result(&format, &result);

    // One sentence per failure, used for both the audit entry and the error
    // the operator sees, so the trail and the terminal cannot disagree.
    let outcome = match rollback_failure_reason(&result) {
        None => Ok(()),
        Some(reason) => Err(reason.message().to_string()),
    };
    if let Some(logger) = &logger {
        record_outcome(
            logger,
            ActionType::Rollback,
            checkpoint_id.to_string(),
            outcome.clone(),
        )
        .await;
    }

    outcome.map_err(anyhow::Error::msg)
}

/// Restoring the bytes is only half of a rollback: until the services that
/// read them are asked to re-read, the machine keeps running the
/// configuration the operator just undid.
///
/// Collects the paths that actually came back (a partially restored
/// checkpoint still offers up whatever it managed), asks their plugins to
/// reload, and writes the outcome onto `result`. A checkpoint that restored
/// nothing is left alone rather than dispatched: `reconcile_plugins_after_rollback`
/// still records a `plugin-registry` failure row when the registry cannot be
/// listed, which would otherwise turn a clean no-op into a reported reload
/// failure. Shared by the local and fleet rollback paths so this
/// collect/guard/dispatch/assign sequence exists once.
pub(crate) async fn reload_restored_paths(
    ctx: &Context,
    registry: &hardener_core::PluginRegistry,
    result: &mut RollbackResult,
) {
    let restored: Vec<PathBuf> = result
        .rollback_files
        .iter()
        .filter(|f| f.restore_success)
        .map(|f| PathBuf::from(&f.restore_path))
        .collect();
    if restored.is_empty() {
        return;
    }
    let reconciled =
        hardener_plugins::reconcile_plugins_after_rollback(ctx, registry, &restored).await;
    result.rollback_reloads = reconciled.reloads;
    result.rollback_divergences = reconciled.divergences;
}

/// Which half of a rollback failed, so the operator is told the one that
/// changes what they do next: files not restored is a different problem from
/// files restored that a service would not take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureReason {
    Files,
    Reload,
}

impl FailureReason {
    pub(crate) fn message(self) -> &'static str {
        match self {
            FailureReason::Files => "Rollback completed with errors: some files were not restored",
            FailureReason::Reload => {
                "Files were restored, but a service did not reload and is still running the previous configuration"
            }
        }
    }
}

pub(crate) fn rollback_failure_reason(result: &RollbackResult) -> Option<FailureReason> {
    match (result.rollback_success, result.reloads_ok()) {
        (false, _) => Some(FailureReason::Files),
        (true, false) => Some(FailureReason::Reload),
        (true, true) => None,
    }
}

fn collect_config_paths() -> Vec<&'static std::path::Path> {
    use std::path::Path;
    vec![
        Path::new("/etc/ssh/sshd_config"),
        Path::new("/etc/sysctl.conf"),
        Path::new("/etc/sysctl.d"),
        Path::new("/etc/pam.d"),
        Path::new("/etc/security"),
        Path::new("/etc/audit/auditd.conf"),
        Path::new("/etc/audit/rules.d"),
    ]
}

#[cfg(test)]
mod tests;
