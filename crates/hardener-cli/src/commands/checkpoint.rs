//! Checkpoint commands: create, list, show, delete, and rollback operations.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, bail};
use hardener_core::{Context, SystemExecutor, executor::host_key_for};
use hardener_state::{ActionResult, ActionType, CheckpointId};
use hardener_types::RollbackResult;

use crate::cli::OutputFormat;
use crate::output;

use super::privilege::is_privileged;
use super::state::{effective_user, get_audit_logger, get_checkpoint_manager};

pub async fn list(
    format: OutputFormat,
    _quiet: bool,
    executor: Arc<dyn SystemExecutor>,
    limit: usize,
    all: bool,
) -> Result<()> {
    let manager = get_checkpoint_manager().await?;
    let current_host = host_key_for(executor.as_ref());

    // `list_checkpoints` returns newest-first (ORDER BY timestamp DESC); the
    // host filter preserves that order, so the renderer's cap keeps the newest.
    let checkpoints: Vec<_> = manager
        .list_checkpoints()
        .await?
        .into_iter()
        .filter(|c| c.host_key == current_host)
        .collect();

    output::checkpoint_list(&format, &checkpoints, limit, all);
    Ok(())
}

pub async fn create(
    name: &str,
    format: OutputFormat,
    quiet: bool,
    executor: Arc<dyn SystemExecutor>,
) -> Result<()> {
    if !is_privileged(executor.as_ref()).await {
        bail!("Root privileges required to create checkpoints.");
    }

    let manager = get_checkpoint_manager().await?;

    // Collect common config file paths to snapshot
    let paths = collect_config_paths();

    if !quiet {
        output::status(&format, &format!("Creating checkpoint: {}", name));
    }

    let checkpoint_id = manager
        .create_checkpoint(executor.as_ref(), name, &paths)
        .await?;

    if let Some(logger) = get_audit_logger().await {
        let _ = logger
            .log_action(
                ActionType::CheckpointCreate,
                effective_user(),
                name.to_string(),
                ActionResult::Success,
            )
            .await;
    }

    output::checkpoint_created(&format, &checkpoint_id);
    Ok(())
}

pub async fn delete(checkpoint_id: &str, format: OutputFormat, quiet: bool) -> Result<()> {
    let manager = get_checkpoint_manager().await?;
    let id = CheckpointId::new(checkpoint_id);

    if !quiet {
        output::status(&format, &format!("Deleting checkpoint: {checkpoint_id}"));
    }

    manager.delete_checkpoint(&id).await?;

    if let Some(logger) = get_audit_logger().await {
        let _ = logger
            .log_action(
                ActionType::CheckpointDelete,
                effective_user(),
                checkpoint_id.to_string(),
                ActionResult::Success,
            )
            .await;
    }

    Ok(())
}

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
) -> Result<()> {
    if !is_privileged(executor.as_ref()).await {
        bail!("Root privileges required to rollback changes.");
    }

    let manager = get_checkpoint_manager().await?;
    let id = CheckpointId::new(checkpoint_id);

    if !quiet {
        output::status(
            &format,
            &format!("Rolling back to checkpoint: {checkpoint_id}"),
        );
    }

    let mut result = manager.rollback(executor.as_ref(), &id).await?;

    // Restoring the bytes is only half of a rollback: until the services that
    // read them are asked to re-read, the machine keeps running the
    // configuration the operator just undid.
    let restored: Vec<PathBuf> = result
        .rollback_files
        .iter()
        .filter(|f| f.restore_success)
        .map(|f| PathBuf::from(&f.restore_path))
        .collect();
    let ctx = Context::with_executor(Arc::clone(&executor));
    let registry = hardener_plugins::create_plugin_registry();
    result.rollback_reloads =
        hardener_plugins::reload_plugins_after_rollback(&ctx, &registry, &restored).await;

    output::rollback_result(&format, &result);

    let reason = rollback_failure_reason(&result);
    let action_result = match reason {
        None => ActionResult::Success,
        Some(_) => ActionResult::Failure,
    };
    if let Some(logger) = get_audit_logger().await {
        let _ = logger
            .log_action(
                ActionType::Rollback,
                effective_user(),
                checkpoint_id.to_string(),
                action_result,
            )
            .await;
    }

    match reason {
        None => Ok(()),
        Some(FailureReason::Files) => {
            bail!("Rollback completed with errors: some files were not restored")
        }
        Some(FailureReason::Reload) => bail!(
            "Files were restored, but a service did not reload and is still running the previous configuration"
        ),
    }
}

/// Which half of a rollback failed, so the operator is told the one that
/// changes what they do next: files not restored is a different problem from
/// files restored that a service would not take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureReason {
    Files,
    Reload,
}

pub fn rollback_failure_reason(result: &RollbackResult) -> Option<FailureReason> {
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
