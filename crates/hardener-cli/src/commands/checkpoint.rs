//! Checkpoint commands — create, list, show, delete, and rollback operations.

use anyhow::{Result, bail};
use hardener_state::CheckpointId;

use crate::cli::OutputFormat;
use crate::output;

use super::state::get_checkpoint_manager;

pub async fn list(format: OutputFormat, _quiet: bool) -> Result<()> {
    let manager = get_checkpoint_manager().await?;
    let checkpoints = manager.list_checkpoints().await?;

    output::checkpoint_list(&format, &checkpoints);
    Ok(())
}

pub async fn create(name: &str, format: OutputFormat, quiet: bool) -> Result<()> {
    if !nix::unistd::geteuid().is_root() {
        bail!("Root privileges required to create checkpoints.");
    }

    let manager = get_checkpoint_manager().await?;

    // Collect common config file paths to snapshot
    let paths = collect_config_paths();

    if !quiet {
        output::status(&format, &format!("Creating checkpoint: {}", name));
    }

    let checkpoint_id = manager.create_checkpoint(name, &paths).await?;

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
    Ok(())
}

pub async fn show(checkpoint_id: &str, format: OutputFormat, _quiet: bool) -> Result<()> {
    let manager = get_checkpoint_manager().await?;
    let id = CheckpointId::new(checkpoint_id);

    let (checkpoint, file_states) = manager.get_checkpoint(&id).await?;

    output::checkpoint_details(&format, &checkpoint, &file_states);
    Ok(())
}

pub async fn rollback(checkpoint_id: &str, format: OutputFormat, quiet: bool) -> Result<()> {
    if !nix::unistd::geteuid().is_root() {
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

    let result = manager.rollback(&id).await?;
    output::rollback_result(&format, &result);

    if !result.rollback_success {
        bail!("Rollback completed with errors");
    }

    Ok(())
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
