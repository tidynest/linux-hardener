//! Shared state initialisation - database and signing key paths

use anyhow::Result;
use hardener_state::signing::repair_narrowed_directory_mode;
use hardener_state::{CheckpointManager, CheckpointSigner, init_db};
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Root signing key directory, separate from checkpoint data.
const SYSTEM_KEY_DIR: &str = "/etc/linux-hardener";

/// Root checkpoint data directory.
const SYSTEM_DATA_DIR: &str = "/var/lib/linux-hardener";

/// Legacy key path (pre-separation) for migration.
const LEGACY_KEY_PATH: &str = "/var/lib/linux-hardener/signing.key";

/// Returns (db_path, key_path) based on effective UID.
///
/// Root context separates the signing key from the database:
///   - Key: `/etc/linux-hardener/signing.key` (credential)
///   - DB:  `/var/lib/linux-hardener/checkpoints.db` (state)
///
/// Non-root keeps both in  the user data directory where there is
/// no privilege boundary to enforce separation.
fn resolve_paths() -> Result<(PathBuf, PathBuf)> {
    if nix::unistd::getuid().is_root() {
        let db_path = PathBuf::from(SYSTEM_DATA_DIR).join("checkpoints.db");
        let key_path = PathBuf::from(SYSTEM_KEY_DIR).join("signing.key");

        prepare_root_dirs(Path::new(SYSTEM_KEY_DIR), Path::new(SYSTEM_DATA_DIR))?;

        migrate_key_from(Path::new(LEGACY_KEY_PATH), &key_path)?;

        Ok((db_path, key_path))
    } else {
        let data_dir = dirs::data_local_dir()
            .map(|p| p.join("linux-hardener"))
            .unwrap_or_else(|| PathBuf::from(".linux-hardener"));
        fs::create_dir_all(&data_dir)?;
        Ok((
            data_dir.join("checkpoints.db"),
            data_dir.join("signing.key"),
        ))
    }
}

/// Creates the two root directories and settles their modes.
///
/// Taking both paths as arguments is what makes the modes assertable: the
/// caller's own are absolute and privileged, so nothing unprivileged can
/// exercise them, and the modes are the entire content of this function.
///
/// The key directory is `/etc/linux-hardener`, which holds `config.toml` as
/// well as the signing key, so it keeps the 0755 the package installed. This
/// used to force it to 0700 and hide the configuration from every unprivileged
/// reader; [`repair_narrowed_directory_mode`] undoes that on hosts where it
/// already happened. The key file's own 0400 is unchanged and is what protects
/// it. The data directory has no such second role, so it is still set outright.
fn prepare_root_dirs(key_dir: &Path, data_dir: &Path) -> Result<()> {
    fs::create_dir_all(key_dir)?;
    repair_narrowed_directory_mode(key_dir);
    fs::create_dir_all(data_dir)?;
    let _ = fs::set_permissions(data_dir, fs::Permissions::from_mode(0o755));
    Ok(())
}

/// Moves the signing key from the legacy co-located path if it exists at the
/// old location but not at the new one.
///
/// The second half of that condition is the whole of it, and it was inverted:
/// the test read `new_path.exists()`, so the migration ran only in the one case
/// where it must not and never ran in the case it exists for. Both readings
/// destroy the ability to restore, which is the only thing a checkpoint is for.
///
/// Migrating onto a key that is already there overwrites the key that signed
/// every checkpoint taken since the separation, and deletes the legacy one
/// afterwards, so neither key survives to verify its own signatures. Not
/// migrating when the new path is empty leaves the legacy key in place while
/// [`CheckpointSigner::new_with_path`] mints a fresh one for the empty path, so
/// every checkpoint taken before the upgrade fails its signature check and
/// `rollback` refuses it.
fn migrate_key_from(legacy: &std::path::Path, new_path: &std::path::Path) -> Result<()> {
    if !legacy.exists() || new_path.exists() {
        return Ok(());
    }

    fs::copy(legacy, new_path)?;
    // Restrictive mode - read-only for root
    fs::set_permissions(
        new_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o400),
    )?;
    fs::remove_file(legacy)?;
    Ok(())
}

/// Opens the checkpoint database and its signer at the paths
/// [`resolve_paths`] chose for this user, migrating a pre-separation key first.
pub async fn get_checkpoint_manager() -> Result<CheckpointManager> {
    let (db_path, key_path) = resolve_paths()?;
    let pool = init_db(Some(db_path.as_path())).await?;
    let signer = CheckpointSigner::new_with_path(&key_path)?;
    Ok(CheckpointManager::new_with_signer(pool, signer)?)
}

/// Root audit log directory for privileged operations.
const SYSTEM_LOG_DIR: &str = "/var/log/linux-hardener";

/// Returns the effective username for audit logging.
pub fn effective_user() -> String {
    nix::unistd::User::from_uid(nix::unistd::getuid())
        .ok()
        .flatten()
        .map(|user| user.name)
        .unwrap_or_else(|| format!("uid:{}", nix::unistd::getuid()))
}

/// Opens an [`AuditLogger`] writing `audit.log` under `dir`, creating the
/// directory (and restricting it to `mode`, when given) first.
///
/// Every failure carries the path it was working on, because "audit logging
/// unavailable" with no location is not actionable.
async fn audit_logger_in(
    dir: &std::path::Path,
    mode: Option<u32>,
) -> Result<hardener_state::AuditLogger> {
    use anyhow::Context;

    fs::create_dir_all(dir)
        .with_context(|| format!("creating audit log directory {}", dir.display()))?;
    if let Some(mode) = mode {
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(mode));
    }

    let path = dir.join("audit.log");
    hardener_state::AuditLogger::new(&path.to_string_lossy())
        .await
        .with_context(|| format!("opening audit log {}", path.display()))
}

/// Creates an [`AuditLogger`] at the appropriate path.
///
/// Root: `/var/log/linux-hardener/audit.log` (0700 directory)
/// Non-root: `$XDG_DATA_HOME/linux-hardener/audit.log`
pub async fn audit_logger() -> Result<hardener_state::AuditLogger> {
    if nix::unistd::getuid().is_root() {
        audit_logger_in(std::path::Path::new(SYSTEM_LOG_DIR), Some(0o700)).await
    } else {
        // The user data directory holds more than this log, so its mode is
        // left to whatever created it.
        let dir = dirs::data_local_dir()
            .map(|p| p.join("linux-hardener"))
            .unwrap_or_else(|| PathBuf::from(".linux-hardener"));
        audit_logger_in(&dir, None).await
    }
}

/// The audit logger, or `None` after telling the operator there will be no
/// audit trail.
///
/// Callers continue without one: refusing to harden a host because its log
/// directory is unwritable would be the worse failure. What must not happen
/// is the previous behaviour, where every failure folded to `None` and a
/// privileged `apply`, `checkpoint` or `batch` ran with the audit trail
/// silently absent. The notice goes to stderr so `--format json` stdout
/// stays parseable.
pub async fn get_audit_logger() -> Option<hardener_state::AuditLogger> {
    match audit_logger().await {
        Ok(logger) => Some(logger),
        Err(e) => {
            tracing::warn!("audit logging unavailable: {e:#}");
            eprintln!("W  Audit logging unavailable: {e:#}");
            eprintln!("   This operation will not be recorded in the audit trail.");
            None
        }
    }
}

#[cfg(test)]
mod tests;
