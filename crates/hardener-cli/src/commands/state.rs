//! Shared state initialisation - database and signing key paths

use anyhow::Result;
use hardener_state::{CheckpointManager, CheckpointSigner, init_db};
use std::os::unix::fs::PermissionsExt;
use std::{fs, path::PathBuf};

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

        fs::create_dir_all(SYSTEM_KEY_DIR)?;
        let _ = fs::set_permissions(SYSTEM_KEY_DIR, fs::Permissions::from_mode(0o700));
        fs::create_dir_all(SYSTEM_DATA_DIR)?;
        let _ = fs::set_permissions(SYSTEM_DATA_DIR, fs::Permissions::from_mode(0o755));

        migrate_legacy_key(&key_path)?;

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

/// Moves the signing key from the legacy co-located path if it exists
/// at the old location but not at the new one.
fn migrate_legacy_key(new_path: &std::path::Path) -> Result<()> {
    let legacy = std::path::Path::new(LEGACY_KEY_PATH);
    if legacy.exists() && new_path.exists() {
        fs::copy(legacy, new_path)?;
        // Restrictive mode - read-only for root
        fs::set_permissions(
            new_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o400),
        )?;
        fs::remove_file(legacy)?;
    }
    Ok(())
}

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
mod tests {
    use super::*;

    /// Every failure used to fold to `None`, so a privileged run simply had
    /// no audit trail and said nothing. The failure must survive as an error
    /// carrying the path, which is what lets the caller report it.
    #[tokio::test]
    async fn an_unusable_audit_directory_produces_an_error_not_silence() {
        let dir = tempfile::tempdir().unwrap();
        // A regular file where a directory belongs: create_dir_all below it
        // fails with ENOTDIR.
        let not_a_dir = dir.path().join("not-a-dir");
        fs::write(&not_a_dir, "regular file").unwrap();

        // AuditLogger has no Debug, so unwrap the Result by hand.
        let message = match audit_logger_in(&not_a_dir.join("logs"), None).await {
            Ok(_) => panic!("an uncreatable audit directory must not fold to success"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            message.contains("audit log directory"),
            "the error must say what it was doing: {message}"
        );
        assert!(
            message.contains("not-a-dir"),
            "the error must name the path: {message}"
        );
    }

    /// The ordinary case still works, so the guard above is not just
    /// rejecting everything.
    #[tokio::test]
    async fn a_usable_directory_opens_the_audit_log() {
        let dir = tempfile::tempdir().unwrap();
        let logger_dir = dir.path().join("audit");

        audit_logger_in(&logger_dir, Some(0o700))
            .await
            .expect("a writable directory must yield a logger");

        assert!(logger_dir.join("audit.log").exists());
    }
}
