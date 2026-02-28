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

/// Default audit log path for privileged operations.
const SYSTEM_LOG_PATH: &str = "/var/log/linux-hardener/audit.log";

/// Returns the effective username for audit logging.
pub fn effective_user() -> String {
    nix::unistd::User::from_uid(nix::unistd::getuid())
        .ok()
        .flatten()
        .map(|user| user.name)
        .unwrap_or_else(|| format!("uid:{}", nix::unistd::getuid()))
}

/// Creates an [`AuditLogger`] at the appropriate path.
///
/// Root: `/var/log/linux-hardener/audit.log` (0700 directory)
/// Non-root: `$XDG_DATA_HOME/linux-hardener/audit.log`
pub async fn get_audit_logger() -> Option<hardener_state::AuditLogger> {
    let log_path = if nix::unistd::getuid().is_root() {
        fs::create_dir_all("/var/log/linux-hardener").ok()?;
        let _ = fs::set_permissions(
            "/var/log/linux-hardener",
            fs::Permissions::from_mode(0o700),
        );
        SYSTEM_LOG_PATH.to_string()
    } else {
        let dir = dirs::data_local_dir()
            .map(|p| p.join("linux-hardener"))
            .unwrap_or_else(|| PathBuf::from(".linux-hardener"));
        fs::create_dir_all(&dir).ok()?;
        dir.join("audit.log").to_string_lossy().to_string()
    };

    hardener_state::AuditLogger::new(&log_path).await.ok()
}
