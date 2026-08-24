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

// The audit log's location, the effective user and the config writer all live
// in `hardener_core::config_write` now. They moved because `hardener-cli` is a
// binary and the desktop backend needs the same three answers: while they were
// here, src-tauri could not reach them and wrote its own configuration
// unaudited. Re-exported so every call site in this crate is unchanged, and so
// there is still one answer to where this host's audit trail lives.
//
// `get_audit_logger` is called from `main.rs` and nowhere else in this crate,
// and that is the rule rather than an accident of the current code. It answers
// with this host's real trail, chosen by uid, so any command that resolved its
// own could be driven by a test straight into the invoking user's audit log.
// `exception::add` did exactly that until 2026-08-24 and filed 126 real
// entries. Every command now takes an `Option<AuditLogger>` and the dispatch
// supplies it, which makes the rule checkable:
//
//     git grep -c 'get_audit_logger[(]' -- crates/hardener-cli/src
//
// should answer `main.rs:13` and name no other file.
//
// Both oddities in that pattern are load-bearing, and each was found by the
// previous spelling failing. Without the bracketed paren at all, it matches
// every doc comment discussing the rule as readily as every call: 21 lines
// across 5 files, 8 of them prose, which reads at a glance as the rule being
// broken in `exception.rs`, `scope.rs` and `systemd.rs`, where it holds. With a
// plain `()` instead, it matches this very line, so the check reports the file
// documenting it as a second call site. The character class matches a literal
// `(` and is not itself one, so the command can be written down inside the
// thing it checks.
//
// A check that cannot tell a violation from a sentence about violations is
// answering a different question from the one it was written for.
pub use hardener_core::config_write::{effective_user, get_audit_logger};

#[cfg(test)]
mod tests;
