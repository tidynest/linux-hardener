//! Checkpoint manager for creating and managing system state snapshots.

use crate::checkpoint::{
    CheckpointId, FileRestoreAction, FileRestoreResult, FileState, RollbackResult,
};
use crate::{Checkpoint, CheckpointSigner};
use hardener_common::error::{HardeningError, Result};
use hardener_common::executor::SystemExecutor;
use sqlx::{Row, SqlitePool};
use std::path::Path;

/// Default rollback path prefixes for production use.
///
/// Paths match via `starts_with`, so `/etc/ssh` covers both
/// `/etc/ssh` itself and any file beneath it (e.g. `/etc/ssh/sshd_config`).
/// Trailing slashes are intentionally omitted for this reason.
const DEFAULT_ROLLBACK_PREFIXES: &[&str] = &[
    "/etc/ssh",
    "/etc/sysctl",
    "/etc/security",
    "/etc/pam.d",
    "/etc/audit",
    "/etc/apparmor",
    "/etc/selinux",
    "/etc/login.defs",
    "/etc/nftables",
    "/etc/firewalld",
    "/etc/ufw",
    "/etc/sudoers",
    "/root",
    "/boot",
];

/// Bundled header fields passed to `store_checkpoint` to stay within the argument-count lint.
struct CheckpointHeader<'a> {
    id: &'a CheckpointId,
    name: &'a str,
    timestamp: i64,
    username: &'a str,
    signature: &'a [u8],
    host_key: &'a str,
}

/// Manages checkpoint creation, storage, and retrieval.
///
/// The CheckpointManager handles all operations related to checkpoints,
/// including creating snapshots of file states and storing them in the database.
pub struct CheckpointManager {
    /// Database connection pool.
    db_pool: SqlitePool,
    /// Cryptographic signer for checkpoint integrity
    signer: CheckpointSigner,
    /// Allowed path prefixes for rollback file writes.
    allowed_rollback_prefixes: Vec<String>,
}

impl CheckpointManager {
    /// Creates a new CheckpointManager, loading the signing key from the default path.
    ///
    /// # Errors
    /// Returns an error if the signing key cannot be loaded or generated.
    pub fn new(db_pool: SqlitePool) -> Result<CheckpointManager> {
        let signer = CheckpointSigner::new()?;
        Ok(Self {
            db_pool,
            signer,
            allowed_rollback_prefixes: DEFAULT_ROLLBACK_PREFIXES
                .iter()
                .map(|prefix| prefix.to_string())
                .collect(),
        })
    }

    /// Creates a new CheckpointManager with a custom signer.
    ///
    /// This is primarily used for testing to avoid requiring root permissions.
    pub fn new_with_signer(
        db_pool: SqlitePool,
        signer: CheckpointSigner,
    ) -> Result<CheckpointManager> {
        Ok(Self {
            db_pool,
            signer,
            allowed_rollback_prefixes: DEFAULT_ROLLBACK_PREFIXES
                .iter()
                .map(|prefix| prefix.to_string())
                .collect(),
        })
    }

    /// Creates a CheckpointManager with custom rollback path prefixes.
    ///
    /// Allows tests and specialised deployments to override the default
    /// allowlist without weakening production security.
    pub fn new_with_allowlist(
        db_pool: SqlitePool,
        signer: CheckpointSigner,
        allowed_prefixes: Vec<String>,
    ) -> Result<CheckpointManager> {
        Ok(Self {
            db_pool,
            signer,
            allowed_rollback_prefixes: allowed_prefixes,
        })
    }

    /// Generates a unique checkpoint ID.
    ///
    /// Uses a timestamp-based approach for sortable IDs.
    fn generate_checkpoint_id() -> CheckpointId {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        // Format: checkpoint_<timestamp>_<random>
        let random_suffix: u32 = rand::random();
        CheckpointId::new(format!("cp_{}_{:08x}", timestamp, random_suffix))
    }

    /// Captures the current state of a single file (not a directory) via the executor.
    ///
    /// Records file content, permissions, and ownership.  An unreadable file's content
    /// is stored as `None`; absent files are represented with all-zero metadata.
    async fn capture_single_file(
        &self,
        executor: &dyn SystemExecutor,
        file_path: &Path,
    ) -> Result<FileState> {
        let meta = executor
            .file_metadata(file_path)
            .await
            .map_err(|e| HardeningError::System(std::io::Error::other(e)))?;

        if !meta.exists {
            return Ok(FileState {
                file_path: file_path.to_string_lossy().to_string(),
                file_content: None,
                file_permissions: 0,
                file_owner_uid: 0,
                file_owner_gid: 0,
            });
        }

        // Content is best-effort: unreadable files are stored with content=None.
        let file_content = executor
            .read_file(file_path)
            .await
            .ok()
            .map(|s| s.into_bytes());

        Ok(FileState {
            file_path: file_path.to_string_lossy().to_string(),
            file_content,
            file_permissions: meta.mode,
            file_owner_uid: meta.uid,
            file_owner_gid: meta.gid,
        })
    }

    /// Captures metadata for a path without reading contents.
    ///
    /// Records permissions and ownership but sets `file_content` to `None`.
    /// The directory type bit (`0o40000`) in `file_permissions` distinguishes
    /// this from "didn't exist" entries (which have `file_permissions: 0`).
    async fn capture_directory_entry(
        &self,
        executor: &dyn SystemExecutor,
        dir_path: &Path,
    ) -> Result<FileState> {
        let meta = executor
            .file_metadata(dir_path)
            .await
            .map_err(|e| HardeningError::System(std::io::Error::other(e)))?;

        if !meta.exists {
            return Ok(FileState {
                file_path: dir_path.to_string_lossy().to_string(),
                file_content: None,
                file_permissions: 0,
                file_owner_uid: 0,
                file_owner_gid: 0,
            });
        }

        Ok(FileState {
            file_path: dir_path.to_string_lossy().to_string(),
            file_content: None,
            file_permissions: meta.mode,
            file_owner_uid: meta.uid,
            file_owner_gid: meta.gid,
        })
    }

    /// Captures the current state of a file or directory via the executor.
    ///
    /// If the path is a directory, recursively captures all files within it.
    /// Records file content, permissions, and ownership for each file.
    async fn capture_file_state(
        &self,
        executor: &dyn SystemExecutor,
        file_path: &Path,
    ) -> Result<Vec<FileState>> {
        let meta = executor
            .file_metadata(file_path)
            .await
            .map_err(|e| HardeningError::System(std::io::Error::other(e)))?;

        if !meta.exists {
            return Ok(vec![FileState {
                file_path: file_path.to_string_lossy().to_string(),
                file_content: None,
                file_permissions: 0,
                file_owner_uid: 0,
                file_owner_gid: 0,
            }]);
        }

        if meta.is_dir {
            self.capture_directory_recursive(executor, file_path).await
        } else {
            Ok(vec![self.capture_single_file(executor, file_path).await?])
        }
    }

    /// Recursively captures all files within a directory via the executor.
    async fn capture_directory_recursive(
        &self,
        executor: &dyn SystemExecutor,
        dir_path: &Path,
    ) -> Result<Vec<FileState>> {
        let mut file_states = vec![self.capture_directory_entry(executor, dir_path).await?];

        let children = executor
            .read_dir(dir_path)
            .await
            .map_err(|e| HardeningError::System(std::io::Error::other(e)))?;

        for child in children {
            let child_meta = executor
                .file_metadata(&child)
                .await
                .map_err(|e| HardeningError::System(std::io::Error::other(e)))?;

            if child_meta.is_dir {
                let sub_states =
                    Box::pin(self.capture_directory_recursive(executor, &child)).await?;
                file_states.extend(sub_states);
            } else {
                file_states.push(self.capture_single_file(executor, &child).await?);
            }
        }

        Ok(file_states)
    }

    /// Computes an SHA-256 digest over checkpoint metadata and file contents.
    ///
    /// Shared by both signing (at checkpoint creation) and verification
    /// (at rollback) to ensure identical digest computation.
    fn generate_digest(
        checkpoint_id: &CheckpointId,
        checkpoint_name: &str,
        checkpoint_timestamp: i64,
        checkpoint_username: &str,
        file_states: &[FileState],
    ) -> Vec<u8> {
        use ring::digest::{Context as DigestContext, SHA256};

        let mut hash_context = DigestContext::new(&SHA256);
        hash_context.update(checkpoint_id.as_str().as_bytes());
        hash_context.update(checkpoint_name.as_bytes());
        hash_context.update(&checkpoint_timestamp.to_be_bytes());
        hash_context.update(checkpoint_username.as_bytes());

        // Sort by path for deterministic ordering regardless of DB row order
        let mut sorted_states: Vec<&FileState> = file_states.iter().collect();
        sorted_states.sort_by_key(|s| &s.file_path);

        for file_state in sorted_states {
            hash_context.update(file_state.file_path.as_bytes());
            if let Some(content) = &file_state.file_content {
                hash_context.update(content);
            }
            hash_context.update(&file_state.file_permissions.to_be_bytes());
            hash_context.update(&file_state.file_owner_uid.to_be_bytes());
            hash_context.update(&file_state.file_owner_gid.to_be_bytes());
        }

        // Finalise the hash
        hash_context.finish().as_ref().to_vec()
    }

    /// Generates a cryptographic signature for checkpoint integrity.
    ///
    /// The signature covers checkpoint metadata and hashes of all file contents.
    ///
    /// # Security Implications
    /// This creates a tamper-proof record. Any modification to checkpoint data
    /// or file contents will cause signature verification to fail.
    fn generate_signature(
        &self,
        checkpoint_id: &CheckpointId,
        checkpoint_name: &str,
        checkpoint_timestamp: i64,
        checkpoint_username: &str,
        file_states: &[FileState],
    ) -> Result<Vec<u8>> {
        let digest = Self::generate_digest(
            checkpoint_id,
            checkpoint_name,
            checkpoint_timestamp,
            checkpoint_username,
            file_states,
        );
        self.signer.sign(&digest)
    }

    /// Creates a new checkpoint capturing the state of the specified files.
    ///
    /// File content, permissions, and ownership are read via `executor`, so the
    /// snapshot reflects the state of the host that executor targets.
    ///
    /// # Arguments
    /// * `executor` - Executor for file I/O (local or remote via SSH)
    /// * `checkpoint_name` - Human-readable label for this checkpoint
    /// * `file_paths` - Paths to capture (directories are captured recursively)
    ///
    /// # Errors
    /// Returns an error if files cannot be read or the database operation fails.
    pub async fn create_checkpoint(
        &self,
        executor: &dyn SystemExecutor,
        checkpoint_name: &str,
        file_paths: &[&Path],
    ) -> Result<CheckpointId> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let checkpoint_id = Self::generate_checkpoint_id();
        let checkpoint_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let checkpoint_username = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
        let host_key = if executor.is_remote() {
            executor.description()
        } else {
            "local".to_string()
        };

        let mut file_states = Vec::new();
        for file_path in file_paths {
            let states = self.capture_file_state(executor, file_path).await?;
            file_states.extend(states);
        }

        let checkpoint_signature = self.generate_signature(
            &checkpoint_id,
            checkpoint_name,
            checkpoint_timestamp,
            &checkpoint_username,
            &file_states,
        )?;

        let header = CheckpointHeader {
            id: &checkpoint_id,
            name: checkpoint_name,
            timestamp: checkpoint_timestamp,
            username: &checkpoint_username,
            signature: &checkpoint_signature,
            host_key: &host_key,
        };
        self.store_checkpoint(header, &file_states).await?;

        Ok(checkpoint_id)
    }

    /// Creates a checkpoint capturing only metadata (permissions/ownership) for each path.
    ///
    /// Unlike `create_checkpoint`, this does not read file contents or recurse into
    /// directories. Suitable for plugins that only modify mode bits or ownership.
    pub async fn create_checkpoint_metadata_only(
        &self,
        executor: &dyn SystemExecutor,
        checkpoint_name: &str,
        file_paths: &[&Path],
    ) -> Result<CheckpointId> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let checkpoint_id = Self::generate_checkpoint_id();
        let checkpoint_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let checkpoint_username = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
        let host_key = if executor.is_remote() {
            executor.description()
        } else {
            "local".to_string()
        };

        let mut file_states = Vec::new();
        for file_path in file_paths {
            file_states.push(self.capture_directory_entry(executor, file_path).await?);
        }

        let checkpoint_signature = self.generate_signature(
            &checkpoint_id,
            checkpoint_name,
            checkpoint_timestamp,
            &checkpoint_username,
            &file_states,
        )?;

        let header = CheckpointHeader {
            id: &checkpoint_id,
            name: checkpoint_name,
            timestamp: checkpoint_timestamp,
            username: &checkpoint_username,
            signature: &checkpoint_signature,
            host_key: &host_key,
        };
        self.store_checkpoint(header, &file_states).await?;

        Ok(checkpoint_id)
    }

    /// Stores checkpoint and file states in the database.
    async fn store_checkpoint(
        &self,
        header: CheckpointHeader<'_>,
        file_states: &[FileState],
    ) -> Result<()> {
        let mut tx = self
            .db_pool
            .begin()
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))?;

        // Insert checkpoint metadata
        sqlx::query(
            "INSERT INTO checkpoints (
                id,
                name,
                timestamp,
                username,
                signature,
                created_at,
                host_key
                )
            VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(header.id.as_str())
        .bind(header.name)
        .bind(header.timestamp)
        .bind(header.username)
        .bind(header.signature)
        .bind(header.timestamp)
        .bind(header.host_key)
        .execute(&mut *tx)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

        // Insert file states
        for file_state in file_states {
            sqlx::query(
                "INSERT INTO file_states (
                checkpoint_id,
                file_path,
                content,
                permissions,
                owner_uid,
                owner_gid
                )
                VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(header.id.as_str())
            .bind(&file_state.file_path)
            .bind(&file_state.file_content)
            .bind(file_state.file_permissions)
            .bind(file_state.file_owner_uid as i64)
            .bind(file_state.file_owner_gid as i64)
            .execute(&mut *tx)
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))?;

        Ok(())
    }

    /// Retrieves a checkpoint and its file states by ID.
    ///
    /// # Arguments
    /// * `checkpoint_id` - The checkpoint ID to retrieve
    ///
    /// # Errors
    /// Returns an error if checkpoint doesn't exist or database operation fails.
    pub async fn get_checkpoint(
        &self,
        checkpoint_id: &CheckpointId,
    ) -> Result<(Checkpoint, Vec<FileState>)> {
        // Retrieve checkpoint metadata
        let checkpoint_row = sqlx::query(
            "SELECT
                id,
                name,
                timestamp,
                username,
                signature,
                host_key
            FROM checkpoints WHERE id = ?",
        )
        .bind(checkpoint_id.as_str())
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

        let checkpoint = Checkpoint {
            checkpoint_id: CheckpointId::new(checkpoint_row.get::<String, _>("id")),
            checkpoint_name: checkpoint_row.get("name"),
            checkpoint_timestamp: checkpoint_row.get("timestamp"),
            checkpoint_username: checkpoint_row.get("username"),
            checkpoint_signature: checkpoint_row.get("signature"),
            host_key: checkpoint_row.get("host_key"),
        };

        // Retrieve file states
        let file_rows = sqlx::query(
            "SELECT
                file_path,
                content,
                permissions,
                owner_uid,
                owner_gid
            FROM
                file_states WHERE checkpoint_id = ?
            ORDER BY file_path",
        )
        .bind(checkpoint_id.as_str())
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

        let mut file_states = Vec::new();
        for row in file_rows {
            file_states.push(FileState {
                file_path: row.get("file_path"),
                file_content: row.get("content"),
                file_permissions: row.get::<i64, _>("permissions") as u32,
                file_owner_uid: row.get::<i64, _>("owner_uid") as u32,
                file_owner_gid: row.get::<i64, _>("owner_gid") as u32,
            });
        }

        Ok((checkpoint, file_states))
    }

    /// Lists all checkpoints in the database.
    ///
    /// Returns checkpoints sorted by timestamp (newest first).
    ///
    /// # Errors
    /// Returns an error if database operation fails.
    pub async fn list_checkpoints(&self) -> Result<Vec<Checkpoint>> {
        let rows = sqlx::query(
            "SELECT
                id,
                name,
                timestamp,
                username,
                signature,
                host_key
             FROM checkpoints
             ORDER BY timestamp DESC",
        )
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

        let mut checkpoints = Vec::new();
        for row in rows {
            checkpoints.push(Checkpoint {
                checkpoint_id: CheckpointId::new(row.get::<String, _>("id")),
                checkpoint_name: row.get("name"),
                checkpoint_timestamp: row.get("timestamp"),
                checkpoint_username: row.get("username"),
                checkpoint_signature: row.get("signature"),
                host_key: row.get("host_key"),
            });
        }

        Ok(checkpoints)
    }

    /// Deletes a checkpoint and all its associated file states.
    ///
    /// # Arguments
    /// * `checkpoint_id` - The checkpoint ID to delete
    ///
    /// # Errors
    /// Returns an error if checkpoint doesn't exist or database operation fails.
    pub async fn delete_checkpoint(&self, checkpoint_id: &CheckpointId) -> Result<()> {
        let mut tx = self
            .db_pool
            .begin()
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))?;

        // Delete file states first (foreign key constraint)
        sqlx::query("DELETE FROM file_states WHERE checkpoint_id = ?")
            .bind(checkpoint_id.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))?;

        // Delete checkpoint metadata
        sqlx::query("DELETE FROM checkpoints WHERE id = ?")
            .bind(checkpoint_id.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))?;

        Ok(())
    }

    /// Verifies the cryptographic signature of a checkpoint without restoring files.
    ///
    /// Returns `Ok(())` if the signature is valid, `Err` if verification fails
    /// or the checkpoint data has been tampered with.
    pub async fn verify_checkpoint(&self, checkpoint_id: &CheckpointId) -> Result<()> {
        let (checkpoint, file_states) = self.get_checkpoint(checkpoint_id).await?;

        let digest = Self::generate_digest(
            &checkpoint.checkpoint_id,
            &checkpoint.checkpoint_name,
            checkpoint.checkpoint_timestamp,
            &checkpoint.checkpoint_username,
            &file_states,
        );
        self.signer
            .verify(&digest, &checkpoint.checkpoint_signature)
    }

    /// Restores a single file to its checkpointed state.
    ///
    /// Validates the path against an allowlist and rejects symlinks before
    /// performing any write. Returns the action taken and success/failure.
    fn restore_file_state_tracked(
        &self,
        file_state: &FileState,
    ) -> (FileRestoreAction, Result<()>) {
        use std::{fs, os::unix::fs::PermissionsExt, path::Path};

        let path = Path::new(&file_state.file_path);

        let path_str = &file_state.file_path;
        if !path_str.starts_with('/')
            || path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
            || !self
                .allowed_rollback_prefixes
                .iter()
                .any(|p| path_str.starts_with(p))
        {
            return (
                FileRestoreAction::Skipped,
                Err(HardeningError::Config(format!(
                    "Rollback path outside allowed directories: {path_str}"
                ))),
            );
        }

        if path.is_symlink() {
            if let Ok(resolved) = path.canonicalize() {
                let resolved_str = resolved.to_string_lossy();
                if !self
                    .allowed_rollback_prefixes
                    .iter()
                    .any(|p| resolved_str.starts_with(p))
                {
                    return (
                        FileRestoreAction::Skipped,
                        Err(HardeningError::Config(format!(
                            "Rollback symlink {path_str} resolves outside allowed directories"
                        ))),
                    );
                }
            } else {
                return (
                    FileRestoreAction::Skipped,
                    Err(HardeningError::Config(format!(
                        "Rollback target is a broken symlink: {path_str}"
                    ))),
                );
            }
        }

        // Determine what action this file needs.
        let action = match (&file_state.file_content, path.is_dir()) {
            (Some(_), _) => FileRestoreAction::Restored,
            (None, true) => FileRestoreAction::PermissionsRestored,
            (None, false) if file_state.file_permissions == 0 && path.exists() => {
                FileRestoreAction::Removed
            }
            (None, false) => return (FileRestoreAction::Skipped, Ok(())),
        };

        // Remove files that didn't exist at checkpoint time
        if matches!(action, FileRestoreAction::Removed) {
            let result = fs::remove_file(path).map_err(HardeningError::System);
            return (action, result);
        }

        // Restore file content atomically to prevent partial writes on interruption
        if let Some(content) = &file_state.file_content {
            let content_str = String::from_utf8_lossy(content);
            if let Err(e) = hardener_common::file_utils::update_file_atomically(path, &content_str)
            {
                return (action, Err(e));
            }
        }

        // Restore permissions
        if let Err(e) = fs::set_permissions(
            path,
            fs::Permissions::from_mode(file_state.file_permissions),
        ) {
            return (action, Err(HardeningError::System(e)));
        }

        // Restore ownership
        let chown_result = nix::unistd::chown(
            path,
            Some(nix::unistd::Uid::from_raw(file_state.file_owner_uid)),
            Some(nix::unistd::Gid::from_raw(file_state.file_owner_gid)),
        )
        .map_err(|e| HardeningError::Privilege(format!("Failed to restore ownership: {e}")));

        (action, chown_result)
    }

    /// Restores the system to a previous checkpoint state.
    ///
    /// This will restore all files captured in the checkpoint to their
    /// original state, including content, permissions, and ownership.
    ///
    /// # Arguments
    /// * `checkpoint_id` - The checkpoint ID to restore
    ///
    /// # Security Implications
    /// This function requires root privileges to restore file ownership.
    /// Failed rollbacks may leave the system in an inconsistent state.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Checkpoint doesn't exist
    /// - File restoration fails
    /// - Insufficient privileges
    pub async fn rollback(&self, checkpoint_id: &CheckpointId) -> Result<RollbackResult> {
        // Retrieve checkpoint and all file states
        let (checkpoint, file_states) = self.get_checkpoint(checkpoint_id).await?;

        // Verify checkpoint integrity before restoring files
        let digest = Self::generate_digest(
            &checkpoint.checkpoint_id,
            &checkpoint.checkpoint_name,
            checkpoint.checkpoint_timestamp,
            &checkpoint.checkpoint_username,
            &file_states,
        );
        self.signer
            .verify(&digest, &checkpoint.checkpoint_signature)?;

        // Phase 1: Pre-validate all targets before writing anything.
        // Rejects if any target path fails the allowlist check, preventing a
        // partially-rolled-back inconsistent state. Symlinks are allowed only
        // if their resolved target is also within the allowed prefixes (e.g.
        // Debian symlinks /etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf).
        for fs in &file_states {
            let path = Path::new(&fs.file_path);
            let path_str = &fs.file_path;

            if !path_str.starts_with('/')
                || path
                    .components()
                    .any(|c| c == std::path::Component::ParentDir)
                || !self
                    .allowed_rollback_prefixes
                    .iter()
                    .any(|p| path_str.starts_with(p))
            {
                return Err(HardeningError::Config(format!(
                    "Rollback aborted: path outside allowed directories: {path_str}"
                )));
            }
            if path.is_symlink() {
                let resolved = path.canonicalize().map_err(|e| {
                    HardeningError::Config(format!(
                        "Rollback aborted: cannot resolve symlink {path_str}: {e}"
                    ))
                })?;
                let resolved_str = resolved.to_string_lossy();
                if !self
                    .allowed_rollback_prefixes
                    .iter()
                    .any(|p| resolved_str.starts_with(p))
                {
                    return Err(HardeningError::Config(format!(
                        "Rollback aborted: symlink {path_str} resolves outside allowed directories"
                    )));
                }
            }
        }

        // Phase 2: Apply all file restores (pre-validated).
        let mut all_ok = true;
        let files: Vec<_> = file_states
            .iter()
            .map(|fs| {
                let (action, result) = self.restore_file_state_tracked(fs);
                let success = result.is_ok();
                all_ok &= success;
                FileRestoreResult {
                    restore_path: fs.file_path.clone(),
                    restore_action: action,
                    restore_success: success,
                    restore_error: result.err().map(|e| e.to_string()),
                }
            })
            .collect();

        Ok(RollbackResult {
            rollback_checkpoint_id: checkpoint_id.as_str().to_owned(),
            rollback_checkpoint_name: checkpoint.checkpoint_name,
            rollback_success: all_ok,
            rollback_files: files,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hardener_common::executor::MockExecutor;

    /// Builds a CheckpointManager over a temporary in-memory SQLite database
    /// with a freshly generated signing key — no filesystem privileges needed.
    async fn test_manager() -> CheckpointManager {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("mgr_test.db");
        let db_pool = crate::db::init_db(Some(&db_path)).await.expect("init_db");
        let key_path = dir.path().join("test.key");
        let signer = CheckpointSigner::new_with_path(&key_path).expect("signer");
        // Keep `dir` alive for the duration of the test by leaking it into the heap.
        // The OS reclaims the tempdir when the process exits.
        std::mem::forget(dir);
        CheckpointManager::new_with_signer(db_pool, signer).expect("manager")
    }

    #[tokio::test]
    async fn create_checkpoint_captures_via_executor_and_tags_host() {
        let exec = MockExecutor::new()
            .remote()
            .with_description("ssh://root@h")
            .with_file("/etc/sysctl.conf", "kernel.kptr_restrict = 1\n");

        let manager = test_manager().await;
        let id = manager
            .create_checkpoint(&exec, "t", &[std::path::Path::new("/etc/sysctl.conf")])
            .await
            .expect("create_checkpoint");

        let (cp, file_states) = manager.get_checkpoint(&id).await.expect("get_checkpoint");
        assert_eq!(cp.host_key, "ssh://root@h");
        assert_eq!(file_states.len(), 1);
        assert_eq!(
            file_states[0].file_content.as_deref(),
            Some(b"kernel.kptr_restrict = 1\n".as_ref()),
        );
        assert!(
            exec.log()
                .files_read
                .iter()
                .any(|p| p.ends_with("sysctl.conf"))
        );
    }

    #[tokio::test]
    async fn local_executor_tags_host_key_as_local() {
        let exec = MockExecutor::new().with_file("/etc/test.conf", "v=1\n");

        let manager = test_manager().await;
        let id = manager
            .create_checkpoint(
                &exec,
                "local-test",
                &[std::path::Path::new("/etc/test.conf")],
            )
            .await
            .expect("create_checkpoint");

        let (cp, _) = manager.get_checkpoint(&id).await.expect("get_checkpoint");
        assert_eq!(cp.host_key, "local");
    }

    #[tokio::test]
    async fn absent_file_is_captured_as_missing_entry() {
        let exec = MockExecutor::new(); // no files seeded

        let manager = test_manager().await;
        let id = manager
            .create_checkpoint(
                &exec,
                "absent",
                &[std::path::Path::new("/etc/no-such-file")],
            )
            .await
            .expect("create_checkpoint");

        let (_, file_states) = manager.get_checkpoint(&id).await.expect("get_checkpoint");
        assert_eq!(file_states.len(), 1);
        assert!(file_states[0].file_content.is_none());
        assert_eq!(file_states[0].file_permissions, 0);
    }

    #[tokio::test]
    async fn metadata_only_checkpoint_stores_no_content() {
        let exec = MockExecutor::new().with_directory("/etc/pam.d");

        let manager = test_manager().await;
        let id = manager
            .create_checkpoint_metadata_only(
                &exec,
                "meta-only",
                &[std::path::Path::new("/etc/pam.d")],
            )
            .await
            .expect("create_checkpoint_metadata_only");

        let (_, file_states) = manager.get_checkpoint(&id).await.expect("get_checkpoint");
        assert_eq!(file_states.len(), 1);
        assert!(file_states[0].file_content.is_none());
        assert_ne!(file_states[0].file_permissions, 0);
    }

    #[tokio::test]
    async fn list_checkpoints_includes_host_key() {
        let exec = MockExecutor::new()
            .remote()
            .with_description("ssh://root@target")
            .with_file("/etc/ssh/sshd_config", "Port 22\n");

        let manager = test_manager().await;
        manager
            .create_checkpoint(
                &exec,
                "listed",
                &[std::path::Path::new("/etc/ssh/sshd_config")],
            )
            .await
            .expect("create_checkpoint");

        let list = manager.list_checkpoints().await.expect("list_checkpoints");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].host_key, "ssh://root@target");
    }
}
