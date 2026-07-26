//! Checkpoint manager for creating and managing system state snapshots.

use crate::checkpoint::{
    CheckpointId, FileRestoreAction, FileRestoreResult, FileState, RollbackResult,
};
use crate::{Checkpoint, CheckpointSigner};
use hardener_common::error::{HardeningError, Result};
use hardener_common::executor::{SystemExecutor, host_key_for};
use hardener_types::UNDELETABLE_ROLLBACK_PATHS;
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
    // Account databases (CIS 6.1.2-6.1.5): checkpointed by the permissions
    // plugin; `starts_with` also covers their `-` backup twins (e.g. /etc/passwd-).
    "/etc/passwd",
    "/etc/group",
    "/etc/shadow",
    "/etc/gshadow",
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
#[derive(Clone)]
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
        let mut file_states = Vec::new();
        for file_path in file_paths {
            let states = self.capture_file_state(executor, file_path).await?;
            file_states.extend(states);
        }

        self.persist_signed_checkpoint(executor, checkpoint_name, file_states)
            .await
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
        let mut file_states = Vec::new();
        for file_path in file_paths {
            file_states.push(self.capture_directory_entry(executor, file_path).await?);
        }

        self.persist_signed_checkpoint(executor, checkpoint_name, file_states)
            .await
    }

    /// Snapshots the current on-disk state of `reference_states`' paths as a new
    /// signed checkpoint, so a rollback can itself be undone.
    ///
    /// Each path mirrors the capture modality of its reference entry: a
    /// content-captured entry is re-read strictly (an existing but unreadable
    /// file is a hard error, since storing it as absent would delete it on
    /// undo), while a metadata-only entry (account databases, directories)
    /// captures metadata only, preserving the guarantee that no password-file
    /// content ever enters the checkpoint database.
    ///
    /// # Errors
    /// Fails closed: any capture or store failure returns an error and persists
    /// nothing, so the caller can abort the rollback before touching the system.
    async fn snapshot_current_state(
        &self,
        executor: &dyn SystemExecutor,
        checkpoint_name: &str,
        reference_states: &[FileState],
    ) -> Result<CheckpointId> {
        let mut file_states = Vec::with_capacity(reference_states.len());
        for reference in reference_states {
            let path = Path::new(&reference.file_path);
            if reference.file_content.is_some() {
                let meta = executor
                    .file_metadata(path)
                    .await
                    .map_err(|e| HardeningError::System(std::io::Error::other(e)))?;
                if meta.exists && meta.is_file {
                    let content = executor.read_file(path).await.map_err(|e| {
                        HardeningError::Executor(format!(
                            "Cannot snapshot current state of {} before rollback: {e}",
                            reference.file_path
                        ))
                    })?;
                    file_states.push(FileState {
                        file_path: reference.file_path.clone(),
                        file_content: Some(content.into_bytes()),
                        file_permissions: meta.mode,
                        file_owner_uid: meta.uid,
                        file_owner_gid: meta.gid,
                    });
                } else {
                    file_states.push(self.capture_directory_entry(executor, path).await?);
                }
            } else {
                file_states.push(self.capture_directory_entry(executor, path).await?);
            }
        }

        self.persist_signed_checkpoint(executor, checkpoint_name, file_states)
            .await
    }

    /// Signs and stores a fully-captured set of file states as a checkpoint,
    /// stamping id, timestamp, invoking user, and target host. Shared by every
    /// checkpoint-creating path.
    async fn persist_signed_checkpoint(
        &self,
        executor: &dyn SystemExecutor,
        checkpoint_name: &str,
        file_states: Vec<FileState>,
    ) -> Result<CheckpointId> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let checkpoint_id = Self::generate_checkpoint_id();
        let checkpoint_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let checkpoint_username = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
        let host_key = host_key_for(executor);

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

    /// Returns, for each requested checkpoint name, the newest checkpoint with
    /// that name captured from `host_key`. Names without a checkpoint on that
    /// host are omitted. Order of the result follows `names`.
    ///
    /// # Errors
    /// Returns an error if the database query fails.
    pub async fn latest_named_for_host(
        &self,
        host_key: &str,
        names: &[String],
    ) -> Result<Vec<Checkpoint>> {
        let all = self.list_checkpoints().await?;
        Ok(select_latest_named(&all, host_key, names))
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

    /// Restores a single file to its checkpointed state via the executor.
    ///
    /// Validates the path against an allowlist and rejects symlinks (local check)
    /// before performing any write. Returns the action taken and success/failure.
    ///
    /// chmod and chown are best-effort: a failure there is recorded as a warning
    /// in the returned result but does NOT abort the overall rollback.
    async fn restore_file_state_tracked(
        &self,
        executor: &dyn SystemExecutor,
        file_state: &FileState,
    ) -> (FileRestoreAction, Result<()>) {
        let path = Path::new(&file_state.file_path);
        let path_str = &file_state.file_path;

        // --- Allowlist check (always runs; symlink check is local-only) ---
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

        // Symlink traversal guard: only meaningful on the local filesystem.
        // For remote executors the path does not exist locally, so is_symlink()
        // returns false and we rely solely on the prefix allowlist above.
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

        // Determine the required action. `file_permissions` holds the full
        // st_mode (type bit included), so any path that existed at capture (a
        // directory, or a file that was unreadable, even one with 0000 perms)
        // has a non-zero mode and gets its permissions/owner re-applied. Only a
        // path absent at checkpoint time is stored as 0, meaning "remove on restore".
        let action = match &file_state.file_content {
            Some(_) => FileRestoreAction::Restored,
            None if file_state.file_permissions != 0 => FileRestoreAction::PermissionsRestored,
            None => FileRestoreAction::Removed,
        };

        // A mode-0 row means "absent at capture", but a checkpoint written by a
        // version that could not read a path's metadata records an existing file
        // the same way, and upgrading does not rewrite rows already stored. An
        // apply never creates any of these paths, so a row calling one absent
        // while the host actually has it is an untrustworthy row rather than an
        // instruction to delete. A path that is genuinely still absent needs no
        // action at all, and must not be reported as a failure.
        if matches!(action, FileRestoreAction::Removed) {
            return remove_or_refuse(executor, path, path_str).await;
        }

        // Restore file content.
        if let Some(content) = &file_state.file_content {
            let content_str = String::from_utf8_lossy(content);
            if let Err(e) = executor.write_file(path, &content_str).await {
                return (
                    action,
                    Err(HardeningError::Executor(format!(
                        "Failed to write {path_str}: {e}"
                    ))),
                );
            }
        }

        // Restore permissions: best-effort; a failure is a warning, not a fatal error.
        // ponytail: chmod/chown/rm run without sudo, so on a remote host these
        // succeed only when the ssh user owns/can-modify the target (typically
        // root). Non-root remote restore therefore degrades to content-only
        // (content write itself uses `sudo tee`). The remote-root privilege model
        // is owned by the `batch apply` slice (the apply.rs euid gate); revisit
        // there if non-root remote restore is required.
        let mode_str = format!("{:o}", file_state.file_permissions & 0o7777);
        let chmod_warn = executor
            .execute_command("chmod", &[mode_str.as_str(), path_str])
            .await
            .err()
            .map(|e| format!("chmod {path_str}: {e}"));

        // Restore ownership: best-effort.
        let owner_str = format!(
            "{}:{}",
            file_state.file_owner_uid, file_state.file_owner_gid
        );
        let chown_warn = executor
            .execute_command("chown", &[owner_str.as_str(), path_str])
            .await
            .err()
            .map(|e| format!("chown {path_str}: {e}"));

        // Surface the first best-effort warning (if any) as a non-fatal error so
        // it appears in the per-file restore_error field of RollbackResult.
        let meta_result = match (chmod_warn, chown_warn) {
            (Some(w), _) | (None, Some(w)) => Err(HardeningError::Executor(w)),
            (None, None) => Ok(()),
        };

        (action, meta_result)
    }

    /// Restores the system to a previous checkpoint state via the executor.
    ///
    /// Refuses to restore a checkpoint onto a different host than the one it was
    /// captured from. File content is written through `executor` so that remote
    /// rollbacks target the correct host.
    ///
    /// # Arguments
    /// * `executor` - Executor targeting the host to restore
    /// * `checkpoint_id` - The checkpoint ID to restore
    ///
    /// # Security Implications
    /// This function requires root privileges on the target host to restore
    /// file ownership. Failed rollbacks may leave the system in an inconsistent state.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The checkpoint belongs to a different host than the executor targets
    /// - The checkpoint doesn't exist or has been tampered with
    /// - File restoration fails
    pub async fn rollback(
        &self,
        executor: &dyn SystemExecutor,
        checkpoint_id: &CheckpointId,
    ) -> Result<RollbackResult> {
        // Retrieve checkpoint and all file states.
        let (checkpoint, file_states) = self.get_checkpoint(checkpoint_id).await?;

        // Cross-host guard: refuse to restore one host's checkpoint onto another.
        let current_host = host_key_for(executor);
        if checkpoint.host_key != current_host {
            return Err(HardeningError::Config(format!(
                "Checkpoint {} belongs to host '{}', but the current target is '{}'. \
                 Refusing to restore one host's state onto another.",
                checkpoint_id.as_str(),
                checkpoint.host_key,
                current_host,
            )));
        }

        // Verify checkpoint integrity before restoring files.
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

        // Reversible-rollback guarantee: with every target validated but nothing
        // yet written, snapshot the current state of the files about to be
        // overwritten so this rollback can itself be undone. Fail closed: if the
        // snapshot cannot be taken, refuse the rollback rather than destroy state
        // we could not back up. Placed after Phase 1 so only allow-listed paths
        // are read and no orphan checkpoint persists if validation rejects.
        self.snapshot_current_state(
            executor,
            &format!("Before rollback to '{}'", checkpoint.checkpoint_name),
            &file_states,
        )
        .await?;

        // Phase 2: Apply all file restores (pre-validated).
        let mut all_ok = true;
        let mut files = Vec::with_capacity(file_states.len());
        for fs in &file_states {
            let (action, result) = self.restore_file_state_tracked(executor, fs).await;
            let success = result.is_ok();
            all_ok &= success;
            files.push(FileRestoreResult {
                restore_path: fs.file_path.clone(),
                restore_action: action,
                restore_success: success,
                restore_error: result.err().map(|e| e.to_string()),
            });
        }

        Ok(RollbackResult {
            rollback_checkpoint_id: checkpoint_id.as_str().to_owned(),
            rollback_checkpoint_name: checkpoint.checkpoint_name,
            rollback_success: all_ok,
            rollback_files: files,
        })
    }
}

/// Selects, per requested name, the newest checkpoint matching that name on the
/// given host. Pure and order-independent (picks the maximum timestamp), so it
/// does not depend on the caller's sort order. Names with no match are omitted.
fn select_latest_named(
    checkpoints: &[Checkpoint],
    host_key: &str,
    names: &[String],
) -> Vec<Checkpoint> {
    names
        .iter()
        .filter_map(|name| {
            checkpoints
                .iter()
                .filter(|c| c.host_key.as_str() == host_key && c.checkpoint_name == *name)
                .max_by_key(|c| c.checkpoint_timestamp)
                .cloned()
        })
        .collect()
}

/// Handles a checkpoint row whose action is [`FileRestoreAction::Removed`]:
/// `path` was recorded absent at capture time, and this decides whether that
/// row may still be trusted.
///
/// `path_str` outside [`UNDELETABLE_ROLLBACK_PATHS`] is deleted unconditionally,
/// matching an apply that created the file itself. A listed path is probed
/// first, and is deleted only when that probe positively confirms it is still
/// absent; a probe error fails closed rather than guessing. Kept as a free
/// function (rather than nested `if`s inline in `restore_file_state_tracked`)
/// so the two conditions it distinguishes, ordinary-removal versus
/// protected-path, read as one flat decision instead of two levels of nesting.
async fn remove_or_refuse(
    executor: &dyn SystemExecutor,
    path: &Path,
    path_str: &str,
) -> (FileRestoreAction, Result<()>) {
    if !UNDELETABLE_ROLLBACK_PATHS.contains(&path_str) {
        let result = executor
            .execute_command("rm", &["-f", path_str])
            .await
            .map(|_| ())
            .map_err(|e| HardeningError::Executor(e.to_string()));
        return (FileRestoreAction::Removed, result);
    }

    match executor.path_exists(path).await {
        Ok(false) => (FileRestoreAction::Skipped, Ok(())),
        Ok(true) => (
            FileRestoreAction::Skipped,
            Err(HardeningError::Rollback(format!(
                "Refusing to delete {path_str}: the checkpoint recorded this path as absent, but \
                 it exists now. It may have arrived from a package installed after the checkpoint \
                 was taken; this tool will not delete it."
            ))),
        ),
        Err(e) => (
            FileRestoreAction::Skipped,
            Err(HardeningError::Rollback(format!(
                "Refusing to delete {path_str}: could not determine whether it exists: {e}"
            ))),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hardener_common::executor::MockExecutor;

    #[test]
    fn default_prefixes_cover_account_database_paths() {
        // The permissions plugin checkpoints these (CIS 6.1.2-6.1.5). Rollback's
        // Phase-1 allowlist matches via `starts_with`, so each must be covered or
        // the entire rollback aborts (regression: exit 1 on apply→rollback).
        for path in ["/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"] {
            assert!(
                DEFAULT_ROLLBACK_PREFIXES
                    .iter()
                    .any(|p| path.starts_with(p)),
                "{path} not covered by DEFAULT_ROLLBACK_PREFIXES (rollback would abort)"
            );
        }
    }

    #[tokio::test]
    async fn rollback_restores_zero_perm_account_file_instead_of_removing_it() {
        use hardener_common::executor::{CommandOutput, FileMetadata};

        // End-to-end guard for the cross-distro regression (permissions
        // apply→rollback exit 1 + silent /etc/shadow deletion on Arch). Drives the
        // public rollback() API and proves BOTH halves of the fix together:
        //   1. /etc/shadow is in the production allowlist → Phase-1 does not abort.
        //   2. A file that existed at capture with perms 0000 is stored with a
        //      non-zero mode (S_IFREG type bit, as the fixed LocalExecutor now
        //      reports it), so restore re-applies permissions rather than reading
        //      mode 0 as "did not exist" and deleting the path.
        let manager = test_manager().await; // production DEFAULT_ROLLBACK_PREFIXES
        let shadow = "/etc/shadow";
        let ok = || CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        };
        let executor = MockExecutor::new()
            .with_file_metadata(
                shadow,
                "",
                FileMetadata {
                    exists: true,
                    is_file: true,
                    is_dir: false,
                    mode: 0o100000, // S_IFREG | 0000 perms: what the fixed local executor reports
                    size: 0,
                    uid: 0,
                    gid: 0,
                },
            )
            .with_command("chmod", &["0", shadow], ok())
            .with_command("chown", &["0:0", shadow], ok());

        let cp_id = manager
            .create_checkpoint_metadata_only(&executor, "perm-test", &[Path::new(shadow)])
            .await
            .expect("checkpoint");

        // Returning Ok (not Err) proves the allowlist accepts /etc/shadow.
        let result = manager
            .rollback(&executor, &cp_id)
            .await
            .expect("rollback must not abort on an allow-listed path");

        assert!(
            result.rollback_success,
            "rollback should succeed: {result:?}"
        );
        assert_eq!(result.rollback_files.len(), 1);
        assert_eq!(
            result.rollback_files[0].restore_action,
            FileRestoreAction::PermissionsRestored,
            "an existing 0000-perm file must be permission-restored, never Removed"
        );
        assert!(
            !executor
                .log()
                .commands_executed
                .iter()
                .any(|(program, _)| program == "rm"),
            "rollback must never issue `rm` for a file that existed at capture"
        );
    }

    #[tokio::test]
    async fn rollback_refuses_to_delete_every_undeletable_path_recorded_as_absent() {
        use hardener_common::executor::FileMetadata;

        // A checkpoint written by a version whose stat probe reported an
        // existing file as absent stores it with mode 0, which restore reads
        // as "remove on rollback". Fixing capture cannot disarm rows already
        // on disk, so restore must refuse the deletion outright.
        //
        // Every entry in the list is exercised, not a representative one, so a
        // path added to UNDELETABLE_ROLLBACK_PATHS is covered the moment it is
        // added rather than waiting for someone to remember a new test.
        let manager = test_manager().await;
        let mut exercised = 0usize;

        for path in UNDELETABLE_ROLLBACK_PATHS {
            // rollback()'s Phase 1 runs path.is_symlink()/canonicalize() against
            // the real local filesystem before the guard under test is ever
            // reached. If one of these paths happens to be a symlink on the
            // machine running the test, resolving outside
            // DEFAULT_ROLLBACK_PREFIXES, Phase 1 aborts the whole rollback for a
            // reason unrelated to this guard, and the unwrap_or_else below would
            // panic on a contributor's own /etc rather than on a real defect.
            // Skip such a path rather than let the test depend on the local
            // filesystem; every other entry is still exercised in full.
            if Path::new(path).is_symlink() {
                eprintln!(
                    "rollback_refuses_to_delete_every_undeletable_path_recorded_as_absent: \
                     skipping {path}, it is a symlink on this machine"
                );
                continue;
            }
            exercised += 1;

            // Capture believes the path is absent: nothing registered on the
            // mock, so file_metadata reports a confirmed absence and the row
            // stores 0.
            let capturing = MockExecutor::new();
            let cp_id = manager
                .create_checkpoint_metadata_only(&capturing, "poisoned", &[Path::new(path)])
                .await
                .unwrap_or_else(|e| panic!("{path}: capture of a confirmed-absent path: {e}"));

            // Rollback then runs against a host that does have the path, which
            // is what an operator upgrading from v1.4.0 actually has.
            let restoring = MockExecutor::new().with_file_metadata(
                path,
                "",
                FileMetadata {
                    exists: true,
                    is_file: true,
                    is_dir: false,
                    mode: 0o100644,
                    size: 0,
                    uid: 0,
                    gid: 0,
                },
            );

            let result = manager
                .rollback(&restoring, &cp_id)
                .await
                .unwrap_or_else(|e| panic!("{path}: rollback must run rather than abort: {e}"));

            let restoring_log = restoring.log();
            let deletions: Vec<_> = restoring_log
                .commands_executed
                .iter()
                .filter(|(cmd, args)| cmd == "rm" && args.iter().any(|a| a == path))
                .collect();
            assert!(
                deletions.is_empty(),
                "rollback must never delete {path}, but issued: {deletions:?}"
            );
            assert_eq!(
                result.rollback_files[0].restore_action,
                FileRestoreAction::Skipped,
                "{path}: a refused deletion must be recorded as Skipped"
            );
            assert!(
                !result.rollback_success,
                "{path}: a refused deletion means the checkpoint is untrustworthy and must be reported, not silently swallowed"
            );
        }

        assert!(
            exercised > 0,
            "every UNDELETABLE_ROLLBACK_PATHS entry was a symlink on this machine; the guard was never exercised"
        );
    }

    #[tokio::test]
    async fn rollback_still_deletes_a_path_an_apply_can_create() {
        use hardener_common::executor::FileMetadata;

        // The counterpart to the test above: the refusal is keyed on list
        // membership, so a path an apply CAN create must still be removed. The
        // kernel plugin writes its own /etc/sysctl.d drop-in, so a checkpoint
        // taken before that apply records the file as absent truthfully, and
        // deleting it is what the operator asked for. Protecting it instead
        // would leave the hardening in place after a rollback.
        let manager = test_manager().await;
        let drop_in = "/etc/sysctl.d/99-hardener.conf";
        assert!(
            !UNDELETABLE_ROLLBACK_PATHS.contains(&drop_in),
            "{drop_in} is created by the kernel plugin's apply, so it must stay deletable"
        );

        let capturing = MockExecutor::new();
        let cp_id = manager
            .create_checkpoint_metadata_only(&capturing, "pre-apply", &[Path::new(drop_in)])
            .await
            .expect("capture of a confirmed-absent path must succeed");

        let restoring = MockExecutor::new()
            .with_file_metadata(
                drop_in,
                "",
                FileMetadata {
                    exists: true,
                    is_file: true,
                    is_dir: false,
                    mode: 0o100644,
                    size: 0,
                    uid: 0,
                    gid: 0,
                },
            )
            .with_command("rm", &["-f", drop_in], ok_output());

        let result = manager
            .rollback(&restoring, &cp_id)
            .await
            .expect("rollback must run rather than abort");

        let restoring_log = restoring.log();
        assert!(
            restoring_log
                .commands_executed
                .iter()
                .any(|(cmd, args)| cmd == "rm" && args.iter().any(|a| a == drop_in)),
            "a file the apply created must still be deleted, but the commands issued were: {:?}",
            restoring_log.commands_executed
        );
        assert_eq!(
            result.rollback_files[0].restore_action,
            FileRestoreAction::Removed,
            "an unprotected path recorded as absent must be Removed"
        );
        assert!(
            result.rollback_success,
            "deleting a path the apply created is an ordinary success: {result:?}"
        );
    }

    #[tokio::test]
    async fn rollback_refuses_to_delete_a_critical_path_when_existence_cannot_be_checked() {
        // The existence probe itself can fail, for example an SSH command that
        // dies mid-check. That is neither "confirmed absent" nor "confirmed
        // present": the guard must fail closed rather than guess either way.
        let manager = test_manager().await;
        let passwd = "/etc/passwd";

        let capturing = MockExecutor::new();
        let cp_id = manager
            .create_checkpoint_metadata_only(&capturing, "poisoned", &[Path::new(passwd)])
            .await
            .expect("capture of a confirmed-absent path must succeed");

        let restoring = MockExecutor::new().with_path_exists_error(passwd);

        let result = manager
            .rollback(&restoring, &cp_id)
            .await
            .expect("rollback must run rather than abort");

        let restoring_log = restoring.log();
        let deletions: Vec<_> = restoring_log
            .commands_executed
            .iter()
            .filter(|(cmd, args)| cmd == "rm" && args.iter().any(|a| a == passwd))
            .collect();
        assert!(
            deletions.is_empty(),
            "rollback must never delete {passwd} when its existence cannot be confirmed, but issued: {deletions:?}"
        );
        assert_eq!(
            result.rollback_files[0].restore_action,
            FileRestoreAction::Skipped,
            "an unverifiable path must be recorded as Skipped"
        );
        assert!(
            !result.rollback_success,
            "an unverifiable path means rollback cannot proceed safely and must be reported, not silently swallowed"
        );
    }

    #[tokio::test]
    async fn rollback_succeeds_when_a_protected_path_is_genuinely_absent() {
        // A minimal host with no sudo installed has no /etc/sudoers.d. Capture
        // records that absence correctly, so rollback has nothing to delete and
        // must report an ordinary success. Refusing here would fail every
        // rollback on every host that lacks an optional package.
        let manager = test_manager().await;
        let sudoers_d = "/etc/sudoers.d";

        // Absent at capture and still absent at restore: nothing registered.
        let executor = MockExecutor::new();
        let cp_id = manager
            .create_checkpoint_metadata_only(&executor, "minimal-host", &[Path::new(sudoers_d)])
            .await
            .expect("capture of a confirmed-absent path must succeed");

        let result = manager
            .rollback(&executor, &cp_id)
            .await
            .expect("rollback must run");

        assert!(
            result.rollback_success,
            "a genuinely absent optional path must not fail the rollback: {result:?}"
        );
        assert!(
            result.rollback_files[0].restore_error.is_none(),
            "no error should be recorded for a path that was never there: {:?}",
            result.rollback_files[0].restore_error
        );
    }

    /// Builds a CheckpointManager over a temporary in-memory SQLite database
    /// with a freshly generated signing key: no filesystem privileges needed.
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
    async fn rollback_restores_directory_permissions_not_skipped() {
        // A directory's captured mode (0o755) carries no S_IFDIR bit; `file_metadata`
        // masks the type bit off. Rollback must still re-apply its permissions rather
        // than skip or remove it. Regression guard for the masked-mode directory bug.
        let ok = hardener_common::executor::CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        };
        let exec = MockExecutor::new()
            .with_directory("/etc/pam.d")
            .with_command("chmod", &["755", "/etc/pam.d"], ok.clone())
            .with_command("chown", &["0:0", "/etc/pam.d"], ok);

        let manager = test_manager().await;
        let id = manager
            .create_checkpoint_metadata_only(&exec, "dir", &[std::path::Path::new("/etc/pam.d")])
            .await
            .expect("create");
        let result = manager.rollback(&exec, &id).await.expect("rollback");

        assert!(result.rollback_success, "directory rollback should succeed");
        let entry = result
            .rollback_files
            .iter()
            .find(|f| f.restore_path.ends_with("pam.d"))
            .expect("directory entry present");
        assert!(
            matches!(entry.restore_action, FileRestoreAction::PermissionsRestored),
            "directory must have permissions restored, not skipped or removed"
        );
        assert!(
            !exec.log().commands_executed.iter().any(|(p, _)| p == "rm"),
            "directory must not be removed on rollback"
        );
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
    async fn capture_refuses_to_record_an_unverifiable_path_as_absent() {
        // The data-loss bug at its source. An unstat-able path recorded as
        // absent (file_permissions: 0) is deleted by a later rollback, so
        // capture must fail rather than record it.
        let manager = test_manager().await;
        let executor = MockExecutor::new()
            .with_metadata_error("/etc/passwd")
            .with_path_exists("/etc/passwd", true);

        manager
            .create_checkpoint_metadata_only(
                &executor,
                "permissions-hardening",
                &[std::path::Path::new("/etc/passwd")],
            )
            .await
            .expect_err("an unverifiable path must abort capture, not be stored as absent");
    }

    #[tokio::test]
    async fn capture_still_records_a_genuinely_absent_path() {
        // The other half: confirmed absence must stay an ordinary outcome, or
        // every host lacking an optional path would fail to apply.
        let manager = test_manager().await;
        let executor = MockExecutor::new();

        manager
            .create_checkpoint_metadata_only(
                &executor,
                "permissions-hardening",
                &[std::path::Path::new("/etc/sudoers.d")],
            )
            .await
            .expect("a confirmed-absent path is not an error");
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

    fn cp(id: &str, name: &str, ts: i64, host: &str) -> Checkpoint {
        Checkpoint {
            checkpoint_id: CheckpointId::new(id.to_string()),
            checkpoint_name: name.to_string(),
            checkpoint_timestamp: ts,
            checkpoint_username: "u".to_string(),
            checkpoint_signature: vec![],
            host_key: host.to_string(),
        }
    }

    #[test]
    fn select_latest_named_picks_newest_per_name_for_host() {
        let all = vec![
            cp("a", "ssh-hardening-pre-apply", 100, "ssh://root@h"),
            cp("b", "ssh-hardening-pre-apply", 200, "ssh://root@h"),
            cp("c", "kernel-hardening-pre-apply", 150, "ssh://root@h"),
            cp("d", "ssh-hardening-pre-apply", 999, "ssh://root@other"),
        ];
        let names = vec![
            "ssh-hardening-pre-apply".to_string(),
            "kernel-hardening-pre-apply".to_string(),
        ];
        let got = select_latest_named(&all, "ssh://root@h", &names);
        assert_eq!(got.len(), 2, "one checkpoint per matched name");
        assert_eq!(
            got[0].checkpoint_id.as_str(),
            "b",
            "newest ssh checkpoint on this host"
        );
        assert_eq!(got[1].checkpoint_id.as_str(), "c");
    }

    #[test]
    fn select_latest_named_omits_unmatched_names_and_other_hosts() {
        let all = vec![cp("a", "ssh-hardening-pre-apply", 100, "ssh://root@h")];
        let names = vec![
            "audit-hardening-pre-apply".to_string(),
            "ssh-hardening-pre-apply".to_string(),
        ];
        let got = select_latest_named(&all, "ssh://root@nope", &names);
        assert!(got.is_empty(), "no checkpoints for that host");
    }

    #[tokio::test]
    async fn latest_named_for_host_reads_db() {
        let exec = MockExecutor::new()
            .remote()
            .with_description("ssh://root@h")
            .with_file("/etc/ssh/sshd_config", "Port 22\n");
        let manager = test_manager().await;
        manager
            .create_checkpoint(
                &exec,
                "ssh-hardening-pre-apply",
                &[std::path::Path::new("/etc/ssh/sshd_config")],
            )
            .await
            .expect("create");
        let got = manager
            .latest_named_for_host("ssh://root@h", &["ssh-hardening-pre-apply".to_string()])
            .await
            .expect("select");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].checkpoint_name, "ssh-hardening-pre-apply");
    }

    /// Builds a CheckpointManager with a custom allowlist containing `/etc/x`.
    async fn test_manager_with_etc_x() -> CheckpointManager {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("mgr_test.db");
        let db_pool = crate::db::init_db(Some(&db_path)).await.expect("init_db");
        let key_path = dir.path().join("test.key");
        let signer = CheckpointSigner::new_with_path(&key_path).expect("signer");
        std::mem::forget(dir);
        CheckpointManager::new_with_allowlist(db_pool, signer, vec!["/etc/x".to_string()])
            .expect("manager")
    }

    #[tokio::test]
    async fn rollback_refuses_cross_host_checkpoint() {
        let remote = MockExecutor::new()
            .remote()
            .with_description("ssh://a")
            .with_file("/etc/x", "original\n");

        let manager = test_manager_with_etc_x().await;
        let id = manager
            .create_checkpoint(&remote, "t", &[std::path::Path::new("/etc/x")])
            .await
            .expect("create_checkpoint");

        // A local executor targets "local", but the checkpoint was for "ssh://a".
        let local = MockExecutor::new();
        let err = manager
            .rollback(&local, &id)
            .await
            .expect_err("expected cross-host error");
        assert!(
            err.to_string().contains("Refusing to restore"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn rollback_restores_through_executor() {
        use hardener_common::executor::CommandOutput;

        // Seed the executor with the "original" file content and register
        // chmod/chown so best-effort metadata commands succeed.
        let exec = MockExecutor::new()
            .with_file("/etc/x", "original\n")
            .with_command(
                "chmod",
                &["644", "/etc/x"],
                CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            )
            .with_command(
                "chown",
                &["0:0", "/etc/x"],
                CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            );

        let manager = test_manager_with_etc_x().await;
        let id = manager
            .create_checkpoint(&exec, "t", &[std::path::Path::new("/etc/x")])
            .await
            .expect("create_checkpoint");

        // Overwrite the file in the mock's in-memory store.
        exec.write_file(std::path::Path::new("/etc/x"), "changed\n")
            .await
            .expect("write_file");

        let result = manager.rollback(&exec, &id).await.expect("rollback");
        assert!(result.rollback_success, "rollback_success should be true");

        // The executor's write_file restores the content into the mock store.
        let restored = exec
            .read_file(std::path::Path::new("/etc/x"))
            .await
            .expect("read_file after rollback");
        assert_eq!(restored, "original\n");
    }

    /// A helper producing a zero-exit command output for best-effort chmod/chown.
    fn ok_output() -> hardener_common::executor::CommandOutput {
        hardener_common::executor::CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        }
    }

    #[tokio::test]
    async fn rollback_snapshots_current_state_before_restoring() {
        // The reversible-rollback guarantee: before overwriting the live files,
        // rollback captures their CURRENT content as a new checkpoint named after
        // the one being restored.
        let exec = MockExecutor::new()
            .with_file("/etc/x", "original\n")
            .with_command("chmod", &["644", "/etc/x"], ok_output())
            .with_command("chown", &["0:0", "/etc/x"], ok_output());
        let manager = test_manager_with_etc_x().await;
        let id = manager
            .create_checkpoint(&exec, "hardening", &[Path::new("/etc/x")])
            .await
            .expect("create_checkpoint");

        // The live state diverges from the checkpoint we will restore.
        exec.write_file(Path::new("/etc/x"), "changed\n")
            .await
            .expect("write_file");

        let before = manager.list_checkpoints().await.expect("list").len();
        manager.rollback(&exec, &id).await.expect("rollback");
        let after = manager.list_checkpoints().await.expect("list");

        assert_eq!(
            after.len(),
            before + 1,
            "rollback must create exactly one pre-rollback checkpoint"
        );
        let pre = after
            .iter()
            .find(|c| c.checkpoint_name == "Before rollback to 'hardening'")
            .expect("a checkpoint named after the restored one must exist");
        let (_, states) = manager
            .get_checkpoint(&pre.checkpoint_id)
            .await
            .expect("get_checkpoint");
        let captured = states
            .iter()
            .find(|s| s.file_path == "/etc/x")
            .expect("the snapshot must include /etc/x");
        assert_eq!(
            captured.file_content.as_deref(),
            Some(b"changed\n".as_ref()),
            "the snapshot must capture the CURRENT content, not the restored checkpoint's"
        );
    }

    #[tokio::test]
    async fn rollback_snapshot_keeps_account_files_metadata_only() {
        // Parity with apply-time capture: account databases are snapshot
        // metadata-only, so no password hashes ever enter the checkpoint DB.
        use hardener_common::executor::FileMetadata;
        let shadow = "/etc/shadow";
        let exec = MockExecutor::new()
            .with_file_metadata(
                shadow,
                "root:$6$secret$hash:19000:0:99999:7:::\n",
                FileMetadata {
                    exists: true,
                    is_file: true,
                    is_dir: false,
                    mode: 0o100000,
                    size: 0,
                    uid: 0,
                    gid: 0,
                },
            )
            .with_command("chmod", &["0", shadow], ok_output())
            .with_command("chown", &["0:0", shadow], ok_output());
        let manager = test_manager().await; // production allowlist covers /etc/shadow
        let id = manager
            .create_checkpoint_metadata_only(&exec, "perm", &[Path::new(shadow)])
            .await
            .expect("create_checkpoint_metadata_only");

        manager.rollback(&exec, &id).await.expect("rollback");

        let after = manager.list_checkpoints().await.expect("list");
        let pre = after
            .iter()
            .find(|c| c.checkpoint_name == "Before rollback to 'perm'")
            .expect("pre-rollback checkpoint");
        let (_, states) = manager
            .get_checkpoint(&pre.checkpoint_id)
            .await
            .expect("get_checkpoint");
        let s = states
            .iter()
            .find(|s| s.file_path == shadow)
            .expect("shadow captured");
        assert!(
            s.file_content.is_none(),
            "account files must be snapshot metadata-only: no content may be stored"
        );
    }

    #[tokio::test]
    async fn rollback_is_reversible_via_its_pre_rollback_checkpoint() {
        // End-to-end undo: after rolling back, restoring the pre-rollback
        // checkpoint returns the system to the state it was in before rollback.
        let exec = MockExecutor::new()
            .with_file("/etc/x", "baseline\n")
            .with_command("chmod", &["644", "/etc/x"], ok_output())
            .with_command("chown", &["0:0", "/etc/x"], ok_output());
        let manager = test_manager_with_etc_x().await;
        let baseline = manager
            .create_checkpoint(&exec, "baseline", &[Path::new("/etc/x")])
            .await
            .expect("create_checkpoint");

        // Move the live state forward (as an apply would).
        exec.write_file(Path::new("/etc/x"), "hardened\n")
            .await
            .expect("write_file");

        // Roll back to baseline; this must snapshot the "hardened" state first.
        manager.rollback(&exec, &baseline).await.expect("rollback");
        assert_eq!(
            exec.read_file(Path::new("/etc/x")).await.expect("read"),
            "baseline\n"
        );

        // Undo the rollback by restoring the pre-rollback checkpoint.
        let pre = manager
            .list_checkpoints()
            .await
            .expect("list")
            .into_iter()
            .find(|c| c.checkpoint_name == "Before rollback to 'baseline'")
            .expect("pre-rollback checkpoint");
        manager
            .rollback(&exec, &pre.checkpoint_id)
            .await
            .expect("undo rollback");

        assert_eq!(
            exec.read_file(Path::new("/etc/x")).await.expect("read"),
            "hardened\n",
            "undoing the rollback must restore the pre-rollback state"
        );
    }

    #[tokio::test]
    async fn rollback_fails_closed_when_current_state_cannot_be_captured() {
        // If the current state cannot be snapshot, rollback must refuse and write
        // nothing: a rollback we cannot undo is more dangerous than not running.
        use hardener_common::executor::FileMetadata;
        let setup = MockExecutor::new()
            .with_file("/etc/x", "original\n")
            .with_command("chmod", &["644", "/etc/x"], ok_output())
            .with_command("chown", &["0:0", "/etc/x"], ok_output());
        let manager = test_manager_with_etc_x().await;
        let id = manager
            .create_checkpoint(&setup, "cp", &[Path::new("/etc/x")])
            .await
            .expect("create_checkpoint");

        // Roll back against a host where /etc/x exists but is unreadable.
        let exec = MockExecutor::new()
            .with_file_metadata(
                "/etc/x",
                "unreadable",
                FileMetadata {
                    exists: true,
                    is_file: true,
                    is_dir: false,
                    mode: 0o644,
                    size: 10,
                    uid: 0,
                    gid: 0,
                },
            )
            .with_read_permission_denied("/etc/x")
            .with_command("chmod", &["644", "/etc/x"], ok_output())
            .with_command("chown", &["0:0", "/etc/x"], ok_output());

        let before = manager.list_checkpoints().await.expect("list").len();
        let result = manager.rollback(&exec, &id).await;

        assert!(
            result.is_err(),
            "rollback must fail closed when the current state cannot be captured"
        );
        assert!(
            exec.log().files_written.is_empty(),
            "no file may be written when rollback fails closed"
        );
        assert_eq!(
            manager.list_checkpoints().await.expect("list").len(),
            before,
            "no half-committed pre-rollback checkpoint may persist on failure"
        );
    }

    #[tokio::test]
    async fn rollback_leaves_no_snapshot_when_validation_rejects() {
        // The snapshot runs after Phase 1 validation, so a rollback rejected for
        // an out-of-allowlist path must not persist an orphan pre-rollback
        // checkpoint or read that path's content.
        let exec = MockExecutor::new().with_file("/tmp/evil.conf", "x\n");
        let manager = test_manager_with_etc_x().await; // allowlist is ["/etc/x"] only
        let id = manager
            .create_checkpoint(&exec, "bad", &[Path::new("/tmp/evil.conf")])
            .await
            .expect("create_checkpoint");

        let before = manager.list_checkpoints().await.expect("list").len();
        let result = manager.rollback(&exec, &id).await;

        assert!(
            result.is_err(),
            "rollback must reject a path outside the allowlist"
        );
        assert_eq!(
            manager.list_checkpoints().await.expect("list").len(),
            before,
            "a rollback rejected by validation must not persist a pre-rollback checkpoint"
        );
    }
}
