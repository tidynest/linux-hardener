//! Checkpoint manager for creating and managing system state snapshots.

use crate::checkpoint::{
    CheckpointId, FileRestoreAction, FileRestoreResult, FileState, RollbackResult,
};
use crate::{Checkpoint, CheckpointSigner};
use hardener_common::error::{HardeningError, Result};
use sqlx::{Row, SqlitePool};
use std::path::Path;

/// Default rollback path prefixes for production use.
const DEFAULT_ROLLBACK_PREFIXES: &[&str] = &[
    "/etc/ssh/",
    "/etc/sysctl.d/",
    "/etc/security/",
    "/etc/pam.d/",
    "/etc/audit/",
    "/etc/apparmor",
    "/etc/selinux/",
    "/etc/login.defs",
    "/etc/nftables",
    "/etc/firewalld/",
    "/etc/ufw/",
];

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

    /// Captures the current state of a single file (not a directory).
    ///
    /// Records file content, permissions, and ownership.
    ///
    /// # Arguments
    /// * `file_path` - Path to the file to capture
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or metadata cannot be accessed.
    fn capture_single_file(&self, file_path: &Path) -> Result<FileState> {
        use std::fs::File;
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        // Open file once — all subsequent operations use this handle,
        // eliminating the TOCTOU window between exists/metadata/read.
        let mut file = match File::open(file_path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(FileState {
                    file_path: file_path.to_string_lossy().to_string(),
                    file_content: None,
                    file_permissions: 0,
                    file_owner_uid: 0,
                    file_owner_gid: 0,
                });
            }
            Err(e) => return Err(HardeningError::System(e)),
        };

        // Metadata and content from the same open file descriptor
        let file_metadata = file.metadata().map_err(HardeningError::System)?;
        let mut file_content = Vec::new();
        file.read_to_end(&mut file_content)
            .map_err(HardeningError::System)?;

        Ok(FileState {
            file_path: file_path.to_string_lossy().to_string(),
            file_content: Some(file_content),
            file_permissions: file_metadata.permissions().mode(),
            file_owner_uid: file_metadata.uid(),
            file_owner_gid: file_metadata.gid(),
        })
    }

    /// Captures metadata for a directory entry without reading contents.
    ///
    /// Records permissions and ownership but sets `file_content` to `None`.
    /// The directory type bit (`0o40000`) in `file_permissions` distinguishes
    /// this from "didn't exist" entries (which have `file_permissions: 0`).
    fn capture_directory_entry(&self, dir_path: &Path) -> Result<FileState> {
        use std::fs;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if !dir_path.exists() {
            return Ok(FileState {
                file_path: dir_path.to_string_lossy().to_string(),
                file_content: None,
                file_permissions: 0,
                file_owner_uid: 0,
                file_owner_gid: 0,
            });
        }

        let metadata = fs::symlink_metadata(dir_path).map_err(HardeningError::System)?;

        Ok(FileState {
            file_path: dir_path.to_string_lossy().to_string(),
            file_content: None,
            file_permissions: metadata.permissions().mode(),
            file_owner_uid: metadata.uid(),
            file_owner_gid: metadata.gid(),
        })
    }

    /// Captures the current state of a file or directory.
    ///
    /// If the path is a directory, recursively captures all files within it.
    /// Records file content, permissions, and ownership for each file.
    ///
    /// # Arguments
    /// * `file_path` - Path to the file or directory to capture
    ///
    /// # Errors
    /// Returns an error if files cannot be read or metadata cannot be accessed.
    fn capture_file_state(&self, file_path: &Path) -> Result<Vec<FileState>> {
        use std::fs;

        // Check if path exists
        if !file_path.exists() {
            // Path doesn't exist - record that fact as a single entry
            return Ok(vec![FileState {
                file_path: file_path.to_string_lossy().to_string(),
                file_content: None,
                file_permissions: 0,
                file_owner_uid: 0,
                file_owner_gid: 0,
            }]);
        }

        let metadata = fs::symlink_metadata(file_path).map_err(HardeningError::System)?;

        if metadata.is_dir() {
            // Recursively capture all files in directory
            self.capture_directory_recursive(file_path)
        } else {
            // Single file
            Ok(vec![self.capture_single_file(file_path)?])
        }
    }

    /// Recursively captures all files within a directory.
    fn capture_directory_recursive(&self, dir_path: &Path) -> Result<Vec<FileState>> {
        use std::fs;

        let mut file_states = vec![self.capture_directory_entry(dir_path)?];

        let entries = fs::read_dir(dir_path).map_err(HardeningError::System)?;

        for entry in entries {
            let entry = entry.map_err(HardeningError::System)?;
            let path = entry.path();

            if path.is_dir() {
                // Recurse into subdirectory
                let sub_states = self.capture_directory_recursive(&path)?;
                file_states.extend(sub_states);
            } else {
                // Capture file
                let state = self.capture_single_file(&path)?;
                file_states.push(state);
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

        for file_state in file_states {
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
        Ok(self.signer.sign(&digest))
    }

    /// Creates a new checkpoint capturing the state of specified files.
    ///
    /// # Arguments
    /// * `checkpoint_name` - Human-readable name for the checkpoint
    /// * `file_paths` - List of file paths to capture
    ///
    /// # Errors
    /// Returns an error if files cannot be read or database operation fails.
    pub async fn create_checkpoint(
        &self,
        checkpoint_name: &str,
        file_paths: &[&Path],
    ) -> Result<CheckpointId> {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Generate unique ID
        let checkpoint_id = Self::generate_checkpoint_id();

        // Get current timestamp
        let checkpoint_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Get current username
        let checkpoint_username = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());

        // Capture file states (handles both files and directories)
        let mut file_states = Vec::new();
        for file_path in file_paths {
            let states = self.capture_file_state(file_path)?;
            file_states.extend(states);
        }

        // Generate cryptographic signature over checkpoint data
        let checkpoint_signature = self.generate_signature(
            &checkpoint_id,
            checkpoint_name,
            checkpoint_timestamp,
            &checkpoint_username,
            &file_states,
        )?;

        // Store checkpoint in database
        self.store_checkpoint(
            &checkpoint_id,
            checkpoint_name,
            checkpoint_timestamp,
            &checkpoint_username,
            &checkpoint_signature,
            &file_states,
        )
        .await?;

        Ok(checkpoint_id)
    }

    /// Creates a checkpoint capturing only metadata (permissions/ownership) for each path.
    ///
    /// Unlike `create_checkpoint`, this does not read file contents or recurse
    /// into directories. Suitable for plugins that only modify mode bits.
    pub async fn create_checkpoint_metadata_only(
        &self,
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

        let mut file_states = Vec::new();
        for file_path in file_paths {
            file_states.push(self.capture_directory_entry(file_path)?);
        }

        let checkpoint_signature = self.generate_signature(
            &checkpoint_id,
            checkpoint_name,
            checkpoint_timestamp,
            &checkpoint_username,
            &file_states,
        )?;

        self.store_checkpoint(
            &checkpoint_id,
            checkpoint_name,
            checkpoint_timestamp,
            &checkpoint_username,
            &checkpoint_signature,
            &file_states,
        )
        .await?;

        Ok(checkpoint_id)
    }

    /// Stores checkpoint and file states in the database.
    async fn store_checkpoint(
        &self,
        checkpoint_id: &CheckpointId,
        checkpoint_name: &str,
        checkpoint_timestamp: i64,
        checkpoint_username: &str,
        checkpoint_signature: &[u8],
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
                created_at
                )
            VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(checkpoint_id.as_str())
        .bind(checkpoint_name)
        .bind(checkpoint_timestamp)
        .bind(checkpoint_username)
        .bind(checkpoint_signature)
        .bind(checkpoint_timestamp)
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
            .bind(checkpoint_id.as_str())
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
                signature
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
                file_states WHERE checkpoint_id = ?",
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
                signature
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
            return (
                FileRestoreAction::Skipped,
                Err(HardeningError::Config(format!(
                    "Rollback target is a symlink: {path_str}"
                ))),
            );
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
        // Rejects if any target path fails the allowlist check or is a symlink,
        // preventing a partially-rolled-back inconsistent state.
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
                return Err(HardeningError::Config(format!(
                    "Rollback aborted: target is a symlink: {path_str}"
                )));
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
