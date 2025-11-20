//! Checkpoint manager for creating and managing system state snapshots.

use crate::checkpoint::{CheckpointId, FileState};
use crate::{Checkpoint, CheckpointSigner};
use hardener_common::error::Result;
use sqlx::{Row, SqlitePool};
use std::path::Path;

/// Manages checkpoint creation, storage, and retrieval.
///
/// The CheckpointManager handles all operations related to checkpoints,
/// including creating snapshots of file states and storing them in the database.
pub struct CheckpointManager {
    /// Database connection pool.
    db_pool: SqlitePool,
    /// Cryptographic signer for checkpoint integrity
    signer: CheckpointSigner,
}

impl CheckpointManager {
    pub fn new(db_pool: SqlitePool) -> Result<CheckpointManager> {
        let signer = CheckpointSigner::new()?;
        Ok(Self { db_pool, signer })
    }

    /// Creates a new CheckpointManager with a custom signer.
    ///
    /// This is primarily used for testing to avoid requiring root permissions.
    pub fn new_with_signer(
        db_pool: SqlitePool,
        signer: CheckpointSigner,
    ) -> Result<CheckpointManager> {
        Ok(Self { db_pool, signer })
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

    /// Captures the current state of a file.
    ///
    /// Records file content, permissions, and ownership.
    ///
    /// # Arguments
    /// * `file_path` - Path to the file to capture
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or metadata cannot be accessed.
    fn capture_file_state(&self, file_path: &Path) -> Result<FileState> {
        use std::fs;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        // Check if file exists
        if !file_path.exists() {
            // File doesn't exist - record that fact
            return Ok(FileState {
                file_path: file_path.to_string_lossy().to_string(),
                file_content: None,
                file_permissions: 0,
                file_owner_uid: 0,
                file_owner_gid: 0,
            });
        }

        // Get metadata first
        let file_metadata = fs::metadata(file_path)
            .map_err(|e| hardener_common::error::HardeningError::System(e))?;

        // Read file content
        let file_content =
            fs::read(file_path).map_err(|e| hardener_common::error::HardeningError::System(e))?;

        // Extract permissions and ownership
        let file_permissions = file_metadata.permissions().mode();
        let file_owner_uid = file_metadata.uid();
        let file_owner_gid = file_metadata.gid();

        Ok(FileState {
            file_path: file_path.to_string_lossy().to_string(),
            file_content: Some(file_content),
            file_permissions,
            file_owner_uid,
            file_owner_gid,
        })
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
        use ring::digest::{Context as DigestContext, SHA256};

        // Create a hash context
        let mut hash_context = DigestContext::new(&SHA256);

        // Hash checkpoint metadata
        hash_context.update(checkpoint_id.as_str().as_bytes());
        hash_context.update(checkpoint_name.as_bytes());

        hash_context.update(&checkpoint_timestamp.to_be_bytes());
        hash_context.update(checkpoint_username.as_bytes());

        // Hash each file's content
        for file_state in file_states {
            hash_context.update(file_state.file_path.as_bytes());
            if let Some(content) = &file_state.file_content {
                hash_context.update(content);
            }
        }

        // Finalise the hash
        let digest = hash_context.finish();

        // Sign the hash
        let signature = self.signer.sign(digest.as_ref());

        Ok(signature)
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

        // Capture file states
        let mut file_states = Vec::new();
        for file_path in file_paths {
            let state = self.capture_file_state(file_path)?;
            file_states.push(state);
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
        .execute(&self.db_pool)
        .await
        .map_err(|e| hardener_common::error::HardeningError::Database(e.to_string()))?;

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
            .execute(&self.db_pool)
            .await
            .map_err(|e| hardener_common::error::HardeningError::Database(e.to_string()))?;
        }

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
            FROM checkpoints WHERE id =?",
        )
        .bind(checkpoint_id.as_str())
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| hardener_common::error::HardeningError::Database(e.to_string()))?;

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
        .map_err(|e| hardener_common::error::HardeningError::Database(e.to_string()))?;

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
        .map_err(|e| hardener_common::error::HardeningError::Database(e.to_string()))?;

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
        // Delete file states first (foreign key constraint)
        sqlx::query("DELETE FROM file_states WHERE checkpoint_id = ?")
            .bind(checkpoint_id.as_str())
            .execute(&self.db_pool)
            .await
            .map_err(|e| hardener_common::error::HardeningError::Database(e.to_string()))?;

        // Delete checkpoint metadata
        sqlx::query("DELETE FROM checkpoints WHERE id = ?")
            .bind(checkpoint_id.as_str())
            .execute(&self.db_pool)
            .await
            .map_err(|e| hardener_common::error::HardeningError::Database(e.to_string()))?;

        Ok(())
    }

    /// Restores a single file to its captured state.
    ///
    /// This will restore file content, permissions, and ownership.
    /// If the file didn't exist in the checkpoint (content is None),
    /// the file will be deleted.
    ///
    /// # Arguments
    /// * `file_state` - The file state to restore
    ///
    /// # Security Implications
    /// This function requires root privileges to change file ownership.
    ///
    /// # Errors
    /// Returns an error if file operations fail or insufficient privileges.
    fn restore_file_state(&self, file_state: &FileState) -> Result<()> {
        use std::{fs, os::unix::fs::PermissionsExt, path::Path};

        let path = Path::new(&file_state.file_path);

        // Handle file content: restore or delete
        match &file_state.file_content {
            Some(content) => {
                // File existed - restore content
                fs::write(path, content)
                    .map_err(|e| hardener_common::error::HardeningError::System(e))?;
            }
            None => {
                // File didn't exist - delete it if it exists now
                if path.exists() {
                    fs::remove_file(path)
                        .map_err(|e| hardener_common::error::HardeningError::System(e))?;
                }
                // If file doesn't exist, nothing to do
                return Ok(());
            }
        }

        // Restore permissions
        let permissions = fs::Permissions::from_mode(file_state.file_permissions);
        fs::set_permissions(path, permissions)
            .map_err(|e| hardener_common::error::HardeningError::System(e))?;

        // Restore ownership (requires root privileges)
        nix::unistd::chown(
            path,
            Some(nix::unistd::Uid::from_raw(file_state.file_owner_uid)),
            Some(nix::unistd::Gid::from_raw(file_state.file_owner_gid)),
        )
        .map_err(|e| {
            hardener_common::error::HardeningError::Privilege(format!(
                "Failed to restore ownership: {}",
                e
            ))
        })?;

        Ok(())
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
    pub async fn rollback(&self, checkpoint_id: &CheckpointId) -> Result<()> {
        // Retrieve checkpoint and all file states
        let (_checkpoint, file_states) = self.get_checkpoint(checkpoint_id).await?;

        // Restore each file
        for file_state in &file_states {
            self.restore_file_state(file_state)?;
        }

        Ok(())
    }
}
