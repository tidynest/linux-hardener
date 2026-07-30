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
/// The mode every symlink on Linux has: the link type bit and 0777.
///
/// Stored in place of the captured mode, which `file_metadata` reads through the
/// link and so describes the target. It must not be 0, because restore reads a
/// zero mode as "this path was absent, remove it on rollback".
const SYMLINK_MODE: u32 = 0o120777;

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
    // Where `systemctl disable` and `systemctl mask` record their state: the
    // wants/ symlinks and the mask symlinks to /dev/null. systemd.unit(5) calls
    // this the directory for "system units created by the administrator", and
    // it is the only unit directory the services plugin's changes reach. Its
    // package-owned counterpart /usr/lib/systemd/system is deliberately absent:
    // nothing this tool does writes there, so restoring into it could only
    // overwrite packaged unit files with stale copies.
    "/etc/systemd/system",
    "/root",
    "/boot",
];

/// Whether a file's content must be captured, or may be skipped if unreadable.
///
/// A path a plugin explicitly declared may be rewritten by that plugin, so a
/// checkpoint that holds no content for it offers no recovery. A file found by
/// recursing into a declared directory is incidental: refusing the whole
/// capture over one unreadable file there would break hosts that work today.
#[derive(Clone, Copy)]
enum ContentPolicy {
    Required,
    BestEffort,
}

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
    /// Records file content, permissions, and ownership. Absent files are
    /// represented with all-zero metadata. How an unreadable existing file's
    /// content is handled depends on `policy`: see [`ContentPolicy`].
    async fn capture_single_file(
        &self,
        executor: &dyn SystemExecutor,
        file_path: &Path,
        policy: ContentPolicy,
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
                file_link_target: None,
            });
        }

        // Asked before the read, because reading a symlink returns the target's
        // bytes and storing those is the state that cannot be restored. The mode
        // stored is `SYMLINK_MODE` rather than the captured one, which describes
        // the target.
        if let Some(target) = Self::link_target_of(executor, file_path).await? {
            return Ok(FileState {
                file_path: file_path.to_string_lossy().to_string(),
                file_content: None,
                file_permissions: SYMLINK_MODE,
                file_owner_uid: meta.uid,
                file_owner_gid: meta.gid,
                file_link_target: Some(target),
            });
        }

        let file_content = match executor.read_file(file_path).await {
            Ok(content) => Some(content.into_bytes()),
            Err(e) => match policy {
                ContentPolicy::Required => {
                    return Err(HardeningError::Executor(format!(
                        "Cannot checkpoint {}: its content could not be read ({e}). Without \
                         that content, a later rollback could not restore the file, so \
                         continuing would leave it unprotected.",
                        file_path.display(),
                    )));
                }
                ContentPolicy::BestEffort => {
                    tracing::warn!(
                        "Checkpoint for {} will not hold its content: {e}",
                        file_path.display(),
                    );
                    None
                }
            },
        };

        Ok(FileState {
            file_path: file_path.to_string_lossy().to_string(),
            file_content,
            file_permissions: meta.mode,
            file_owner_uid: meta.uid,
            file_owner_gid: meta.gid,
            file_link_target: None,
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
                file_link_target: None,
            });
        }

        // Asked here too, and for the same reason: a declared path can be a link
        // to a directory, and the chmod a metadata restore issues follows it.
        Ok(FileState {
            file_path: dir_path.to_string_lossy().to_string(),
            file_content: None,
            file_permissions: meta.mode,
            file_owner_uid: meta.uid,
            file_owner_gid: meta.gid,
            file_link_target: Self::link_target_of(executor, dir_path).await?,
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
                file_link_target: None,
            }]);
        }

        // Asked before the directory branch. `file_metadata` follows a link, so a
        // link to a directory reports `is_dir`, and recursing would capture the
        // target directory's files under paths that resolve back through the
        // link, so restoring them would write into the target directory.
        if let Some(target) = Self::link_target_of(executor, file_path).await? {
            return Ok(vec![FileState {
                file_path: file_path.to_string_lossy().to_string(),
                file_content: None,
                file_permissions: SYMLINK_MODE,
                file_owner_uid: meta.uid,
                file_owner_gid: meta.gid,
                file_link_target: Some(target),
            }]);
        }

        if meta.is_dir {
            self.capture_directory_recursive(executor, file_path).await
        } else {
            Ok(vec![
                self.capture_single_file(executor, file_path, ContentPolicy::Required)
                    .await?,
            ])
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
                file_states.push(
                    self.capture_single_file(executor, &child, ContentPolicy::BestEffort)
                        .await?,
                );
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
            // Only when present, the same way `file_content` is handled. A
            // checkpoint signed before this field existed carries `None` here and
            // hashes to what it hashed then, so its signature still verifies.
            if let Some(target) = &file_state.file_link_target {
                hash_context.update(target.as_bytes());
            }
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
                    // A snapshot that stored a link's followed content would be
                    // as unrestorable as the checkpoint it exists to undo.
                    let link_target = Self::link_target_of(executor, path).await?;
                    file_states.push(FileState {
                        file_path: reference.file_path.clone(),
                        file_content: link_target.is_none().then(|| content.into_bytes()),
                        file_permissions: if link_target.is_some() {
                            SYMLINK_MODE
                        } else {
                            meta.mode
                        },
                        file_owner_uid: meta.uid,
                        file_owner_gid: meta.gid,
                        file_link_target: link_target,
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
                owner_gid,
                link_target
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(header.id.as_str())
            .bind(&file_state.file_path)
            .bind(&file_state.file_content)
            .bind(file_state.file_permissions)
            .bind(file_state.file_owner_uid as i64)
            .bind(file_state.file_owner_gid as i64)
            .bind(&file_state.file_link_target)
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
                owner_gid,
                link_target
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
                file_link_target: row.get("link_target"),
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

    /// Whether `path` is a symlink, and what it points at.
    ///
    /// Fail-closed by propagating the error rather than reporting `None`: "not a
    /// symlink" and "could not tell" restore differently and only one of them is
    /// safe, so a capture that cannot answer refuses instead of storing a link's
    /// followed content. `readlink` is in coreutils, so on a host where this
    /// fails the capture had bigger problems than this check.
    async fn link_target_of(executor: &dyn SystemExecutor, path: &Path) -> Result<Option<String>> {
        executor.read_link(path).await.map_err(|e| {
            HardeningError::Executor(format!(
                "Cannot tell whether {} is a symlink, so it cannot be captured safely: {e}",
                path.display()
            ))
        })
    }

    /// Why a rollback must not write this path, or `None` if it may.
    ///
    /// One definition, because both phases ask it and their copies had come to
    /// disagree about the answer's weight: Phase 1 returned `Err` and abandoned
    /// the whole rollback, while Phase 2 recorded the same condition as one
    /// skipped file. The fatal copy ran first, so a single stock unit symlink
    /// under `/etc/systemd/system` pointing into the package-owned
    /// `/usr/lib/systemd/system` stopped `hardener rollback` restoring anything
    /// at all, on four of the five test distributions.
    ///
    /// The refusals themselves are unchanged and deliberate. A path outside the
    /// allowlist, or a symlink resolving outside it, would have a captured copy
    /// written somewhere this tool never modifies; a symlink that cannot be
    /// resolved is refused because what the write would reach is unknown, which
    /// is the fail-closed direction.
    ///
    /// The symlink half is meaningful only on the local filesystem. For a remote
    /// executor the path does not exist here, `is_symlink` is false, and the
    /// prefix allowlist is the whole check.
    fn rollback_target_refusal(&self, file_state: &FileState) -> Option<String> {
        let path = Path::new(&file_state.file_path);
        let path_str = &file_state.file_path;

        let within = |candidate: &str| {
            self.allowed_rollback_prefixes
                .iter()
                .any(|p| candidate.starts_with(p))
        };

        if !path_str.starts_with('/')
            || path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
            || !within(path_str)
        {
            return Some(format!(
                "Rollback path outside allowed directories: {path_str}"
            ));
        }

        // A link is restored by recreating the link, so the write lands on `path`
        // and nowhere else. Following it here would refuse precisely the entries
        // `file_link_target` exists to make restorable. The check below still
        // guards the other direction: a checkpoint recording a regular file whose
        // path is now a symlink pointing outside the allowlist.
        if file_state.file_link_target.is_some() {
            return None;
        }

        if path.is_symlink() {
            return match path.canonicalize() {
                Ok(resolved) if within(&resolved.to_string_lossy()) => None,
                Ok(_) => Some(format!(
                    "Rollback symlink {path_str} resolves outside allowed directories"
                )),
                Err(e) => Some(format!(
                    "Rollback target is a broken symlink: {path_str}: {e}"
                )),
            };
        }

        None
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

        if let Some(reason) = self.rollback_target_refusal(file_state) {
            return (
                FileRestoreAction::Skipped,
                Err(HardeningError::Config(reason)),
            );
        }

        // A symlink is restored by recreating the link, never by writing through
        // it: the content would land in whatever it points at, and chmod and
        // chown follow it just as readily, which is how a rollback came to be
        // able to overwrite a packaged unit file. `ln -sfn` creates the link, or
        // replaces whatever stands in its place.
        if let Some(target) = &file_state.file_link_target {
            let result = match restore_command_refusal(
                executor,
                "ln",
                &["-sfn", target, path_str],
                path_str,
            )
            .await
            {
                None => Ok(()),
                Some(refusal) => Err(HardeningError::Executor(refusal)),
            };
            return (FileRestoreAction::Restored, result);
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
        // apply creates none of these paths but /etc/sysctl.d and
        // /etc/audit/rules.d, which the kernel and audit plugins create above
        // their own checkpoints so that each capture records its own as present,
        // and /etc/security, which the pam plugin creates and no plugin
        // captures, so no apply's own checkpoint holds a row for it. A row calling
        // a path absent while the host actually has it is therefore an
        // untrustworthy row rather than an instruction to delete. A path that is
        // genuinely still absent needs no action at all, and must not be reported
        // as a failure.
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
        let chmod_warn =
            restore_command_refusal(executor, "chmod", &[mode_str.as_str(), path_str], path_str)
                .await;

        // Restore ownership: best-effort.
        let owner_str = format!(
            "{}:{}",
            file_state.file_owner_uid, file_state.file_owner_gid
        );
        let chown_warn =
            restore_command_refusal(executor, "chown", &[owner_str.as_str(), path_str], path_str)
                .await;

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

        // Phase 1: sort the targets into those a rollback may write and those it
        // must not, before anything is written.
        //
        // Refusing one path is not a reason to abandon the others. It used to be:
        // this loop returned `Err` on the first target outside the allowlist, so
        // one stock unit symlink under `/etc/systemd/system` resolving into the
        // package-owned `/usr/lib/systemd/system` left `hardener rollback`
        // restoring nothing on four of the five test distributions. Phase 2 had
        // always treated the same condition as a single skipped file, and it is
        // the honest reading: nothing out of bounds is read or written either
        // way, and the operator gets back the files that could be restored plus
        // a named reason for each that could not.
        let mut restorable: Vec<FileState> = Vec::with_capacity(file_states.len());
        let mut files: Vec<FileRestoreResult> = Vec::new();
        for fs in file_states {
            match self.rollback_target_refusal(&fs) {
                Some(reason) => files.push(FileRestoreResult {
                    restore_path: fs.file_path.clone(),
                    restore_action: FileRestoreAction::Skipped,
                    restore_success: false,
                    restore_error: Some(reason),
                }),
                None => restorable.push(fs),
            }
        }

        // Nothing left to restore is a rollback that did not happen, so it is
        // reported as an error rather than as a run whose every file was skipped.
        // It also means there is nothing to snapshot, so no orphan pre-rollback
        // checkpoint is persisted for a rollback that changed nothing.
        if restorable.is_empty() {
            return Err(HardeningError::Config(format!(
                "Rollback aborted: no path in checkpoint {} may be restored. {}",
                checkpoint_id.as_str(),
                files
                    .iter()
                    .filter_map(|f| f.restore_error.as_deref())
                    .collect::<Vec<_>>()
                    .join("; ")
            )));
        }

        // Reversible-rollback guarantee: with every target validated but nothing
        // yet written, snapshot the current state of the files about to be
        // overwritten so this rollback can itself be undone. Fail closed: if the
        // snapshot cannot be taken, refuse the rollback rather than destroy state
        // we could not back up. Placed after Phase 1 so only allow-listed paths
        // are read, and given only the restorable set so a refused path's content
        // is never read either.
        self.snapshot_current_state(
            executor,
            &format!("Before rollback to '{}'", checkpoint.checkpoint_name),
            &restorable,
        )
        .await?;

        // Phase 2: Apply the restores Phase 1 admitted.
        let mut all_ok = files.is_empty();
        for fs in &restorable {
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

/// Runs one restore command and describes why it did not happen, or `None` if
/// it did.
///
/// `execute_command` returns `Ok` for a process that started and exited
/// non-zero, so a transport error is only half of what can go wrong: a `chmod`
/// the target refuses and a `chmod` that never ran are different outcomes and
/// both mean the file is not as the checkpoint recorded it. Every restore
/// command in this module goes through here so the two cannot be told apart at
/// one site and conflated at the next.
///
/// A refusal that says nothing on stderr is still reported, by its exit status.
/// An empty description would put the caller back where it started, unable to
/// distinguish a failure from a success.
async fn restore_command_refusal(
    executor: &dyn SystemExecutor,
    program: &str,
    args: &[&str],
    path_str: &str,
) -> Option<String> {
    let detail = match executor.execute_command(program, args).await {
        Ok(output) if output.success() => return None,
        Ok(output) if output.stderr.trim().is_empty() => {
            format!("exited {}", output.exit_code)
        }
        Ok(output) => output.stderr.trim().to_string(),
        Err(e) => e.to_string(),
    };
    Some(format!("{program} {path_str}: {detail}"))
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
        let result =
            match restore_command_refusal(executor, "rm", &["-f", path_str], path_str).await {
                None => Ok(()),
                Some(refusal) => Err(HardeningError::Executor(refusal)),
            };
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
        // Phase-1 allowlist matches via `starts_with`, so an uncovered path is
        // refused and skipped rather than restored, and the rollback reports
        // failure. It no longer abandons the other files, but a declared path
        // silently not coming back is still the wrong outcome.
        for path in ["/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"] {
            assert!(
                DEFAULT_ROLLBACK_PREFIXES
                    .iter()
                    .any(|p| path.starts_with(p)),
                "{path} not covered by DEFAULT_ROLLBACK_PREFIXES (rollback would abort)"
            );
        }
    }

    #[test]
    fn default_prefixes_cover_the_systemd_paths_the_services_plugin_checkpoints() {
        // The services plugin checkpoints /etc/systemd/system before disabling
        // or masking a unit, so an uncovered path here would be skipped and the
        // unit never restored. Phase 1 used to abandon the entire rollback over
        // one such path; it now skips it and restores the rest, which makes this
        // check about whether the plugin's own writes come back rather than about
        // whether anything comes back at all.
        let path = "/etc/systemd/system/multi-user.target.wants/example.service";
        assert!(
            DEFAULT_ROLLBACK_PREFIXES
                .iter()
                .any(|p| path.starts_with(p)),
            "{path} not covered by DEFAULT_ROLLBACK_PREFIXES (rollback would abort)"
        );
    }

    #[test]
    fn default_prefixes_exclude_package_owned_unit_directories() {
        // Nothing this tool does writes to the packaged unit directory, so
        // restoring into it could only overwrite a distribution's unit files
        // with copies captured before a package update.
        for path in ["/usr/lib/systemd/system/sshd.service", "/usr/bin/systemctl"] {
            assert!(
                !DEFAULT_ROLLBACK_PREFIXES
                    .iter()
                    .any(|p| path.starts_with(p)),
                "{path} must stay outside the rollback allowlist"
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

    /// A command that ran and refused is not a command that worked.
    ///
    /// `execute_command` returns `Ok` for a process that started and exited
    /// non-zero, so a removal blocked by a read-only mount or an unwritable
    /// parent directory arrived here as success. Rollback then reported the
    /// file removed, `rollback_success` stayed true, and the operator was told
    /// the host was back at the checkpoint while the file the apply created was
    /// still on disk still doing its job.
    #[tokio::test]
    async fn a_removal_the_host_refused_is_not_a_successful_rollback() {
        use hardener_common::executor::FileMetadata;

        let manager = test_manager().await;
        let drop_in = "/etc/sysctl.d/99-hardener.conf";

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
            .with_command(
                "rm",
                &["-f", drop_in],
                hardener_common::executor::CommandOutput {
                    stdout: String::new(),
                    stderr: "rm: cannot remove '/etc/sysctl.d/99-hardener.conf': Read-only \
                             file system"
                        .to_string(),
                    exit_code: 1,
                },
            );

        let result = manager
            .rollback(&restoring, &cp_id)
            .await
            .expect("rollback must run rather than abort");

        assert!(
            !result.rollback_success,
            "a file the host refused to remove is still hardening it: {result:?}"
        );
        assert!(
            result.rollback_files[0]
                .restore_error
                .as_deref()
                .is_some_and(|e| e.contains("Read-only file system")),
            "the reason the host gave must reach the operator, got: {:?}",
            result.rollback_files[0].restore_error
        );
    }

    /// The same conflation on the metadata half of a restore.
    ///
    /// These two are best-effort by design, and the comment above them names
    /// the case they are expected to lose: a remote restore by a user who does
    /// not own the target. That is precisely a command that runs and is
    /// refused, so the one failure the design anticipates was the one it could
    /// not see, and a restore that recovered content but no permissions
    /// reported itself as complete.
    #[tokio::test]
    async fn permissions_the_host_refused_to_restore_are_reported() {
        use hardener_common::executor::{CommandOutput, FileMetadata};

        for refused in ["chmod", "chown"] {
            let manager = test_manager().await;
            let path = "/etc/shadow";
            let denied = || CommandOutput {
                stdout: String::new(),
                stderr: "Operation not permitted".to_string(),
                exit_code: 1,
            };

            let executor = MockExecutor::new()
                .with_file_metadata(
                    path,
                    "",
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
                .with_command(
                    "chmod",
                    &["0", path],
                    if refused == "chmod" {
                        denied()
                    } else {
                        ok_output()
                    },
                )
                .with_command(
                    "chown",
                    &["0:0", path],
                    if refused == "chown" {
                        denied()
                    } else {
                        ok_output()
                    },
                );

            let cp_id = manager
                .create_checkpoint_metadata_only(&executor, "perm-test", &[Path::new(path)])
                .await
                .expect("checkpoint");

            let result = manager
                .rollback(&executor, &cp_id)
                .await
                .expect("rollback must not abort on an allow-listed path");

            assert!(
                !result.rollback_success,
                "{refused} was refused, so the mode on {path} is not what the checkpoint \
                 recorded: {result:?}"
            );
            assert!(
                result.rollback_files[0]
                    .restore_error
                    .as_deref()
                    .is_some_and(|e| e.contains(refused) && e.contains("Operation not permitted")),
                "the refusal must name the command and the reason, got: {:?}",
                result.rollback_files[0].restore_error
            );
        }
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
    async fn capture_refuses_a_declared_path_whose_content_cannot_be_read() {
        // A checkpoint that silently records no content for a file it was asked
        // to protect is worse than no checkpoint: rollback restores the mode and
        // never the contents, so the file cannot be recovered.
        let manager = test_manager().await;
        let path = "/etc/security/faillock.conf";
        let executor = MockExecutor::new()
            .with_file(path, "deny = 3\n")
            .with_read_permission_denied(path);

        let result = manager
            .create_checkpoint(&executor, "unreadable", &[Path::new(path)])
            .await;

        let error = result
            .expect_err("a declared path whose content could not be read must fail the capture")
            .to_string();
        // Named in the capture's own words, not merely somewhere in the wrapped
        // cause: this mock's read error happens to repeat the path, but a real
        // one need not (a bare "Permission denied (os error 13)" does not), and
        // an operator cannot act on a failure that does not say which file.
        assert!(
            error.contains(&format!("Cannot checkpoint {path}")),
            "the failure must name the path it could not capture, got: {error}"
        );
    }

    #[tokio::test]
    async fn capture_tolerates_an_unreadable_child_of_a_declared_directory() {
        // Guard against over-correction: a plugin declares /etc/pam.d to record
        // it, not to rewrite what is inside. One odd file in there must not stop
        // an apply on a host that works today.
        let manager = test_manager().await;
        let dir = "/etc/pam.d";
        let child = "/etc/pam.d/odd";
        let executor = MockExecutor::new()
            .with_directory(dir)
            .with_file(child, "unreadable\n")
            .with_read_permission_denied(child);

        let result = manager
            .create_checkpoint(&executor, "sweep", &[Path::new(dir)])
            .await;

        let id = result.expect("an unreadable file found by recursion must not fail the capture");
        let (_, file_states) = manager.get_checkpoint(&id).await.expect("get_checkpoint");
        let captured = file_states
            .iter()
            .find(|s| s.file_path == child)
            .expect("the capture must still record a row for the unreadable child");
        assert_eq!(
            captured.file_content, None,
            "the tolerated child must carry no content, since none was read"
        );
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
        test_manager_with_allowlist(vec!["/etc/x".to_string()]).await
    }

    async fn test_manager_with_allowlist(prefixes: Vec<String>) -> CheckpointManager {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("mgr_test.db");
        let db_pool = crate::db::init_db(Some(&db_path)).await.expect("init_db");
        let key_path = dir.path().join("test.key");
        let signer = CheckpointSigner::new_with_path(&key_path).expect("signer");
        std::mem::forget(dir);
        CheckpointManager::new_with_allowlist(db_pool, signer, prefixes).expect("manager")
    }

    /// A link to a directory is a link, not a directory to walk into.
    ///
    /// `file_metadata` follows a link, so such a path reports `is_dir` and the
    /// recursive capture would descend into the target, storing the target
    /// directory's files under child paths that resolve back through the link.
    /// Restoring those would write into the target directory, which is the same
    /// defect one level down.
    ///
    /// The child registered below is what lets this test fail: without it the
    /// recursion would find nothing and a single link entry would be
    /// indistinguishable from a walk that happened to come back empty.
    #[tokio::test]
    async fn a_link_to_a_directory_is_captured_as_a_link_not_walked_into() {
        let exec = MockExecutor::new()
            .with_directory("/etc/x/wants")
            .with_symlink("/etc/x/wants", "/usr/lib/systemd/system")
            .with_file("/etc/x/wants/packaged.service", "[Unit]\n");
        let manager = test_manager_with_etc_x().await;

        let id = manager
            .create_checkpoint(&exec, "dirlink", &[Path::new("/etc/x/wants")])
            .await
            .expect("create_checkpoint");
        let (_, states) = manager.get_checkpoint(&id).await.expect("get_checkpoint");

        assert_eq!(
            states.len(),
            1,
            "a link must be one entry, not a walk of what it points at, got: {:?}",
            states.iter().map(|s| &s.file_path).collect::<Vec<_>>()
        );
        assert_eq!(
            states[0].file_link_target.as_deref(),
            Some("/usr/lib/systemd/system"),
            "the entry must record where the link points"
        );
        assert!(
            states[0].file_content.is_none(),
            "a link has no content of its own to store"
        );
    }

    /// A symlink must come back as a symlink, not as the content it pointed at.
    ///
    /// `file_metadata` follows a link, so a capture of `/etc/systemd/system`
    /// stored the contents of the packaged unit files its enablement links point
    /// at. Restoring that meant writing those bytes back through the link into
    /// `/usr/lib/systemd/system`, which the allowlist exists to prevent, so
    /// `systemctl disable` and `systemctl mask` state has never been recoverable
    /// on any distribution: the rollback either refused the path or, before that,
    /// abandoned the whole run over it.
    ///
    /// Recreating the link writes only the link, so the target's directory is
    /// never touched and the allowlist question is about the link's own path.
    /// The assertions below say that in three ways, because "it did not write
    /// through the link" is the property, and an `ln` that ran alongside a write
    /// would satisfy a weaker one.
    #[tokio::test]
    async fn a_captured_symlink_is_restored_as_a_link_not_as_content() {
        use hardener_common::executor::CommandOutput;

        let link = "/etc/x/autovt.service";
        let target = "/usr/lib/systemd/system/getty.service";
        let exec = MockExecutor::new()
            // Content is what the mock returns for a read, exactly as a real
            // read through the link would return the target's bytes.
            .with_file(link, "[Unit]\nDescription=Getty\n")
            .with_symlink(link, target)
            .with_command(
                "ln",
                &["-sfn", target, link],
                CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            );
        let manager = test_manager_with_etc_x().await;

        let id = manager
            .create_checkpoint(&exec, "svc", &[Path::new(link)])
            .await
            .expect("create_checkpoint");
        let result = manager.rollback(&exec, &id).await.expect("rollback");

        let log = exec.log();
        assert!(
            log.commands_executed
                .iter()
                .any(|(program, args)| program == "ln" && args.iter().any(|a| a == target)),
            "the link must be recreated pointing at its target, got: {:?}",
            log.commands_executed
        );
        assert!(
            !log.files_written.iter().any(|(p, _)| p == Path::new(link)),
            "nothing may be written through the link, got: {:?}",
            log.files_written
        );
        assert!(
            !log.commands_executed
                .iter()
                .any(|(program, args)| (program == "chmod" || program == "chown")
                    && args.iter().any(|a| a == link)),
            "chmod and chown follow a link, so neither may be issued for one, got: {:?}",
            log.commands_executed
        );
        assert!(
            result.rollback_success,
            "restoring a link is a success, got: {:?}",
            result.rollback_files
        );
    }

    /// One file that cannot be restored must not cost the operator every other
    /// file in the checkpoint.
    ///
    /// `/etc/systemd/system` is allow-listed and the services plugin declares
    /// it, so capture recurses in and collects the stock unit symlinks a
    /// distribution ships there. `autovt@.service` points into
    /// `/usr/lib/systemd/system`, which is deliberately not allow-listed,
    /// because writing a captured copy through that link would overwrite a
    /// packaged unit file. The guard is right to refuse it. Phase 1 then turned
    /// that one refusal into an abort of the entire rollback, so
    /// `hardener rollback` restored nothing at all on four of the five test
    /// distributions, measured 2026-07-29.
    ///
    /// Phase 2 already treats the identical condition as a per-file skip, so two
    /// copies of one guard disagreed and the fatal copy ran first.
    #[tokio::test]
    async fn one_unrestorable_path_does_not_abort_the_whole_rollback() {
        use hardener_common::executor::CommandOutput;

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_path_buf();
        let good = root.join("good.conf");
        let outward = root.join("outward.link");
        std::fs::write(&good, "current\n").expect("write good");
        // Resolves outside the allowlist, exactly as a stock unit symlink does.
        std::os::unix::fs::symlink("/etc", &outward).expect("symlink");

        let manager = test_manager_with_allowlist(vec![root.to_string_lossy().into_owned()]).await;
        // chmod and chown are registered because a restore issues both after the
        // write. Without them the run stops at a failed metadata command and the
        // assertion below would pass or fail for a reason that has nothing to do
        // with Phase 1, which is how a fixture comes to hide the thing under test.
        let ok = || CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        };
        let good_str = good.to_str().expect("utf8");
        let exec = MockExecutor::new()
            .with_file(good_str, "captured\n")
            .with_file(outward.to_str().expect("utf8"), "captured\n")
            .with_command("chmod", &["644", good_str], ok())
            .with_command("chown", &["0:0", good_str], ok());

        let id = manager
            .create_checkpoint(&exec, "mixed", &[good.as_path(), outward.as_path()])
            .await
            .expect("create_checkpoint");

        let result = manager
            .rollback(&exec, &id)
            .await
            .expect("one unrestorable path must not abort the rollback");

        let entry = |p: &Path| {
            result
                .rollback_files
                .iter()
                .find(|f| f.restore_path == p.to_string_lossy())
                .unwrap_or_else(|| panic!("{} missing from the result", p.display()))
        };
        assert!(
            entry(&good).restore_success,
            "the in-bounds file must still be restored, got: {:?}",
            entry(&good).restore_error
        );
        let refused = entry(&outward);
        assert!(
            !refused.restore_success,
            "the out-of-bounds symlink must not be written"
        );
        assert!(
            refused
                .restore_error
                .as_deref()
                .unwrap_or_default()
                .contains("resolves outside"),
            "the refusal must say why, got: {:?}",
            refused.restore_error
        );
        assert!(
            !result.rollback_success,
            "a rollback that skipped a file is not a successful one"
        );
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
        // The snapshot runs after Phase 1, over the restorable set only, so a
        // checkpoint whose every path is refused must not persist an orphan
        // pre-rollback checkpoint or read a refused path's content. This fixture
        // holds exactly one path and it is out of bounds, which is the
        // nothing-left-to-restore case: an error, not a run whose every file was
        // skipped.
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
