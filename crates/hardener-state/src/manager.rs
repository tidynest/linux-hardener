//! Checkpoint manager for creating and managing system state snapshots.

use crate::checkpoint::{
    CheckpointId, ContentAbsence, FileRestoreAction, FileRestoreResult, FileState, RollbackResult,
};
use crate::{Checkpoint, CheckpointSigner};
use hardener_common::error::{HardeningError, Result};
use hardener_common::executor::{SystemExecutor, host_key_for};
use hardener_types::UNDELETABLE_ROLLBACK_PATHS;
use sqlx::{Row, SqlitePool};
use std::path::Path;

/// The mode every symlink on Linux has: the link type bit and 0777.
///
/// Stored in place of the captured mode, which `file_metadata` reads through the
/// link and so describes the target. It must not be 0, because restore reads a
/// zero mode as "this path was absent, remove it on rollback".
const SYMLINK_MODE: u32 = 0o120777;

/// The `st_mode` file-type field, and the value it holds for a directory.
///
/// `file_permissions` stores the whole mode, type bit included, so this is how
/// a captured directory is told from a captured file without a second column.
/// The distinction is load bearing on restore: a row with no content is not
/// therefore a directory. It may equally be a file captured metadata-only, as
/// the permissions plugin captures the account databases so their contents never
/// enter the database, or one whose content a best-effort capture could not
/// read. `mkdir -p` over either would put a directory where a file belongs, and
/// the chmod and chown that follow would succeed on it, so the rollback would
/// report the path restored.
///
/// ponytail: a checkpoint written before capture recorded the type bit stores a
/// directory as bare permission bits, so its directories read as files here and
/// are not recreated. Such a row cannot be told from a file's by any means the
/// rollback has, the path itself being gone; the upgrade path is a fresh
/// checkpoint, which every apply since takes.
const FILE_TYPE_MASK: u32 = 0o170000;
const DIRECTORY_TYPE_BITS: u32 = 0o040000;

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
                // A confirmed absence has no content to account for: the zero
                // mode is the whole record.
                file_content_absence: None,
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
                // The link target is what a restore writes, so there is no
                // missing content to account for.
                file_content_absence: None,
            });
        }

        // The absence is recorded beside the content because this is the one
        // place that knows why there is none. A row salvaged from a failed read
        // is otherwise identical to one captured metadata-only on purpose, and
        // restore reported success for both.
        let (file_content, file_content_absence) = match executor.read_file(file_path).await {
            Ok(content) => (Some(content.into_bytes()), None),
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
                    (None, Some(ContentAbsence::ReadFailed))
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
            file_content_absence,
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
                // A confirmed absence has no content to account for: the zero
                // mode is the whole record.
                file_content_absence: None,
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
            // This capture never reads bytes. That is the guarantee the
            // permissions plugin relies on for the account databases, whose
            // contents must never enter the checkpoint database, so it is a
            // deliberate absence rather than a shortfall.
            file_content_absence: Some(ContentAbsence::ByDesign),
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
                // A confirmed absence has no content to account for: the zero
                // mode is the whole record.
                file_content_absence: None,
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
                // The link target is what a restore writes, so there is no
                // missing content to account for.
                file_content_absence: None,
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
            // The same conditional shape, for the same reason and with the same
            // constraint: the absent arm must emit nothing at all, no tag byte
            // and no length prefix, or every checkpoint signed before this field
            // existed stops verifying.
            if let Some(absence) = file_state.file_content_absence {
                hash_context.update(absence.digest_tag());
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
                        // The read above is strict, so reaching here means the
                        // bytes were obtained. A link carries none by design.
                        file_content_absence: None,
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
                link_target,
                content_absence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(header.id.as_str())
            .bind(&file_state.file_path)
            .bind(&file_state.file_content)
            .bind(file_state.file_permissions)
            .bind(file_state.file_owner_uid as i64)
            .bind(file_state.file_owner_gid as i64)
            .bind(&file_state.file_link_target)
            .bind(file_state.file_content_absence.map(|a| a.as_column()))
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
                link_target,
                content_absence
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
                // A legacy NULL, and anything this build does not recognise,
                // reads as "not recorded". A checkpoint taken before the column
                // existed cannot say which of two opposite meanings applied, and
                // guessing would either invent a failure or hide one.
                file_content_absence: ContentAbsence::from_column(row.get("content_absence")),
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

        // A row recorded absent is answered by `rm -f`, which unlinks the entry
        // itself and does not follow it, so that restore lands on `path` and
        // nowhere else for the same reason the exemption above does. `systemctl
        // mask` is the case that needs it: the apply leaves a symlink to
        // /dev/null where the checkpoint recorded nothing, resolving it here
        // refused the removal, and the mask outlived the rollback meant to undo
        // it. Narrow deliberately, a row recorded absent and not symlinks in
        // general: a row carrying content is written through whatever stands at
        // the path, and a directory row's chmod and chown follow a link just as
        // readily, so both still answer to the check below.
        if recorded_absent(file_state) {
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
            // `ln` does not create the directory its link goes in, and
            // `systemctl disable` removes a `*.target.wants` directory as soon
            // as the enablement symlink it held was its last, so the directory
            // is routinely gone exactly when this row is what has to come back.
            // Done here rather than left to the directory's own row: that row
            // is restored first only because the file-state query orders by
            // path, and a checkpoint naming the link alone carries no such row.
            // `parent` is `None` only for the filesystem root, which is always
            // there and needs no creation. It is not re-checked against the
            // allowlist: the parent of an allow-listed path either carries the
            // same prefix or is the prefix's own parent, a system directory the
            // probe finds present, and `mkdir -p` over a directory that is
            // there does nothing at all.
            let parent_refusal = match path.parent() {
                Some(parent) => ensure_directory(executor, parent).await,
                None => None,
            };
            if let Some(refusal) = parent_refusal {
                return (
                    FileRestoreAction::Restored,
                    Err(HardeningError::Executor(refusal)),
                );
            }

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

        // Determine the required action. A row that is not recorded absent and
        // carries no content is a path that existed at capture (a directory, or
        // a file that was unreadable, even one with 0000 perms) and gets its
        // permissions and owner re-applied.
        let action = match &file_state.file_content {
            Some(_) => FileRestoreAction::Restored,
            None if recorded_absent(file_state) => FileRestoreAction::Removed,
            None => FileRestoreAction::PermissionsRestored,
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

        // A captured directory may have been removed since, and nothing else
        // here puts it back: the chmod and chown below are all a directory row
        // consists of, and both fail on a path that is not there. `systemctl
        // disable` deletes a `*.target.wants` directory the moment its last
        // enablement symlink goes, which is the ordinary case for a service
        // that is the only thing wanting its target. Failing to create it is
        // returned rather than folded in with the metadata warnings, because
        // the chmod that follows could then only fail for the same reason and
        // one cause should not be reported twice.
        if file_state.file_permissions & FILE_TYPE_MASK == DIRECTORY_TYPE_BITS
            && let Some(refusal) = ensure_directory(executor, path).await
        {
            return (action, Err(HardeningError::Executor(refusal)));
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

        // A row whose bytes the capture could not read has just had its
        // permissions and owner put back, and nothing else. That is everything
        // this row allows, and reporting it as a plain success is what made the
        // shortfall invisible: the operator asked for the file's contents back
        // and was told the rollback worked. Reported rather than fixed, which is
        // the settled rule that a rollback restores what it can and says what it
        // could not, so `rollback_success` is false and the exit code non-zero.
        //
        // Only `ReadFailed`. A directory and a deliberately metadata-only
        // account database have no bytes to be missing, and a row from before
        // this field existed says nothing either way, so neither is reported.
        if meta_result.is_ok()
            && file_state.file_content_absence == Some(ContentAbsence::ReadFailed)
        {
            return (
                action,
                Err(HardeningError::Executor(format!(
                    "{path_str}: permissions and owner were restored, but its content was \
                     not, because the checkpoint could not read it when it was taken. The \
                     file's contents are whatever the apply left there."
                ))),
            );
        }

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
            rollback_reloads: Vec::new(),
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

/// Creates `dir` if it may be missing, describing why it could not be created
/// and `None` when it is there or was made.
///
/// A rollback restores one recorded path at a time and creates nothing else on
/// the way, so a directory that went away after the checkpoint has to be put
/// back explicitly: `chmod` cannot be applied to a path that is not there, and
/// `ln` will not create the directory its link belongs in. Both sites call
/// here, rather than one relying on the other having run first.
///
/// The mkdir runs wherever the probe does not positively confirm the directory
/// is present: a probe that cannot answer is treated as "may be missing",
/// because `mkdir -p` on an existing directory does nothing, while skipping the
/// creation on the one host that needs it costs the restore. Going through
/// [`restore_command_refusal`] is what checks the exit code, `execute_command`
/// returning `Ok` for a command that ran and failed.
///
/// Deliberately a twin of `hardener_plugins::ensure_directory` rather than a
/// call to it: that one is `pub(crate)` in another crate and takes a
/// `hardener_core::Context`, and this crate depends on `hardener-common`, not
/// on core or plugins.
async fn ensure_directory(executor: &dyn SystemExecutor, dir: &Path) -> Option<String> {
    if matches!(executor.path_exists(dir).await, Ok(true)) {
        return None;
    }

    let dir_str = dir.to_string_lossy();
    restore_command_refusal(executor, "mkdir", &["-p", &dir_str], &dir_str).await
}

/// Whether a checkpoint row says nothing stood at its path when it was taken.
///
/// `file_permissions` holds the full st_mode, type bit included, so every path
/// that existed at capture has a non-zero mode and only a confirmed absence is
/// stored as 0; the content check keeps the answer honest for a row that
/// carries bytes. Named once because two separate decisions turn on it and they
/// have to agree: the action such a row restores to (a removal, not a write),
/// and whether the symlink guard applies to it (it does not, because a removal
/// unlinks the path itself). Written twice they would be free to drift, and a
/// guard that disagreed with the action it is guarding is how a masked unit
/// survived its own rollback.
fn recorded_absent(file_state: &FileState) -> bool {
    file_state.file_content.is_none() && file_state.file_permissions == 0
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
mod tests;
