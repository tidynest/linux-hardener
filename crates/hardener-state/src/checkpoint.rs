//! Checkpoint types for system state snapshots.
//!
//! Checkpoints capture the state of files before modifications,
//! allowing safe rollback of hardening changes.

use serde::{Deserialize, Serialize};

/// Unique identifier for a checkpoint.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct CheckpointId(String);

impl CheckpointId {
    /// Creates a new checkpoint ID from a string.
    pub fn new(id: impl Into<String>) -> CheckpointId {
        Self(id.into())
    }

    /// Returns the string representation of the checkpoint ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A checkpoint representing system state at a point in time.
///
/// Checkpoints capture file states before modifications, allowing
/// rollback to a previous known-good configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Checkpoint {
    /// Unique identifier for this checkpoint.
    pub checkpoint_id: CheckpointId,
    /// Human-readable name for this checkpoint.
    pub checkpoint_name: String,
    /// Unix timestamp when checkpoint was created.
    pub checkpoint_timestamp: i64,
    /// Username who created the checkpoint.
    pub checkpoint_username: String,
    /// Cryptographic signature for integrity verification.
    pub checkpoint_signature: Vec<u8>,
}

/// Represents the state of a single file at checkpoint time.
///
/// Captures file content, permissions, and ownership for restoration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileState {
    /// Path to the file.
    pub file_path: String,
    /// File content as bytes (None if file didn't exist).
    pub file_content: Option<Vec<u8>>,
    /// Unix file permissions (mode bits).
    pub file_permissions: u32,
    /// Owner user ID.
    pub file_owner_uid: u32,
    /// Owner group ID.
    pub file_owner_gid: u32,
}

/// Outcome of a single file restore during rollback.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileRestoreResult {
    /// Path that was restored.
    pub restore_path: String,
    /// What action was taken.
    pub restore_action: FileRestoreAction,
    /// Whether the restore succeeded.
    pub restore_success: bool,
    /// Where the restore failed.
    pub restore_error: Option<String>,
}

/// The type of restore action performed on a file.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum FileRestoreAction {
    /// File content and permissions were restored.
    Restored,
    /// File content was removed (it didn't exist at checkpoint time).
    Removed,
    /// Directory permissions were restored.
    PermissionsRestored,
    /// File was skipped (no action needed).
    Skipped,
}

/// Results of a full rollback operation.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RollbackResult {
    /// Checkpoint that was rolled back to.
    pub rollback_checkpoint_id: String,
    /// Name of the checkpoint.
    pub rollback_checkpoint_name: String,
    /// Whether all files were restored successfully.
    pub rollback_success: bool,
    /// Per-file restore results.
    pub rollback_files: Vec<FileRestoreResult>,
}

impl From<&str> for CheckpointId {
    fn from(s: &str) -> CheckpointId {
        Self(s.to_string())
    }
}

impl From<String> for CheckpointId {
    fn from(s: String) -> CheckpointId {
        Self(s)
    }
}
