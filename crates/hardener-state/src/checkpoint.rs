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
    /// Host this checkpoint was captured from ("local" or e.g. "ssh://root@host").
    pub host_key: String,
}

/// Why a row carries no content, when the path it names existed.
///
/// `file_content: None` had four meanings and could be told apart in only two
/// of them: a confirmed absence pairs it with a zero mode, and a symlink pairs
/// it with a link target. The remaining two were byte-identical. A capture that
/// deliberately stored no bytes and one that tried and failed produced the same
/// row, in the struct, in the table and in the digest, and restore treated both
/// as a permissions-only restore and reported success.
///
/// They need opposite handling. A directory has no bytes to restore and a
/// permissions restore is the whole job; an account database is captured
/// metadata-only so its contents never enter the checkpoint database, and that
/// is a guarantee rather than a shortfall. A file whose bytes could not be read
/// is neither: the rollback did not restore what the operator asked it to, and
/// saying so is the difference between a known limit and a silent one.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ContentAbsence {
    /// The capture chose not to read this path's bytes. A directory, or an
    /// account database captured metadata-only on purpose. Nothing is missing.
    ByDesign,
    /// The capture tried to read this path's bytes and could not, under
    /// a best-effort capture. The row is what could be salvaged, and a
    /// restore from it cannot put the content back.
    ReadFailed,
}

impl ContentAbsence {
    /// The bytes this contributes to a checkpoint's digest.
    ///
    /// Distinct and one byte each. The variant is hashed only when present, so
    /// a row that predates the field contributes nothing and hashes to what it
    /// hashed before, which is what keeps existing signatures verifying.
    pub(crate) fn digest_tag(self) -> &'static [u8] {
        match self {
            Self::ByDesign => b"d",
            Self::ReadFailed => b"f",
        }
    }

    /// How the variant is stored in `file_states.content_absence`.
    pub(crate) fn as_column(self) -> &'static str {
        match self {
            Self::ByDesign => "by_design",
            Self::ReadFailed => "read_failed",
        }
    }

    /// Reads the column back. An unrecognised value is `None`, the same as a
    /// legacy NULL: a row this build cannot interpret must claim nothing rather
    /// than guess which of two opposite meanings was intended.
    pub(crate) fn from_column(stored: Option<String>) -> Option<Self> {
        match stored.as_deref() {
            Some("by_design") => Some(Self::ByDesign),
            Some("read_failed") => Some(Self::ReadFailed),
            _ => None,
        }
    }
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
    /// The path this entry points at, when it is a symlink rather than a file.
    ///
    /// `file_content` is `None` for such an entry, because a symlink's content is
    /// the target's: storing it would restore another file's bytes through the
    /// link, into a directory the rollback allowlist deliberately excludes. That
    /// is why service enable, disable and mask state was unrecoverable before
    /// this field existed.
    ///
    /// `None` means positively not a symlink. A capture that could not tell
    /// refuses rather than storing `None`, because "not a link" and "could not
    /// look" restore differently and only one of them is safe.
    #[serde(default)]
    pub file_link_target: Option<String>,
    /// Why this row carries no content, when it carries none and the path was
    /// there.
    ///
    /// `None` on a row that carries bytes, on a confirmed absence, on a symlink,
    /// and on any row written before this field existed. The last of those is
    /// why a reader must treat `None` as "not recorded" rather than as either
    /// answer: a checkpoint taken by an earlier release cannot say which of the
    /// two it was, and guessing would either invent a failure or hide one.
    #[serde(default)]
    pub file_content_absence: Option<ContentAbsence>,
}

/// The `st_mode` bits `chmod` accepts: permissions, setuid, setgid and sticky.
///
/// Everything above this is the file-type field, which `file_permissions`
/// carries so a captured directory can be told from a captured file without a
/// second column.
const MODE_PERMISSION_BITS: u32 = 0o7777;

impl FileState {
    /// The mode as `chmod` takes it, which is also the mode to show a reader.
    ///
    /// One function rather than the mask written out at each site. Restore and
    /// the desktop's checkpoint expander are the two callers, and they answer
    /// the same question: what would this row set the path to. They disagreed
    /// until 2026-08-26, because only restore masked, so a file captured at
    /// 0644 was listed in the desktop as `100644`.
    ///
    /// Unpadded, so an ordinary file reads `644` rather than `0644`. A row with
    /// no permission bits at all is `0`, which is how a path recorded as absent
    /// renders; rollback reads that zero as "remove this path", so the row is a
    /// record of a deletion rather than a file with no access.
    pub fn restore_mode_string(&self) -> String {
        format!("{:o}", self.file_permissions & MODE_PERMISSION_BITS)
    }
}

// Rollback types are defined in hardener-types for WASM compatibility.
// Re-exported here for backward compatibility with native code.
pub use hardener_types::{FileRestoreAction, FileRestoreResult, RollbackResult};

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
