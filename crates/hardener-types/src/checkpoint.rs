//! Checkpoint and scan-session types shared by the Tauri backend and the
//! Leptos frontend.
//!
//! These five structs were hand-mirrored in `hardener-ui/src/types.rs` until
//! two fields fell through the copy: the incomplete list in #156 and
//! `checkpoint_verified` in #157. Defining them once here removes the drift
//! surface and puts them inside the tree
//! `scripts/validate/validate_gui_mock_fixtures.py` resolves, so a `PROBES`
//! entry can guard the mock against them.

use serde::{Deserialize, Serialize};

/// Checkpoint information returned to the frontend.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CheckpointInfo {
    pub checkpoint_id: String,
    pub checkpoint_name: String,
    pub checkpoint_created: String,
    pub checkpoint_user: String,
    /// Whether the checkpoint's signature was successfully verified.
    /// `false` indicates potential tampering or a missing signing key.
    pub checkpoint_verified: bool,
}

/// A checkpoint list together with whether a source was left out of it.
///
/// The system database is root-owned, so an unprivileged desktop usually
/// cannot read it. Returning the rows alone made a host holding five
/// privileged checkpoints render identically to one holding none, which is
/// the defect in #156: the operator could not tell a successful privileged
/// checkpoint from a failed one, because both produced no new row.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CheckpointList {
    pub checkpoints: Vec<CheckpointInfo>,
    /// The system database exists but could not be read from here, so this
    /// list may be missing every privileged checkpoint. `false` covers both
    /// `DatabaseReach::Read` and `DatabaseReach::Absent`: one means the rows
    /// are present, the other that there are none to miss.
    pub system_unreadable: bool,
    /// Rows in those databases that capture a **different** host, and so are
    /// deliberately not in `checkpoints`.
    ///
    /// `batch apply --execute` runs unprivileged and writes every remote
    /// host's pre-apply checkpoints into the local user database, the same one
    /// this list reads. Offering them here presents another machine's files as
    /// this machine's restore points. A count rather than silence, because a
    /// list that quietly shrank would be indistinguishable from a host that
    /// never took those checkpoints.
    pub other_host_count: usize,
}

/// Detailed checkpoint information including captured files.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CheckpointDetail {
    pub checkpoint_id: String,
    pub checkpoint_name: String,
    pub checkpoint_created: String,
    pub checkpoint_user: String,
    pub file_count: usize,
    pub files: Vec<CheckpointFileInfo>,
}

/// Individual file state within a checkpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CheckpointFileInfo {
    pub path: String,
    pub permissions: String,
    pub has_content: bool,
}

/// Scan session metadata for history display.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanSessionInfo {
    pub session_id: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub total_findings: i32,
    pub total_plugins: i32,
    pub status: String,
}
