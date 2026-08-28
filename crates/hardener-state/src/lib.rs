//! State management: everything the hardener persists between runs.
//!
//! Eight public modules, of which the one-line header this replaces named only
//! the first:
//!
//! - [`checkpoint`] and [`manager`]: the capture and restore that make an apply
//!   reversible.
//! - [`audit`] and [`hash_chain`]: the append-only action log and the chain
//!   that makes tampering with it detectable. Security-critical, and entirely
//!   undocumented here before.
//! - [`signing`]: the AES-256-GCM key protecting checkpoint integrity.
//! - [`scan_history`] and [`scan_manager`]: the desktop's own local scan
//!   history. **Not the scheduler's history**, which is a separate database in
//!   `hardener-scheduler` with its own host-aware schema; the two are easy to
//!   confuse and must not be mixed.
//! - [`db`]: the SQLite schema all of the above share.

pub mod audit;
pub mod checkpoint;
pub mod db;
pub mod hash_chain;
pub mod manager;
pub mod scan_history;
pub mod scan_manager;
pub mod signing;

pub use audit::{ActionResult, ActionType, AuditEntry, AuditLogger};
pub use checkpoint::{
    Checkpoint, CheckpointCreated, CheckpointId, FileRestoreAction, FileRestoreResult, FileState,
    RollbackResult,
};
pub use db::init_db;
pub use hash_chain::HashChain;
pub use manager::{CheckpointManager, DEFAULT_ROLLBACK_PREFIXES, OrphanedFileStates};
pub use scan_history::{ScanSession, ScanSessionId, ScanStatus};
pub use scan_manager::ScanHistoryManager;
pub use signing::CheckpointSigner;
