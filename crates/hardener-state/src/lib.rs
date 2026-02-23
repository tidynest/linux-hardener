//! State management and checkpoint system for rollback functionality.

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
    Checkpoint, CheckpointId, FileRestoreAction, FileRestoreResult, FileState, RollbackResult,
};
pub use db::init_db;
pub use hash_chain::HashChain;
pub use manager::CheckpointManager;
pub use scan_history::{ScanSession, ScanSessionId, ScanStatus};
pub use scan_manager::ScanHistoryManager;
pub use signing::CheckpointSigner;
