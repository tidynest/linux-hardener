//! State management and checkpoint system for rollback functionality.

pub mod audit;
pub mod checkpoint;
pub mod db;
pub mod hash_chain;
pub mod manager;
pub mod signing;

pub use audit::{ActionResult, ActionType, AuditEntry, AuditLogger};
pub use checkpoint::{Checkpoint, CheckpointId, FileState};
pub use db::init_db;
pub use hash_chain::HashChain;
pub use manager::CheckpointManager;
pub use signing::CheckpointSigner;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
