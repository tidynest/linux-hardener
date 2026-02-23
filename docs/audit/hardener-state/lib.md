# hardener-state::lib
**File:** `crates/hardener-state/src/lib.rs` | **Lines:** 36 (25 prod, 11 test)

## Purpose
Crate root: declares modules and re-exports public API.

## Public Re-exports
- `audit::{ActionResult, ActionType, AuditEntry, AuditLogger}`
- `checkpoint::{Checkpoint, CheckpointId, FileRestoreAction, FileRestoreResult, FileState, RollbackResult}`
- `db::init_db`
- `hash_chain::HashChain`
- `manager::CheckpointManager`
- `scan_history::{ScanSession, ScanSessionId, ScanStatus}`
- `scan_manager::ScanHistoryManager`
- `signing::CheckpointSigner`

## Flags
- **DEAD CODE** (line 23-25): `pub fn add(left: u64, right: u64) -> u64` — cargo template stub. Never called. Delete.
- **DEAD TEST** (line 27-36): `it_works` test for the dead `add()` function. Delete.
