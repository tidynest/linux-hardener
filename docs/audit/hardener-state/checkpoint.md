# hardener-state::checkpoint
**File:** `crates/hardener-state/src/checkpoint.rs` | **Lines:** 74 (all production, no tests)

## Purpose
Type definitions for checkpoint system: IDs, metadata, file state snapshots.
Rollback result types (`RollbackResult`, `FileRestoreResult`, `FileRestoreAction`) are re-exported from `hardener-types` for WASM compatibility.

## Dependencies
- Imports from: `serde` (Serialize/Deserialize), `hardener-types` (rollback types)
- Used by: `manager.rs` (all types), `lib.rs` (re-exports), CLI checkpoint commands, Tauri IPC

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `CheckpointId` | newtype(String) | Unique checkpoint identifier with `From<&str>` and `From<String>` |
| `Checkpoint` | struct | id, name, timestamp, username, signature |
| `FileState` | struct | path, content (Option), permissions, uid, gid |
| `FileRestoreResult` | re-export | path, action, success, error (from `hardener-types`) |
| `FileRestoreAction` | re-export | Restored, Removed, PermissionsRestored, Skipped (from `hardener-types`) |
| `RollbackResult` | re-export | checkpoint_id, name, success, files Vec (from `hardener-types`) |

## Data Flow
Types-only module — no data flow. Consumed by `manager.rs` for checkpoint CRUD and rollback operations.

## Flags
None. Clean types-only file with complete documentation.
