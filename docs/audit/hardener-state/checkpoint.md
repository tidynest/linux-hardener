# hardener-state::checkpoint
**File:** `crates/hardener-state/src/checkpoint.rs` | **Lines:** 108 (all production, no tests)

## Purpose
Type definitions for checkpoint system: IDs, metadata, file state snapshots, rollback results.

## Dependencies
- Imports from: `serde` (Serialize/Deserialize)
- Used by: `manager.rs` (all types), `lib.rs` (re-exports), CLI checkpoint commands, Tauri IPC

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `CheckpointId` | newtype(String) | Unique checkpoint identifier with `From<&str>` and `From<String>` |
| `Checkpoint` | struct | id, name, timestamp, username, signature |
| `FileState` | struct | path, content (Option), permissions, uid, gid |
| `FileRestoreResult` | struct | path, action, success, error |
| `FileRestoreAction` | enum | Restored, Removed, PermissionsRestored, Skipped |
| `RollbackResult` | struct | checkpoint_id, name, success, files Vec |

## Data Flow
Types-only module — no data flow. Consumed by `manager.rs` for checkpoint CRUD and rollback operations.

## Flags
None. Clean types-only file with complete documentation.
