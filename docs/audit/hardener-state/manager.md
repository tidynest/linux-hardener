# hardener-state::manager
**File:** `crates/hardener-state/src/manager.rs` | **Lines:** 619 (all production, no test block)

## Purpose
Checkpoint manager: creates, stores, retrieves, deletes, and rolls back file-state snapshots in SQLite. Signs checkpoints with Ed25519 for tamper detection.

## Dependencies
- Imports from: `crate::checkpoint::*` (types), `crate::Checkpoint`, `crate::CheckpointSigner` (signing), `sqlx` (DB), `ring::digest` (SHA-256), `nix::unistd` (chown)
- Used by: `hardener-core::Context` (holds `Arc<CheckpointManager>`), CLI checkpoint/rollback commands, Tauri IPC handlers

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `CheckpointManager` | struct | Holds `SqlitePool` + `CheckpointSigner` |
| `::new(pool)` | fn | Creates manager with auto-loaded signer |
| `::new_with_signer(pool, signer)` | fn | Testing constructor (avoids root perms) |
| `::create_checkpoint(name, paths)` | async fn | Captures files recursively, signs, stores in DB |
| `::create_checkpoint_metadata_only(name, paths)` | async fn | Captures permissions only (no content/recursion) |
| `::get_checkpoint(id)` | async fn | Returns `(Checkpoint, Vec<FileState>)` |
| `::list_checkpoints()` | async fn | All checkpoints, newest first |
| `::delete_checkpoint(id)` | async fn | Deletes checkpoint + file states |
| `::rollback(id)` | async fn | Restores all files, returns `RollbackResult` |

## Data Flow
`create_checkpoint()` → `capture_file_state()` (recursive) → `generate_signature()` (SHA-256 digest → Ed25519 sign) → `store_checkpoint()` (SQLite INSERT)

`rollback()` → `get_checkpoint()` → for each `FileState`: `restore_file_state_tracked()` → write content / set permissions / chown → collect `FileRestoreResult`s → `RollbackResult`

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `generate_checkpoint_id()` | 39-50 | `cp_<millis>_<hex_random>` |
| `capture_single_file()` | 61-97 | Reads content + metadata; records non-existence as permissions=0 |
| `capture_directory_entry()` | 104-128 | Metadata only (permissions/ownership), no content |
| `capture_file_state()` | 140-165 | Dispatches to single-file or directory-recursive |
| `capture_directory_recursive()` | 168-192 | Recursively captures directory tree |
| `generate_signature()` | 201-236 | SHA-256(id+name+ts+user+file_hashes) → Ed25519 sign |
| `store_checkpoint()` | 340-396 | SQLite INSERTs for checkpoint + file states |
| `restore_file_state_tracked()` | 522-572 | Determines action (Restored/Removed/PermissionsRestored/Skipped), executes, returns tuple |

## Flags
- **COSMETIC** (line 417): `WHERE id =?` — missing space before `?` in SQL.
- **VERBOSE** (8 occurrences): `map_err(hardener_common::error::HardeningError::System)` — could use a `use` alias. Deferred.
