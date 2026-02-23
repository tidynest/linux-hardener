# hardener-plugins::lib
**File:** `crates/hardener-plugins/src/lib.rs` | **Lines:** 170

## Purpose
Crate root. Re-exports all 9 plugin modules and provides shared helpers: `rollback_files_from_checkpoint()` (sync bridge creating a tokio runtime), `create_checkpoint_for_apply()`, `create_checkpoint_metadata_only_for_apply()`, and `create_plugin_registry()` (canonical factory registering all 8 plugins).

## Dependencies
- Imports from: `hardener_core` (Context, Checkpoint, PluginRegistry), `hardener_common::error`, `tracing`
- Used by: CLI commands, Tauri backend, plugin apply/rollback methods, tests

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `rollback_files_from_checkpoint` | fn | Sync wrapper — creates tokio runtime to run async rollback |
| `create_checkpoint_for_apply` | async fn | Captures file state before apply; returns checkpoint ID |
| `create_checkpoint_metadata_only_for_apply` | async fn | Captures mode/uid/gid only (no file contents) |
| `create_plugin_registry` | fn | Registers all 8 plugins, returns populated `PluginRegistry` |

## Flags
- **FIXED** (lines 103-108): `#[doc(hidden)]` only covered `AuditHardeningPlugin` re-export; moved to cover only the two macro-support crate re-exports (`hardener_common`, `hardener_core`).
- **DESIGN** (lines 122-129): `let _ = registry.register(...)` silently discards registration errors for all 8 plugins.
