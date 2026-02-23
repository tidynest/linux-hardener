# hardener-cli::commands::checkpoint
**File:** `crates/hardener-cli/src/commands/checkpoint.rs` | **Lines:** 111

## Purpose
Checkpoint CRUD and rollback — list, create, delete, show, rollback operations.

## Dependencies
- Imports from: `hardener_state::{CheckpointManager, CheckpointSigner, init_db}`
- Used by: `main.rs` via `Checkpoint` and `Rollback` subcommand dispatch

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `list(format, quiet)` | async fn | List all checkpoints |
| `create(name, format, quiet)` | async fn | Create checkpoint from common config paths |
| `delete(checkpoint_id, format, quiet)` | async fn | Delete checkpoint by ID |
| `show(checkpoint_id, format, quiet)` | async fn | Show checkpoint details + files |
| `rollback(checkpoint_id, format, quiet)` | async fn | Restore checkpoint, fail on errors |

## Data Flow
CLI args → `get_checkpoint_manager()` → `CheckpointManager::*()` → `output::*()` display

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `get_checkpoint_manager` | 8-26 | Init DB + signer — **duplicated in apply.rs** |
| `collect_config_paths` | 100-111 | Static list of system config paths to snapshot |

## Flags
- **DUPLICATION:** `get_checkpoint_manager()` copied verbatim from `apply.rs`.
- **TYPO:** Line 94 — "Rollback completion with errors" → "completed".
- **MISSING:** No `//!` module doc.
