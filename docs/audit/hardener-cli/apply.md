# hardener-cli::commands::apply
**File:** `crates/hardener-cli/src/commands/apply.rs` | **Lines:** 163

## Purpose
Applies hardening changes — root check, plugin filtering, dry-run validation, checkpoint creation.

## Dependencies
- Imports from: `hardener_core::{ConfigLoader, Context, SystemExecutor}`, `hardener_plugins`, `hardener_state::{CheckpointManager, CheckpointSigner}`
- Used by: `main.rs` via `Apply` subcommand dispatch

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `run(plugin_filter, all, dry_run, format, quiet, executor)` | async fn | Apply hardening with optional dry-run |

## Data Flow
CLI args → root check → registry → per-plugin validate/apply → output results → exit 1 on failure

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `get_checkpoint_manager` | 11-28 | Init DB + signer for rollback support |

## Flags
- **SILENT FAILURE:** Config parse errors swallowed at line 59 via `unwrap_or_else`.
- **MISSING:** No `//!` module doc.
