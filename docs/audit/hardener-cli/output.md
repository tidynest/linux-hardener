# hardener-cli::output
**File:** `crates/hardener-cli/src/output.rs` | **Lines:** 344

## Purpose
Format multiplexer — every output function branches on `OutputFormat` for JSON or coloured terminal text.

## Dependencies
- Imports from: `hardener_common::types::Severity`, `hardener_core::{ApplyResult, Finding, PluginMetadata, ValidationReport}`, `hardener_state::{Checkpoint, FileState, RollbackResult}`
- Used by: all `commands/*` modules for formatted output

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `status(format, msg)` | fn | Status line (suppressed in JSON mode) |
| `info(format, msg)` | fn | Info message |
| `error(format, msg)` | fn | Error message |
| `scan_results(format, results, mode)` | fn | Scan findings display |
| `apply_results(format, results)` | fn | Apply results display |
| `plugin_list(format, plugins)` | fn | Plugin listing |
| `checkpoint_list(format, checkpoints)` | fn | Checkpoint listing |
| `checkpoint_created(format, id)` | fn | Checkpoint creation confirmation |
| `checkpoint_details(format, checkpoint, files)` | fn | Checkpoint detail view |
| `rollback_result(format, result)` | fn | Rollback result display |
| `validation_reports(format, reports)` | fn | Dry-run validation display |

## Data Flow
Command handler → `output::*()` → `match format` → JSON `serde_json` or coloured `println!`

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `format_severity` | 288-296 | Severity → coloured 4-char label |
| `format_timestamp` | 298-309 | Unix epoch → local datetime string |

## Flags
- **INCONSISTENCY:** 5x `.unwrap()` on `serde_json::to_string_pretty()` (lines 50, 101, 140, 161, 270) — `rollback_result` already uses safe `match` pattern. Fix: apply same pattern to all 5.
- **UNUSED:** `_mode: ScanMode` parameter on `scan_results` (line 36).
