# hardener-state::scan_history
**File:** `crates/hardener-state/src/scan_history.rs` | **Lines:** 98 (all production, no tests)

## Purpose
Type definitions for GUI scan history: session IDs, status enum, session metadata.

## Dependencies
- Imports from: `serde` (Serialize/Deserialize), `rand` (ID generation), `std::time`
- Used by: `scan_manager.rs` (all types), `lib.rs` (re-exports), Tauri IPC handlers

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ScanSessionId` | newtype(String) | Unique session identifier with `From<&str>` and `From<String>` |
| `ScanSessionId::generate()` | fn | `scan_<millis>_<hex_random>` format |
| `ScanStatus` | enum | Running, Completed, Failed |
| `ScanStatus::as_str()` | fn | Converts to DB string |
| `ScanStatus::parse(s)` | fn | Parses from DB string (defaults to Running) |
| `ScanSession` | struct | id, started_at, completed_at, total_findings, total_plugins, status |

## Flags
None. Clean types-only file.
