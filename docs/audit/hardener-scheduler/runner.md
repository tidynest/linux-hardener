# hardener-scheduler::runner
**File:** `crates/hardener-scheduler/src/runner.rs` | **Lines:** 616

## Purpose
Scan execution orchestrator. Wires `PluginManager.execute_scan()` → severity filtering → JSON export → database persistence → notification dispatch in a single `run()` cycle. Well-separated concerns: `process_findings()` filters/maps, `build_summary()` aggregates counts, `build_json_export()` formats output.

## Dependencies
- Imports from: `crate::config`, `crate::db`, `crate::json_store`, `crate::notification`, `hardener_common`, `hardener_core`
- Used by: `daemon.rs` (scheduled scans), CLI (manual scans)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `TriggerType` | enum | Scheduled / Manual / Systemd |
| `ScanSummary` | struct | Post-scan summary for notifications |
| `ScanRunner` | struct | Orchestrates scan lifecycle |
| `ScanRunner::run()` | async fn | Full scan cycle: create session → scan → filter → export → complete |

## Flags
- None — file is clean. Good structure, thorough test coverage (~240 lines).
