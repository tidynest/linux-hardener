# hardener-state::scan_manager
**File:** `crates/hardener-state/src/scan_manager.rs` | **Lines:** 497 (389 prod, 108 test)

## Purpose
CRUD manager for GUI scan history. Persists scan sessions, plugin results, and findings to SQLite. The CLI remains stateless — this is Tauri-GUI only.

## Dependencies
- Imports from: `crate::scan_history::*` (types), `hardener_common::error`, `hardener_types::*` (Finding, ScanResult, etc.), `sqlx`
- Used by: Tauri IPC commands (`run_scan`, `get_scan_history`, `get_scan_session`)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ScanHistoryManager` | struct | Holds `SqlitePool` |
| `::new(pool)` | fn | Constructor |
| `::start_session()` | async fn | Creates running session, returns `ScanSessionId` |
| `::store_results(session_id, results)` | async fn | Inserts results + findings rows |
| `::complete_session(session_id, status, counts)` | async fn | Updates session with completion data |
| `::get_latest_scan()` | async fn | Latest completed session + all results |
| `::list_sessions(limit)` | async fn | Session metadata list (newest first) |
| `::cleanup_old_sessions(keep_count)` | async fn | Deletes sessions beyond retention limit |

## Data Flow
`start_session()` → INSERT session → `store_results()` → INSERT results + findings → `complete_session()` → UPDATE status

`get_latest_scan()` → SELECT session → `get_session_results()` → SELECT results → `get_result_findings()` → SELECT findings → deserialise JSON columns

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `get_session_results()` | 185-212 | Fetches results + their findings for a session |
| `get_result_findings()` | 215-258 | Deserialises finding rows back to `Finding` structs |
| `current_timestamp()` | 332-337 | Unix seconds from `SystemTime` |
| `category_to_str()` / `str_to_category()` | 340-365 | FindingCategory ↔ DB string |
| `severity_to_str()` / `str_to_severity()` | 369-388 | Severity ↔ DB string |

## Flags
- **SILENT FAILURE** (line 232, 235): `unwrap_or_default()` hides corrupted JSON — should log a warning.
- **SILENT DEFAULT** (line 364, 387): Unknown category/severity strings silently map to `Services`/`Info` fallbacks.
