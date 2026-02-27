# hardener-ui::components::scan_history_tab
**File:** `crates/hardener-ui/src/components/scan_history_tab.rs` | **Lines:** 133

## Purpose
Scan history list and session detail viewer. Displays past scan sessions with
timestamps, status, and finding counts. Allows viewing individual session details.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ScanHistoryTab` | component | Scan session list with detail view |

## Internal Details
| Item | Description |
|------|-------------|
| Session list | Fetches via `invoke_get_scan_history()` with configurable limit |
| Session card | Shows date, status (pass/fail), finding count, host (local/remote) |
| Detail view | Calls `invoke_get_scan_session()` to display findings for selected session |
| Pagination | Load more button to fetch additional sessions |

## Flags
None.
