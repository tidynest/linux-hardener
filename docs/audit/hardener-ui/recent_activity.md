# hardener-ui::components::recent_activity
**File:** `crates/hardener-ui/src/components/recent_activity.rs` | **Lines:** 97

## Purpose
Dashboard widget showing the last scan and apply summary. Displays finding counts,
pass/fail status, and timestamps.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `RecentActivity` | component | Last scan/apply summary with finding counts and timestamps |

## Internal Details
| Item | Description |
|------|-------------|
| Scan summary | Reads `AppState.scan_results`, shows total findings and severity breakdown |
| Apply summary | Reads `AppState.apply_results`, shows success/failure counts |
| Safe defaults | Uses `.unwrap_or(false)` and `.unwrap_or(0)` — safe patterns, no panic risk |

## Flags
None.
