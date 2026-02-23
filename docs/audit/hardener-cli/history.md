# hardener-cli::commands::history
**File:** `crates/hardener-cli/src/commands/history.rs` | **Lines:** 254

## Purpose
CLI interface for viewing and exporting scan history from the scheduler database.

## Dependencies
- Imports from: `hardener_scheduler::{ScanHistoryManager, db::*}`, `commands::daemon::load_scheduler_config`
- Used by: `main.rs` via `History` subcommand dispatch

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `list(format, quiet, limit, host, status)` | async fn | List recent scan sessions with filters |
| `show(session_id, format, quiet)` | async fn | Show one session's details + findings |
| `export(session_id, output_path, format, quiet)` | async fn | Export session to JSON file |

## Data Flow
CLI args → `open_database()` → `ScanHistoryManager` → query → format + output

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `open_database` | 177-182 | Opens scheduler DB via config |
| `format_timestamp` | 185-193 | Unix epoch → local datetime |
| `print_session_detail` | 196-245 | Detailed session print |
| `truncate_string` | 248-254 | Truncate with ellipsis |

## Flags
- **BUG:** `truncate_string` (line 252) slices bytes, not chars — panics on multi-byte UTF-8 boundary.
