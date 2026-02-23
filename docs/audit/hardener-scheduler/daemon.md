# hardener-scheduler::daemon
**File:** `crates/hardener-scheduler/src/daemon.rs` | **Lines:** 382

## Purpose
Cron-based scanning daemon using `tokio-cron-scheduler`. Manages lifecycle: start → schedule job → wait for shutdown signal (SIGTERM/SIGINT) → graceful stop. Atomic `scan_in_progress` flag prevents concurrent scans.

## Dependencies
- Imports from: `crate::config`, `crate::db`, `crate::json_store`, `crate::runner`, `hardener_common`, `hardener_core`, `tokio_cron_scheduler`
- Used by: CLI daemon command

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `Daemon` | struct | Scheduled scanning daemon |
| `Daemon::new()` | fn | Constructor from config + DB + JSON store |
| `Daemon::run_once()` | async fn | Execute single scan (manual trigger) |
| `Daemon::start()` | async fn | Start cron scheduler loop (blocks until shutdown) |
| `Daemon::stop()` | async fn | Signal graceful shutdown |

## Flags
- **TYPO** (line 187): Fixed — "Crate" → "Create" in comment.
