# hardener-scheduler::notification::dispatcher
**File:** `crates/hardener-scheduler/src/notification/dispatcher.rs` | **Lines:** 142

## Purpose
Coordinates all notification channels. Applies severity threshold gating, sends to each channel, and logs attempts to the database. Initialises email and webhook notifiers from config.

## Dependencies
- Imports from: `super::*`, `crate::config`, `crate::db`, `crate::runner`
- Used by: `runner.rs` (post-scan notifications)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `NotificationDispatcher` | struct | Manages notifiers and severity threshold |
| `NotificationDispatcher::dispatch()` | async fn | Send to all channels, log results |
| `NotificationDispatcher::notifier_count()` | fn | Number of configured channels |
| `NotificationDispatcher::has_notifiers()` | fn | Whether any channels are active |

## Flags
- **TYPO** (line 72): Fixed — doc said "in parallel" but dispatch is sequential.
