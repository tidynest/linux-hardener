# hardener-scheduler::notification::mod
**File:** `crates/hardener-scheduler/src/notification/mod.rs` | **Lines:** 242

## Purpose
Notification subsystem root. Defines `Notifier` trait, `NotificationResult` struct, severity parsing, and `meets_severity_threshold()` gating function. Thorough test suite (11 tests) covering all severity levels.

## Dependencies
- Imports from: `crate::runner`, `hardener_common::types`, `async_trait`
- Used by: `dispatcher.rs`, `email.rs`, `webhook.rs`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `NotificationResult` | struct | Success/failure outcome of a notification attempt |
| `Notifier` | trait | Async send + channel name |
| `parse_severity()` | fn | String → Severity enum, default Medium |
| `meets_severity_threshold()` | fn | Check if summary has findings at or above threshold |

## Flags
- None — clean.
