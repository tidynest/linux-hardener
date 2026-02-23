# hardener-scheduler::notification::email
**File:** `crates/hardener-scheduler/src/notification/email.rs` | **Lines:** 197

## Purpose
SMTP email notifications via `lettre`. Supports STARTTLS, reads password from `HARDENER_SMTP_PASSWORD` env var. Formats subject with severity prefix and body with aligned findings table.

## Dependencies
- Imports from: `super::Notifier`, `crate::config`, `crate::runner`, `lettre`, `async_trait`
- Used by: `notification/dispatcher.rs`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `EmailNotifier` | struct | Sends email to configured recipients |
| `EmailNotifier::new()` | fn | Constructor; returns `None` if disabled or misconfigured |

## Flags
- None — clean. Good validation, proper error handling.
