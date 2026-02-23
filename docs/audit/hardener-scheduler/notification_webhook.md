# hardener-scheduler::notification::webhook
**File:** `crates/hardener-scheduler/src/notification/webhook.rs` | **Lines:** 360

## Purpose
HTTP webhook notifications for Slack, Discord, and generic endpoints. Supports `${VAR}` environment variable expansion in headers. Format-specific payloads with severity-based colour coding.

## Dependencies
- Imports from: `crate::config`, `crate::runner`, `super::Notifier`, `reqwest`, `async_trait`
- Used by: `notification/mod.rs` (registered as notifier)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `WebhookNotifier` | struct | Sends notifications to a single webhook endpoint |
| `WebhookNotifier::new()` | fn | Constructor; returns `None` if URL is empty |

## Flags
- **TYPO** (line 45): Fixed — "replace" → "replaced" in doc comment.
