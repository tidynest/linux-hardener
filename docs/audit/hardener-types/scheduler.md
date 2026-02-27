# hardener-types::scheduler
**File:** `crates/hardener-types/src/scheduler.rs` | **Lines:** 51 (all production)

## Purpose
WASM-compatible scheduler configuration types mirroring `hardener-scheduler` backend structs. Used by the Leptos UI to configure scheduled scans and notifications without native-only dependencies.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `SchedulerUiConfig` | struct | Schedule definition: enabled, cron schedule, plugins, min_severity, notifications |
| `NotificationUiConfig` | struct | Notification settings: min severity, email config, webhook config |
| `EmailUiConfig` | struct | Email: enabled, recipients, from_address |
| `WebhookUiConfig` | struct | Webhook: enabled, url, format |
| `TestNotificationResult` | struct | Test result: success, message |

## Design Notes
- All fields use `#[serde(default)]` for JSON forward-compatibility
- No native-only dependencies — safe for WASM compilation
- Mirrors backend `SchedulerConfig` subset needed by the UI

## Flags
None.
