# hardener-scheduler::config
**File:** `crates/hardener-scheduler/src/config.rs` | **Lines:** 258

## Purpose
Defines the `[scheduler]` section of the hardener config file. Supports scan scheduling, storage paths/retention, email (SMTP), and webhook notifications (Slack/Discord/Generic). Root-aware default paths via `libc::geteuid()`.

## Dependencies
- Imports from: `serde`, `dirs`, `libc`, `std::collections::HashMap`
- Used by: `runner.rs`, `daemon.rs`, `notification/` modules

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `SchedulerConfig` | struct | Root config with schedule, plugins, severity, storage, notifications |
| `StorageConfig` | struct | DB path, JSON output dir, retention settings |
| `NotificationConfig` | struct | Email + webhook sub-configs |
| `EmailConfig` | struct | SMTP settings (password via env var) |
| `WebhookConfig` | struct | List of webhook endpoints |
| `WebhookEndpoint` | struct | URL, format, headers with env var expansion |
| `WebhookFormat` | enum | Generic / Slack / Discord |

## Flags
- None — clean. Good defaults, proper `serde(default)`, thorough TOML round-trip tests.
