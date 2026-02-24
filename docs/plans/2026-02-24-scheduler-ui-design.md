# Scheduler UI Design

**Date:** 2026-02-24
**Status:** Implemented
**Scope:** GUI page for configuring scan scheduling and notifications

## Overview

Add a new top-level "Scheduler" page to the Tauri desktop app that exposes the
existing `hardener-scheduler` backend configuration through the GUI. Users can
enable/disable scheduled scans, pick a cron schedule, select plugins, configure
email and webhook notifications, and verify notification delivery with a test
button.

## Scope

**In scope:**
- Schedule configuration: enabled toggle, preset/custom cron, plugin selection,
  minimum severity
- Notification configuration: email (toggle, recipients, from address), webhook
  (toggle, URL, format), test notification button

**Out of scope (deferred):**
- Daemon start/stop control from GUI
- Daemon scan history (separate DB)
- Systemd timer generation/install from GUI

## Page Structure

New route: `/scheduler`
Nav link: "Scheduler" added after "Remote"

Two vertically stacked sections inside a single page component:

### Section 1 — Schedule Configuration

| Field | Widget | Notes |
|-------|--------|-------|
| Enabled | Toggle switch | Maps to `scheduler.enabled` |
| Schedule | Dropdown | Presets: "Daily at 2:00 AM", "Every 6 hours", "Every 12 hours", "Weekly on Monday", "Custom" |
| Custom cron | Text input | Visible only when "Custom" selected; 5-field cron format hint |
| Plugins | Checkbox group | 8 plugins; empty selection = all |
| Min severity | Dropdown | Critical, High, Medium, Low, Info |

Preset-to-cron mapping (6-field, seconds prefix):
- Daily at 2:00 AM → `0 0 2 * * *`
- Every 6 hours → `0 0 */6 * * *`
- Every 12 hours → `0 0 */12 * * *`
- Weekly on Monday → `0 0 2 * * Mon`

### Section 2 — Notifications

**Email subsection:**
| Field | Widget | Notes |
|-------|--------|-------|
| Enabled | Toggle switch | Maps to `notifications.email.enabled` |
| Recipients | List input | Add/remove email addresses |
| From address | Text input | Sender address |

**Webhook subsection:**
| Field | Widget | Notes |
|-------|--------|-------|
| Enabled | Toggle switch | Maps to `notifications.webhooks.enabled` |
| Endpoint URL | Text input | Single endpoint for now |
| Format | Dropdown | Slack, Discord, Generic |

**Test button:**
- "Send Test Notification" fires a dummy notification through all enabled channels
- Shows inline success/failure message

## Data Flow

```
SchedulerPage ──mount──→ get_scheduler_config ──→ read config.toml ──→ populate form
SchedulerPage ──save───→ save_scheduler_config ──→ write [scheduler] section to config.toml
SchedulerPage ──test───→ test_notification ──→ NotificationDispatcher ──→ inline result
```

## Tauri IPC Commands

| Command | Input | Output |
|---------|-------|--------|
| `get_scheduler_config` | — | `SchedulerConfig` |
| `save_scheduler_config` | `SchedulerConfig` | `()` |
| `test_notification` | — | `Result<String, String>` |

All three commands read/write the TOML config file used by the CLI daemon. The
GUI does not start the daemon itself — it only configures it.

## AppState Signals

```rust
pub scheduler_config: RwSignal<Option<SchedulerConfig>>,
pub is_saving_scheduler: RwSignal<bool>,
pub is_testing_notification: RwSignal<bool>,
```

## Component Tree

```
SchedulerPage
├── ScheduleSection
│   ├── enabled toggle
│   ├── preset dropdown + custom cron input
│   ├── plugin checkboxes
│   └── severity dropdown
└── NotificationSection
    ├── EmailConfig (toggle, recipients list, from address)
    ├── WebhookConfig (toggle, URL, format dropdown)
    └── TestNotificationButton
```

## UI Patterns

Follows established project conventions:
- `expect_context::<AppState>()` for global state access
- `leptos::task::spawn_local` for async IPC calls
- `Card` component for section containers
- Error messages routed to `app_state.error_message`
- Form validation before save (non-empty cron, valid email format)
- Let-chains for flat conditionals (no nested ifs)

## Config Persistence

The scheduler config lives in the `[scheduler]` section of the project's TOML
config file. The Tauri commands use `ConfigLoader` to read the file and
`toml_edit` to write back only the `[scheduler]` section without disturbing
other config sections.
