# hardener-ui::components::schedule_section
**File:** `crates/hardener-ui/src/components/schedule_section.rs` | **Lines:** 266

## Purpose
Cron schedule configuration component. Allows setting scan schedule (cron expression),
selecting which plugins to include, setting minimum severity threshold, and enabling/disabling
the scheduler. Persists configuration via Tauri IPC.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ScheduleSection` | component | Schedule form with cron editor, plugin selection, and save |

## Internal Details
| Item | Description |
|------|-------------|
| Cron input | Text input for cron expression with validation feedback |
| Plugin selection | Checkbox list of available plugins (fetched from registry) |
| Severity threshold | Dropdown: Info, Low, Medium, High, Critical |
| Enable/disable | Toggle switch for `scheduler_config.enabled` |
| Save | Calls `invoke_save_scheduler_config()` with `SchedulerUiConfig` |
| Load | Fetches config via `invoke_get_scheduler_config()` on mount |

## Flags
None.
