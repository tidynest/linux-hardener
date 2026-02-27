# hardener-ui::pages::scheduler_page
**File:** `crates/hardener-ui/src/pages/scheduler_page.rs` | **Lines:** 38

## Purpose
Top-level page for scheduled scanning configuration. Composes `ScheduleSection`
and `NotificationSection` into a unified scheduler settings layout.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `SchedulerPage` | component | Scheduler settings page layout |

## Internal Details
| Item | Description |
|------|-------------|
| Layout | Stacked sections: schedule configuration (top) + notification settings (bottom) |
| Components | `ScheduleSection` + `NotificationSection` |
| Route | `/scheduler` |

## Flags
None.
