# hardener-ui::pages::dashboard_page
**File:** `crates/hardener-ui/src/pages/dashboard_page.rs` | **Lines:** 35

## Purpose
Dashboard layout composing the three main dashboard widgets into a single page view.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `DashboardPage` | component | Composes `SecurityScore` + `QuickActions` + `RecentActivity` |

## Internal Details
| Item | Description |
|------|-------------|
| Layout | Vertical stack of three child components |
| State | Reads from `AppState` signals — no local state of its own |

## Flags
None.
