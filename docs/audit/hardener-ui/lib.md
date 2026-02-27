# hardener-ui::lib
**File:** `crates/hardener-ui/src/lib.rs` | **Lines:** 123

## Purpose
Crate root. Defines the `App` component with client-side router (Dashboard/Analysis/Hardening),
global error banner, skip-link for accessibility, and loads persisted scan data on mount.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `App` | component | Root application component with router and global state |
| `main` | fn | Entry point — mounts Leptos app to DOM |

## Internal Details
| Item | Description |
|------|-------------|
| Router | Five routes: `/` (Dashboard), `/analysis` (Analysis), `/hardening` (Hardening), `/remote` (Remote), `/scheduler` (Scheduler) |
| Error banner | Reads `AppState.has_error` signal, displays global error message |
| Skip-link | `<a>` element for keyboard accessibility — jumps to `#main-content` |
| On-mount scan | Calls `invoke_get_latest_scan()` to hydrate state from last session |
| DOM bootstrap | 4x `.expect()` for `document`, `body`, `getElementById`, `mount_to` — acceptable, app cannot function without DOM |

## Flags
None.
