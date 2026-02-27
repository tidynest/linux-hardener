# hardener-ui::pages::remote_page
**File:** `crates/hardener-ui/src/pages/remote_page.rs` | **Lines:** 51

## Purpose
Top-level page for remote SSH scanning. Composes `HostList`, `HostForm`, and `RemoteStatus`
components into a unified remote management layout.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `RemotePage` | component | Remote scanning page layout |

## Internal Details
| Item | Description |
|------|-------------|
| Layout | Two-column: host management (left) + connection status/scan (right) |
| Components | `HostList` + `HostForm` (left column), `RemoteStatus` (right column) |
| Route | `/remote` |

## Flags
None.
