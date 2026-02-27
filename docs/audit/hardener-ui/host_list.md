# hardener-ui::components::host_list
**File:** `crates/hardener-ui/src/components/host_list.rs` | **Lines:** 188

## Purpose
Displays configured remote SSH hosts in a list with connect/disconnect/delete actions.
Fetches host list from Tauri IPC on mount.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `HostList` | component | Remote host list with connection management |

## Internal Details
| Item | Description |
|------|-------------|
| Host cards | Each host shows name, hostname, user, port, connection status |
| Connect | Calls `invoke_connect_remote()` with selected host profile |
| Disconnect | Calls `invoke_disconnect_remote()` |
| Delete | Confirmation dialog then `invoke_delete_remote_host()` |
| Add button | Opens `HostForm` in create mode |
| Edit | Opens `HostForm` in edit mode with pre-populated fields |

## Flags
None.
