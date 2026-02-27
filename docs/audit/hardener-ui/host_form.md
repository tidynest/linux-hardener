# hardener-ui::components::host_form
**File:** `crates/hardener-ui/src/components/host_form.rs` | **Lines:** 193

## Purpose
Form for creating and editing remote SSH host profiles. Validates inputs and persists
profiles via Tauri IPC for use with remote scanning.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `HostForm` | component | SSH host profile form with validation |

## Internal Details
| Item | Description |
|------|-------------|
| Fields | name, hostname, user (optional), port (default 22), key_file (optional), host_key_checking (default true) |
| Validation | Non-empty name/hostname, valid port range, key file path exists |
| Save | Calls `invoke_save_remote_host()` with `RemoteHostProfile` |
| Edit mode | Pre-populates fields when editing existing host |
| Cancel | Resets form and hides editor |

## Flags
None.
