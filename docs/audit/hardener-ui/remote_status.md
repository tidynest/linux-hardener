# hardener-ui::components::remote_status
**File:** `crates/hardener-ui/src/components/remote_status.rs` | **Lines:** 149

## Purpose
Remote connection status display and scan trigger. Shows active SSH connection details
and provides a button to initiate a remote security scan.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `RemoteStatus` | component | Connection status + remote scan trigger |

## Internal Details
| Item | Description |
|------|-------------|
| Status display | Shows connected host, user, and connection status from `AppState.remote_connection` |
| Scan button | Calls `invoke_remote_scan()` when connected; disabled when disconnected or scanning |
| Results | Updates `AppState.remote_scan_results` with scan findings |
| Loading states | Spinner during connection (`is_connecting`) and scan (`is_remote_scanning`) |

## Flags
None.
