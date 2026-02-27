# hardener-ui::tauri_bindings
**File:** `crates/hardener-ui/src/tauri_bindings.rs` | **Lines:** 404

## Purpose
All Tauri IPC bindings. Provides async wrappers around `window.__TAURI__` invoke calls
with graceful browser-mode fallback when Tauri runtime is unavailable.

## Public Interface — Core Operations
| Item | Kind | Lines | Description |
|------|------|-------|-------------|
| `tauri_available` | fn | 20-31 | Returns `true` if Tauri runtime is detected |
| `invoke_scan` | async fn | 54-72 | Trigger security scan with plugin filter + config path |
| `invoke_apply` | async fn | 74-92 | Apply hardening with selected plugins + config path |
| `invoke_apply_dry_run` | async fn | 94-112 | Preview apply results without committing |
| `invoke_generate_report` | async fn | 114-129 | Generate compliance report for a framework |
| `invoke_export_report` | async fn | 131-151 | Export report with format + output path |
| `invoke_get_latest_scan` | async fn | 153-162 | Fetch most recent scan results |

## Public Interface — Checkpoint Management
| Item | Kind | Lines | Description |
|------|------|-------|-------------|
| `invoke_get_checkpoints` | async fn | 164-172 | List all checkpoints |
| `invoke_create_checkpoint` | async fn | 174-189 | Create manual checkpoint with name |
| `invoke_delete_checkpoint` | async fn | 191-204 | Delete checkpoint by ID |
| `invoke_get_checkpoint_detail` | async fn | 237-252 | Get checkpoint detail with captured files |
| `invoke_rollback` | async fn | 254-272 | Rollback to checkpoint, returns per-file status |

## Public Interface — Scan History
| Item | Kind | Lines | Description |
|------|------|-------|-------------|
| `invoke_get_scan_history` | async fn | 206-220 | Fetch scan sessions with limit |
| `invoke_get_scan_session` | async fn | 222-235 | Fetch single session by ID |

## Public Interface — Remote Scanning
| Item | Kind | Lines | Description |
|------|------|-------|-------------|
| `invoke_list_remote_hosts` | async fn | 274-282 | List configured remote hosts |
| `invoke_save_remote_host` | async fn | 284-298 | Save/update remote host profile |
| `invoke_delete_remote_host` | async fn | 300-312 | Delete remote host by name |
| `invoke_connect_remote` | async fn | 314-328 | Establish SSH connection |
| `invoke_disconnect_remote` | async fn | 330-338 | Close SSH connection |
| `invoke_remote_scan` | async fn | 340-354 | Run scan on connected remote host |

## Public Interface — Scheduler
| Item | Kind | Lines | Description |
|------|------|-------|-------------|
| `invoke_get_scheduler_config` | async fn | 356-364 | Fetch current scheduler configuration |
| `invoke_save_scheduler_config` | async fn | 366-380 | Save scheduler configuration |
| `invoke_test_notification` | async fn | 382-396 | Send test notification |

## Public Interface — Config Picker
| Item | Kind | Lines | Description |
|------|------|-------|-------------|
| `invoke_validate_config` | async fn | 398-404 | Validate config file and return summary |

## Internal Details
| Item | Description |
|------|-------------|
| `invoke_command` | Private helper — serialises args, calls `__TAURI__.invoke`, deserialises response |
| `is_tauri_available` | JS-side check for `window.__TAURI__` existence |

## Flags
None.
