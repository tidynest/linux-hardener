# hardener-ui::tauri_bindings
**File:** `crates/hardener-ui/src/tauri_bindings.rs` | **Lines:** 145

## Purpose
All Tauri IPC bindings. Provides async wrappers around `window.__TAURI__` invoke calls
with graceful browser-mode fallback when Tauri runtime is unavailable.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `tauri_available` | fn | Returns `true` if Tauri runtime is detected |
| `invoke_scan` | async fn | Trigger a security scan |
| `invoke_apply` | async fn | Apply hardening with selected plugins |
| `invoke_apply_dry_run` | async fn | Preview apply results without committing |
| `invoke_generate_report` | async fn | Generate compliance report for a framework |
| `invoke_get_latest_scan` | async fn | Fetch most recent scan results |
| `invoke_get_checkpoints` | async fn | List all checkpoints |
| `invoke_rollback` | async fn | Rollback to a specific checkpoint, returns `RollbackResult` with per-file status |

## Internal Details
| Item | Description |
|------|-------------|
| `invoke_command` | Private helper — serialises args, calls `__TAURI__.invoke`, deserialises response |
| `is_tauri_available` | JS-side check for `window.__TAURI__` existence |

## Flags
None.
