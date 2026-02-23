# hardener-cli::commands::systemd
**File:** `crates/hardener-cli/src/commands/systemd.rs` | **Lines:** 243

## Purpose
Manages systemd unit files for scheduled hardening scans — generate, install, uninstall, status.

## Dependencies
- Imports from: `hardener_scheduler::systemd::{SystemdGenerator, cron_to_calendar, service_name, timer_name}`
- Used by: `main.rs` via `Systemd` subcommand dispatch

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `generate(output_dir, binary_path, schedule, config_path, quiet)` | async fn | Generate .service + .timer files |
| `install(user_mode, schedule, config_path, quiet)` | async fn | Write units, daemon-reload, enable timer |
| `uninstall(user_mode, quiet)` | async fn | Disable timer, remove files, daemon-reload |
| `status(user_mode, quiet)` | async fn | Show systemctl status output |

## Data Flow
CLI args → `SystemdGenerator` → unit content → write to dir or stdout → `systemctl` commands

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `resolve_binary_path` | 227-232 | Default to `current_exe()` |
| `resolve_calendar` | 235-243 | Detect cron vs calendar format |

## Flags
None — clean file.
