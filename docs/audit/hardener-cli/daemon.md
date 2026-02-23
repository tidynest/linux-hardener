# hardener-cli::commands::daemon
**File:** `crates/hardener-cli/src/commands/daemon.rs` | **Lines:** 221

## Purpose
CLI interface to the scheduled scanning daemon — start, run-once, status.

## Dependencies
- Imports from: `hardener_core::{ConfigLoader, Context, PluginManager}`, `hardener_scheduler::{Daemon, JsonStore, ScanHistoryManager, SchedulerConfig}`
- Used by: `main.rs` via `Daemon` subcommand; `load_scheduler_config` reused by `history.rs`, `scan.rs`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `start(format, quiet)` | async fn | Start daemon, blocks until Ctrl-C |
| `run_once(format, quiet)` | async fn | Single scan without daemon loop |
| `status(format, quiet, limit)` | async fn | Show config + recent sessions |
| `load_scheduler_config()` | fn | Load `[scheduler]` from config file — shared utility |

## Data Flow
CLI → load config → init DB + JsonStore → `Daemon::new()` → `start()` or `run_once()`

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `ConfigFile` | 190-194 | Deserialization wrapper for TOML scheduler section |
| `load_scheduler_config` | 199-221 | Check user → system config paths, parse TOML |

## Flags
None — clean file.
