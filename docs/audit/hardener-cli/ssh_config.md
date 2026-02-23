# hardener-cli::ssh_config
**File:** `crates/hardener-cli/src/ssh_config.rs` | **Lines:** 106

## Purpose
Parses SSH connection CLI flags into a typed config, converts to core executor config.

## Dependencies
- Imports from: `hardener_core::SshConfig`, `openssh::KnownHosts`
- Used by: `main.rs` — creates `SshConnectionConfig` when `--ssh` flag is set

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `SshConnectionConfig` | struct | user, host, port, key, timeout, host-key policy |
| `SshConnectionConfig::from_cli(...)` | fn | Parse `user@host` string + CLI flags |
| `SshConnectionConfig::display()` | fn | Human-readable `user@host:port` |
| `SshConnectionConfig::to_core_config()` | fn | Convert to `hardener_core::SshConfig` |

## Data Flow
CLI `--ssh user@host` → `from_cli()` → `SshConnectionConfig` → `to_core_config()` → `SshExecutor::connect()`

## Flags
None — clean file.
