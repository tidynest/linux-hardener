# hardener-core::executor::ssh
**File:** `crates/hardener-core/src/executor/ssh.rs` | **Lines:** 199 (199 prod, 0 test)

## Purpose
SSH-based `SystemExecutor` for remote host hardening via the `openssh` crate. Executes file operations and commands over an SSH session.

## Dependencies
- Imports from: `super::{CommandOutput, FileMetadata, SystemExecutor}`, `anyhow`, `async_trait`, `openssh::{KnownHosts, Session, SessionBuilder}`
- Used by: `lib.rs` (re-exported as `SshExecutor`, `SshConfig`), future remote-hardening workflows
- Feature-gated: `cfg(feature = "system")`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `SshConfig` | struct | `host`, `port`, `user`, `identity_file`, `known_hosts`, `connect_timeout` |
| `SshConfig::default()` | fn | Port 22, `KnownHosts::Strict`, 30s timeout |
| `SshExecutor` | struct | Holds `openssh::Session`, host, user, port |
| `SshExecutor::connect(SshConfig)` | async fn | Builds SSH session via `SessionBuilder` |

## Data Flow
1. `connect()` configures `SessionBuilder` (user, port, known_hosts, keyfile, timeout) and calls `.connect()`
2. All trait methods delegate to `run_command()` which calls `session.raw_command(cmd).output()`
3. `read_file` uses `cat '{path}'`; `write_file` uses `sudo tee '{path}' > /dev/null << 'HARDENER_EOF'`
4. `file_metadata` parses `stat -c '%F %a %s'` output with `rsplitn(3, ' ')`
5. `command_exists` checks `which {program}` exit code

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `run_command(&self, cmd)` | 73-86 | Execute raw SSH command, return `CommandOutput` |

## Flags
- **SECURITY** (lines 105, 116, 128, 143, 150-153, 186-191): Path values are wrapped in single quotes (`'{}'`) for shell injection protection. This is sufficient for normal paths but a path containing a literal single quote could break the quoting. Low risk in practice since file paths are program-controlled, not user-supplied. Status: **Flagged** (low severity).
