# hardener-core::executor (mod)
**File:** `crates/hardener-core/src/executor/mod.rs` | **Lines:** 72 (72 prod, 0 test)

## Purpose
Defines the `SystemExecutor` trait and supporting types (`CommandOutput`, `FileMetadata`) that abstract file and command operations across local, SSH, and mock backends.

## Dependencies
- Imports from: `anyhow`, `async_trait`
- Used by: `executor/local.rs`, `executor/ssh.rs`, `executor/mock.rs` (all implement trait), `context.rs` (stores `Arc<dyn SystemExecutor>`), all plugins (via context)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `SystemExecutor` | trait | `Send + Sync`, 7 async methods for file/command operations |
| `description()` | trait fn | Human-readable label (e.g., "local", "ssh://user@host:22") |
| `is_remote()` | trait fn | `bool` for remote-vs-local branching |
| `read_file(path)` | trait fn | Read file contents, error if missing |
| `read_file_optional(path)` | trait fn | Read file, `None` if missing |
| `write_file(path, content)` | trait fn | Write string to file |
| `path_exists(path)` | trait fn | Check path existence |
| `file_metadata(path)` | trait fn | Get exists/is_file/is_dir/mode/size |
| `execute_command(program, args)` | trait fn | Run command, return stdout/stderr/exit_code |
| `command_exists(program)` | trait fn | Check if program is available |
| `CommandOutput` | struct | `stdout: String`, `stderr: String`, `exit_code: i32` |
| `CommandOutput::success()` | fn | `exit_code == 0` |
| `FileMetadata` | struct | `exists`, `is_file`, `is_dir`, `mode: u32`, `size: u64` |

## Module Declarations
| Submodule | Feature Gate | Description |
|-----------|-------------|-------------|
| `local` | always | Local filesystem executor |
| `mock` | always | Mock executor for testing |
| `ssh` | `system` | SSH remote executor |

## Flags
- None
