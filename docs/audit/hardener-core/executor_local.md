# hardener-core::executor::local
**File:** `crates/hardener-core/src/executor/local.rs` | **Lines:** 87 (87 prod, 0 test)

## Purpose
Local `SystemExecutor` implementation: thin wrapper over `std::fs` and `std::process::Command` for direct host operations.

## Dependencies
- Imports from: `super::{CommandOutput, FileMetadata, SystemExecutor}`, `anyhow`, `async_trait`, `std::os::unix::fs::PermissionsExt`
- Used by: `context.rs` (default executor in `Context::new()`), `lib.rs` (re-exported as `LocalExecutor`)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `LocalExecutor` | struct | Unit struct, no state |
| `LocalExecutor::new()` | fn | Constructor |

## Data Flow
1. `Context::new()` creates `Arc::new(LocalExecutor::new())` as default executor
2. Plugin calls `ctx.executor().read_file(path)` -> `std::fs::read_to_string(path)`
3. `write_file` -> `std::fs::write(path, content)` (direct, no atomic write)
4. `file_metadata` -> `std::fs::metadata(path)`, extracts mode via `PermissionsExt::mode() & 0o777`
5. `execute_command` -> `Command::new(program).args(args).output()`
6. `command_exists` -> delegates to `which {program}`, checks exit code
7. `read_file_optional` -> NotFound returns `Ok(None)`, other errors propagate

## Flags
- None
