# hardener-core::executor::mock
**File:** `crates/hardener-core/src/executor/mock.rs` | **Lines:** 315 (315 prod, 0 test)

## Purpose
Mock `SystemExecutor` for deterministic unit testing: virtual filesystem, command registry, and operation log -- no real I/O.

## Dependencies
- Imports from: `super::{CommandOutput, FileMetadata, SystemExecutor}`, `anyhow`, `async_trait`
- Used by: All plugin test suites, `testing::MockPlugin`, `context.rs` tests (via `Context::with_executor`)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `MockExecutor` | struct | Virtual FS + command map + operation log, all `Arc<Mutex<..>>` |
| `MockExecutor::new()` | fn | Empty executor, local mode |
| `MockExecutor::remote()` | fn | Builder: sets `is_remote = true` |
| `MockExecutor::with_description(&str)` | fn | Builder: custom description string |
| `MockExecutor::with_file(path, content)` | fn | Builder: add file + auto-generated metadata (mode 0o644) |
| `MockExecutor::with_file_metadata(path, content, metadata)` | fn | Builder: add file with custom metadata |
| `MockExecutor::with_directory(path)` | fn | Builder: add directory metadata (mode 0o755) |
| `MockExecutor::with_command(program, args, output)` | fn | Builder: register command response |
| `MockExecutor::with_command_exists(program, exists)` | fn | Builder: explicit existence check result |
| `MockExecutor::log()` | fn | Snapshot of `MockExecutorLog` (files read/written, commands executed) |
| `MockExecutor::clear_log()` | fn | Reset operation log |
| `MockExecutor::files()` | fn | Snapshot of current virtual filesystem |
| `MockExecutorLog` | struct | `files_read`, `files_written`, `commands_executed` |

## Data Flow
1. Test setup: chain builders (`with_file`, `with_command`) to populate virtual state
2. Plugin under test calls `executor.read_file()`, `executor.execute_command()`, etc.
3. Mock records all operations in `log`; returns pre-registered responses or error for unregistered
4. Test assertions check `executor.log()` and `executor.files()` for side effects

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| (SystemExecutor impl methods) | 189-314 | 7 trait methods: delegate to HashMap lookups, log operations |

## Flags
- None (`.expect()` calls on mutex locks are appropriate for test infrastructure -- poisoned mutex indicates a test bug).
