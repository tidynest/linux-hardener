# hardener-core::context
**File:** `crates/hardener-core/src/context.rs` | **Lines:** 358 (301 prod, 57 test)

## Purpose
Execution context for plugins: bundles system detection, audit logging, checkpoint management, and executor reference into a single injectable object.

## Dependencies
- Imports from: `crate::executor::{SystemExecutor, local::LocalExecutor}`, `hardener_common::{error, types}`, `hardener_state::CheckpointManager`, `hostname`, `nix`, `serde`
- Used by: `plugin.rs` (re-exported as `Context`), `plugin_manager.rs` (passed to scan/apply), all 8 hardening plugins

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `Context` | struct | Holds audit log, checkpoint manager, shared data, system info, executor |
| `Context::new()` | fn | Default context with `LocalExecutor` and auto-detected `SystemInfo` |
| `Context::with_executor(Arc<dyn SystemExecutor>)` | fn | Context with custom executor |
| `Context::with_checkpoint_manager(CheckpointManager)` | fn | Context with rollback support |
| `Context::with_executor_and_checkpoint(...)` | fn | Both custom executor and checkpoint |
| `Context::set_checkpoint_manager(&mut self, ...)` | fn | Post-construction checkpoint setter |
| `Context::checkpoint_manager()` | fn | `Option<&Arc<CheckpointManager>>` accessor |
| `Context::log_audit(PluginAuditEntry)` | fn | Appends entry to in-memory audit log |
| `Context::system_info()` | fn | `&SystemInfo` accessor |
| `Context::executor()` | fn | `&Arc<dyn SystemExecutor>` accessor |
| `SystemInfo` | struct | Architecture, distribution, version, hostname, kernel version |
| `SystemInfo::detect()` | fn | Reads `/etc/os-release` + `uname()` + `hostname::get()` |
| `PluginAuditEntry` | struct | In-memory audit record (timestamp, plugin_id, operation, success, error) |
| `PluginAuditEntry::new(...)` | fn | Creates success/failure entry with current timestamp |
| `PluginAuditEntry::with_error(...)` | fn | Creates failure entry with error message |
| `AuditOperation` | enum | `Scan`, `Apply`, `Rollback`, `Validate` |

## Data Flow
1. CLI/plugin_manager creates `Context` with appropriate executor and optional checkpoint manager
2. Plugins receive `&Context` (scan) or `&mut Context` (apply/rollback)
3. Plugins call `ctx.executor()` for file/command ops, `ctx.log_audit()` for tracking
4. `SystemInfo::detect()` parses `/etc/os-release` via `read_os_release()` helper (called per-field)

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `SystemInfo::read_os_release()` | 147-161 | Parses `/etc/os-release` into `HashMap<String, String>` |
| `SystemInfo::detect_architecture()` | 163-165 | Returns `std::env::consts::ARCH` |
| `SystemInfo::detect_distribution()` | 167-179 | `ID` field from os-release, fallback to `NAME` |
| `SystemInfo::detect_distribution_version()` | 182-195 | `VERSION_ID` field, fallback to `VERSION` |
| `SystemInfo::detect_hostname()` | 197-202 | `hostname::get()` via `hostname` crate |
| `SystemInfo::detect_kernel_version()` | 205-211 | `nix::sys::utsname::uname()` release string |
| `PluginAuditEntry::current_timestamp()` | 103-110 | `SystemTime::now()` as Unix seconds |

## Flags
- **DEAD CODE** (line 27-28): `shared_data: Arc<RwLock<HashMap<String, String>>>` has `#[allow(dead_code)]` -- field is initialized but never read anywhere in the codebase. Retained for future inter-plugin communication. Status: **Flagged**.
