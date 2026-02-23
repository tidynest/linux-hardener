# hardener-core::lib
**File:** `crates/hardener-core/src/lib.rs` | **Lines:** 59 (59 prod, 0 test)

## Purpose
Crate root: module declarations, feature-gated re-exports, and public API surface for the entire `hardener-core` crate.

## Dependencies
- Re-exports from: `plugin`, `config`, `config_loader`, `context`, `executor`, `plugin_manager`, `registry`, `testing`
- Used by: All downstream crates (`hardener-cli`, `hardener-plugins`, `hardener-ui`, etc.)

## Public Interface
| Item | Source Module | Feature Gate |
|------|-------------|-------------|
| `ApplyResult`, `Change`, `ChangeType`, `Finding`, `PluginMetadata`, `ScanResult`, `ValidationIssue`, `ValidationReport` | `plugin` (from `hardener-types`) | always |
| `GlobalConfig`, `HardenerConfig`, `PluginConfig`, `PolicyException` | `config` | always |
| `ConfigLoader` | `config_loader` | always |
| `CommandOutput`, `FileMetadata`, `SystemExecutor` | `executor/mod` | always |
| `LocalExecutor` | `executor/local` | always |
| `MockExecutor` | `executor/mock` | always |
| `HardeningPlugin`, `Checkpoint`, `CheckpointId`, `CheckpointManager` | `plugin` (from `hardener-state`) | `system` |
| `Context`, `PluginAuditEntry`, `SystemInfo` | `context` | `system` |
| `SshConfig`, `SshExecutor` | `executor/ssh` | `system` |
| `PluginManager` | `plugin_manager` | `system` |
| `PluginRegistry` | `registry` | `system` |
| `MockPlugin` | `testing` | `system` + `test` |

## Module Declarations
| Module | Feature Gate | Description |
|--------|-------------|-------------|
| `plugin` | always | Core trait + type re-exports |
| `config` | always | Configuration structs |
| `config_loader` | always | Multi-source config loading |
| `executor` | always | Executor trait + local/mock |
| `context` | `system` | Execution context |
| `plugin_manager` | `system` | Dependency resolution + orchestration |
| `registry` | `system` | Plugin storage |
| `testing` | `system` | MockPlugin for tests |

## Flags
- None
