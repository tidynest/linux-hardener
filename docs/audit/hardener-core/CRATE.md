# hardener-core Crate Audit

## Crate Purpose
Central crate for the Linux System Hardener: defines the plugin contract (`HardeningPlugin` trait), executor abstraction (`SystemExecutor` trait), configuration system, plugin registry, and dependency-ordered plugin manager. Everything downstream depends on this crate.

## Architecture Overview

### Feature Gating
The `system` feature gates native-only modules that depend on `hostname`, `nix`, `petgraph`, and `openssh`. WASM builds exclude these, using only `config`, `config_loader`, `plugin` (re-exports), and `executor/{mod,local,mock}`.

### Strategy Pattern
`SystemExecutor` trait with three implementations:
- **LocalExecutor** -- direct `std::fs` + `std::process::Command` for the host machine
- **SshExecutor** -- `openssh` crate for remote hosts (feature-gated)
- **MockExecutor** -- virtual filesystem + command registry for deterministic tests

### Plugin Lifecycle
```
register() ──> resolve_dependencies() ──> execution_order() ──> execute_scan/apply()
    │                  │                         │                       │
PluginRegistry    petgraph DAG            Topo sort            trait method calls
```

### Config Cascade
```
HardenerConfig::default()
    │
    ▼
/etc/linux-hardener/config.toml        (system, optional)
    │
    ▼
~/.config/linux-hardener/config.toml   (user, optional)
    │
    ▼
--config <path>                        (CLI, required if specified)
    │
    ▼
HARDENER_ENABLED_PLUGINS               (env var override)
HARDENER_DISABLED_PLUGINS              (env var override)
```

## Architecture Diagram
```
lib.rs (crate root, re-exports)
 ├── config.rs ◄── config_loader.rs ◄── config_validation.rs
 │     │
 │     ▼
 ├── plugin.rs (trait + re-exports from hardener-types/common/state)
 │     │
 │     ▼
 ├── context.rs [system] ──► executor/mod.rs (SystemExecutor trait)
 │     │                       ├── executor/local.rs
 │     │                       ├── executor/mock.rs
 │     │                       └── executor/ssh.rs [system]
 │     ▼
 ├── registry.rs [system] ◄── plugin.rs (HardeningPlugin trait objects)
 │     │
 │     ▼
 ├── plugin_manager.rs [system] (petgraph DAG, topo sort, scan/apply)
 │
 └── testing.rs [system] (MockPlugin for test suites)
```

## Inter-Module Data Flow
1. **Startup**: CLI creates `ConfigLoader` -> `HardenerConfig`; creates `PluginRegistry`; registers plugin `Box<dyn HardeningPlugin>` instances
2. **Preparation**: `PluginManager::new(registry)` -> `resolve_dependencies()` builds petgraph DAG -> `execution_order()` returns topo-sorted `Vec<PluginId>`
3. **Execution**: `Context` created with executor + optional checkpoint manager; passed to `execute_scan(&ctx)` or `execute_apply(&mut ctx, &config, &plugin_ids)`
4. **Per-plugin**: Manager calls `registry.get(id)` -> `plugin.scan(ctx)` or `plugin.apply(ctx, config.get_plugin_config(id))`
5. **Results**: Aggregated `Vec<ScanResult>` or `Vec<ApplyResult>` returned to CLI for display/persistence

## Public Interface Summary
| Module | Key Exports | Feature Gate |
|--------|------------|-------------|
| `config` | `HardenerConfig`, `GlobalConfig`, `PluginConfig`, `PolicyException` | always |
| `config_loader` | `ConfigLoader` | always |
| `config_validation` | `validate_config()`, `validate_directive_key()` | always |
| `plugin` | `HardeningPlugin` trait, 14 type re-exports | trait: `system`; types: always |
| `context` | `Context`, `SystemInfo`, `PluginAuditEntry`, `AuditOperation` | `system` |
| `executor/mod` | `SystemExecutor` trait, `CommandOutput`, `FileMetadata` | always |
| `executor/local` | `LocalExecutor` | always |
| `executor/mock` | `MockExecutor`, `MockExecutorLog` | always |
| `executor/ssh` | `SshExecutor`, `SshConfig` | `system` |
| `registry` | `PluginRegistry` | `system` |
| `plugin_manager` | `PluginManager` | `system` |

## Aggregate Flags
| ID | File | Severity | Category | Description | Status |
|----|------|----------|----------|-------------|--------|
| F-01 | context.rs:27-28 | Low | Dead Code | `shared_data` field has `#[allow(dead_code)]`, never read | Flagged |
| F-02 | registry.rs:61-110 | Low | Duplication | 4x identical read-lock acquisition with error mapping | Flagged |
| F-03 | registry.rs:14 | Low | Design | `Arc<Box<dyn HardeningPlugin>>` double indirection | Flagged |
| F-04 | config.rs:133 | Medium | Bug | Unknown `plugin_id` fallback returns `&self.ssh` instead of neutral default | Flagged |
| F-05 | executor/ssh.rs | Low | Security | Single-quote path wrapping; theoretical injection if path contains `'` | Flagged |

## Unwrap Count
**Zero production `.unwrap()` calls.** All error handling uses `?`, `map_err`, `unwrap_or_default()`, or `unwrap_or()` with explicit fallbacks. The only `.expect()` calls are in `MockExecutor` (test infrastructure, appropriate for mutex poisoning).

## Line Count Summary
| Module | Total | Prod | Test |
|--------|-------|------|------|
| config_loader.rs | 403 | 300 | 103 |
| config_validation.rs | 397 | 250 | 147 |
| plugin_manager.rs | 334 | 334 | 0 |
| executor/mock.rs | 315 | 315 | 0 |
| context.rs | 313 | 256 | 57 |
| executor/ssh.rs | 221 | 221 | 0 |
| config.rs | 161 | 29 | 132 |
| testing.rs | 148 | 148 | 0 |
| registry.rs | 111 | 26 | 85 |
| plugin.rs | 93 | 81 | 12 |
| executor/local.rs | 88 | 88 | 0 |
| executor/mod.rs | 72 | 72 | 0 |
| lib.rs | 63 | 63 | 0 |
| **Total** | **2,719** | **2,183** | **536** |

## Verdict
The `hardener-core` crate is well-structured with clean separation of concerns. The strategy pattern for executors and the petgraph-based dependency resolution are solid architectural choices. Five flags identified: one medium-severity bug (config fallback), two low-severity design issues (dead code, double indirection), one low-severity duplication, and one low-severity security note. Zero production unwraps. The crate is ready for production use with the F-04 config fallback bug as the only item warranting a near-term fix.
