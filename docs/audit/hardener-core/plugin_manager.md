# hardener-core::plugin_manager
**File:** `crates/hardener-core/src/plugin_manager.rs` | **Lines:** 334 (334 prod, 0 test)

## Purpose
Orchestrates plugin execution: builds a dependency DAG via petgraph, topological-sorts for execution order, and drives scan/apply across all registered plugins.

## Dependencies
- Imports from: `crate::{ApplyResult, Context, HardenerConfig, PluginRegistry, ScanResult}`, `anyhow`, `hardener_common::types::PluginId`, `petgraph::{DiGraph, Topo}`, `tracing`
- Used by: `hardener-cli` (main scan/apply entry point), `lib.rs` (re-exported as `PluginManager`)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `PluginManager` | struct | Registry + DiGraph + node-index map |
| `PluginManager::new(PluginRegistry)` | fn | Constructor, empty graph |
| `PluginManager::resolve_dependencies()` | fn | Two-pass: add nodes, add edges, cycle check |
| `PluginManager::execution_order()` | fn | Topological sort into `Vec<PluginId>` |
| `PluginManager::execute_scan(&self, &Context)` | async fn | Runs `plugin.scan()` in topo order, aggregates `Vec<ScanResult>` |
| `PluginManager::execute_apply(&self, &mut Context, &HardenerConfig, &[PluginId])` | async fn | Runs `plugin.apply()` in topo order with per-plugin config lookup |

## Data Flow
1. `new()` -- stores registry, empty graph
2. `resolve_dependencies()` -- pass 1: `registry.list()` -> add graph nodes; pass 2: `registry.get()` -> `plugin.dependencies()` -> add edges; `is_cyclic_directed()` check
3. `execution_order()` -- `Topo::new()` iterator over graph nodes
4. `execute_scan()` -- for each plugin in order: `plugin.scan(ctx)`, push result or error stub
5. `execute_apply()` -- filter by `plugin_ids` (empty = all), for each: `config.get_plugin_config()` -> `plugin.apply(ctx, config)`

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| (none -- all methods are public) | | |

## Flags
- None
