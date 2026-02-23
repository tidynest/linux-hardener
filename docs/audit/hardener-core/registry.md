# hardener-core::registry
**File:** `crates/hardener-core/src/registry.rs` | **Lines:** 199 (114 prod, 85 test)

## Purpose
Thread-safe plugin storage: wraps `RwLock<HashMap<PluginId, Arc<Box<dyn HardeningPlugin>>>>` with register/get/list/count/contains operations.

## Dependencies
- Imports from: `hardener_common::{error, types::PluginId}`, `crate::plugin::{HardeningPlugin, PluginMetadata}`
- Used by: `plugin_manager.rs` (owned field), `hardener-cli` (plugin registration at startup), `lib.rs` (re-exported)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `PluginRegistry` | struct | `Arc<RwLock<HashMap<PluginId, Arc<Box<dyn HardeningPlugin>>>>>` |
| `PluginRegistry::new()` | fn | Empty registry |
| `PluginRegistry::register(Box<dyn HardeningPlugin>)` | fn | Insert plugin, reject duplicates |
| `PluginRegistry::get(&PluginId)` | fn | Clone `Arc<Box<..>>` from map, `Option` |
| `PluginRegistry::list()` | fn | All metadata, sorted by plugin_id |
| `PluginRegistry::count()` | fn | Number of registered plugins |
| `PluginRegistry::contains(&PluginId)` | fn | Key existence check |

## Data Flow
1. CLI startup: `register()` inserts each plugin Box, keyed by `plugin.metadata().plugin_id`
2. `PluginManager::resolve_dependencies()` calls `list()` for node creation, `get()` for edge creation
3. `PluginManager::execute_scan/apply()` calls `get()` per plugin in topo order

## Flags
- **DUPLICATION** (lines 61-66, 75-80, 93-98, 105-110): Four read-lock acquisitions with identical error-mapping closures. Could extract a `fn read_lock(&self) -> Result<RwLockReadGuard<..>>` helper. Status: **Flagged**.
- **DESIGN** (line 14): `Arc<Box<dyn HardeningPlugin>>` is double indirection. `Arc<dyn HardeningPlugin>` would suffice since `Arc` already heap-allocates. The outer `Arc` on the `PluginMap` type alias adds a third layer. Functional but sub-optimal. Status: **Flagged**.
