# hardener-plugins::macros
**File:** `crates/hardener-plugins/src/macros.rs` | **Lines:** 81

## Purpose
`define_plugin!` macro generating plugin boilerplate: unit struct, `metadata_impl()`, and `HardeningPlugin` trait implementation with `todo!()` stubs. Scaffolding tool for rapid prototyping — none of the 8 production plugins use it.

## Dependencies
- Imports from: `hardener_core::plugin`, `hardener_common::types`, `async_trait` (all via `$crate::`)
- Used by: `lib.rs` test only

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `define_plugin!` | macro | Generates struct + `HardeningPlugin` impl from declarative spec |

## Flags
- **BUG** (line 46): Fixed — `PluginId::from($dep)` was unqualified; would fail to compile for any non-empty `dependencies` list. Changed to `$crate::hardener_common::types::PluginId::from($dep)`.
- **ANTIPATTERN** (lines 53, 61, 69, 77): `todo!()` stubs in scan/apply/rollback/validate. Intentional scaffolding — panics at runtime if macro-generated plugin is used without overriding methods.
