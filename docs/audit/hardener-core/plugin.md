# hardener-core::plugin
**File:** `crates/hardener-core/src/plugin.rs` | **Lines:** 93 (81 prod, 12 test)

## Purpose
Defines the core `HardeningPlugin` trait (scan, apply, rollback, validate) and re-exports types from `hardener-types` and `hardener-common` for ergonomic downstream use.

## Dependencies
- Imports from: `crate::config::PluginConfig`, `async_trait`, `hardener_common::error::Result`
- Re-exports from: `hardener_types` (ApplyResult, Change, ChangeType, Finding, PluginMetadata, ScanResult, ValidationIssue, ValidationReport), `hardener_common::types` (ComplianceMapping, FindingCategory, FindingPolicyException, PluginId, Severity), `hardener_state` (Checkpoint, CheckpointId, CheckpointManager)
- Used by: `registry.rs` (trait object storage), `plugin_manager.rs` (trait method calls), all 8 plugins (implement trait), `lib.rs` (re-exported)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `HardeningPlugin` | trait | `Send + Sync`, gated behind `cfg(feature = "system")` |
| `metadata()` | trait fn | Returns `PluginMetadata` |
| `dependencies()` | trait fn | Returns `Vec<PluginId>` of prerequisite plugins |
| `scan(&self, &Context)` | async trait fn | Read-only system assessment, returns `ScanResult` |
| `apply(&self, &mut Context, &PluginConfig)` | async trait fn | Apply hardening, returns `ApplyResult` |
| `rollback(&self, &mut Context, &Checkpoint)` | async trait fn | Restore to checkpoint state |
| `validate(&self, &Context, &PluginConfig)` | async trait fn | Dry-run validation, returns `ValidationReport` |
| (re-exports) | types | 14 types re-exported from hardener-types, hardener-common, hardener-state |

## Data Flow
1. Plugin registration: `Box<dyn HardeningPlugin>` stored in `PluginRegistry`
2. Plugin execution: `PluginManager` calls trait methods in topological order
3. Context flows down: `&Context` for reads, `&mut Context` for state-changing operations

## Flags
- None
