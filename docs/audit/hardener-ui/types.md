# hardener-ui::types
**File:** `crates/hardener-ui/src/types.rs` | **Lines:** 20

## Purpose
Type re-exports from `hardener-types` and UI-specific type definitions.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `CheckpointInfo` | struct | UI-specific checkpoint representation (4 string fields: id, name, timestamp, description) |
| (re-exports) | `pub use` | Core types from `hardener-types` used across UI components |

## Internal Details
| Item | Description |
|------|-------------|
| Module doc | Present — `//!` doc comment |
| `CheckpointInfo` | UI-only struct, not shared with backend — string-based for display convenience |

## Flags
None.
