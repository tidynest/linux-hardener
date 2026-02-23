# hardener-ui::state::mod
**File:** `crates/hardener-ui/src/state/mod.rs` | **Lines:** 57

## Purpose
Global application state. All reactive signals for scan results, apply results,
checkpoints, selected finding, error state, and compliance data.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `AppState` | struct | 11 `RwSignal` fields — central reactive store for the entire UI |

## Fields
| Field | Type | Description |
|-------|------|-------------|
| `scan_results` | `RwSignal<Vec<ScanResult>>` | Current scan findings |
| `apply_results` | `RwSignal<Vec<ApplyResult>>` | Last apply operation results |
| `checkpoints` | `RwSignal<Vec<CheckpointInfo>>` | Available rollback checkpoints |
| `selected_finding` | `RwSignal<Option<Finding>>` | Currently selected finding for detail view |
| `has_error` | `RwSignal<bool>` | Global error flag for banner display |
| `error_message` | `RwSignal<String>` | Error message text |
| `compliance_results` | `RwSignal<Vec<FrameworkScore>>` | Compliance score results |

## Internal Details
| Item | Description |
|------|-------------|
| `Default` impl | Empty collections, `false` booleans, empty strings |
| Derives | `Clone + Copy` — all fields are `RwSignal` (cheap copy) |

## Flags
None.
