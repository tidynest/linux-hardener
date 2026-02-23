# hardener-ui::components::history_section
**File:** `crates/hardener-ui/src/components/history_section.rs` | **Lines:** 193

## Purpose
Checkpoint management and rollback UI. Lists existing checkpoints, displays details,
and triggers rollback operations via Tauri IPC.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `HistorySection` | component | Checkpoint list with rollback controls |

## Internal Details
| Item | Description |
|------|-------------|
| Checkpoint list | Fetches via `invoke_get_checkpoints()`, renders chronologically |
| Rollback trigger | Calls `invoke_rollback()` with selected checkpoint ID |
| Result display | Shows restore results after rollback completes |

## Fixes Applied
| # | Description |
|---|-------------|
| 1 | `results.last().unwrap()` → `.expect("guarded by Show when=")` — documents the invariant |

## Flags
None.
