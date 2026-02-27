# hardener-ui::components::history_section
**File:** `crates/hardener-ui/src/components/history_section.rs` | **Lines:** 398

## Purpose
Checkpoint management and rollback UI. Lists existing checkpoints with detail view,
supports manual checkpoint creation, deletion, and rollback operations via Tauri IPC.
Shows per-file restore results after rollback.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `HistorySection` | component | Checkpoint CRUD with rollback controls and detail view |

## Internal Details
| Item | Description |
|------|-------------|
| Checkpoint list | Fetches via `invoke_get_checkpoints()`, renders chronologically with name/date/id |
| Create checkpoint | Manual checkpoint creation with user-supplied name |
| Delete checkpoint | Confirmation dialog before deletion |
| Detail view | Shows captured files for selected checkpoint via `invoke_get_checkpoint_detail()` |
| Rollback trigger | Calls `invoke_rollback()` with selected checkpoint ID |
| Result display | Shows per-file restore results with success/fail indicators after rollback |

## Fixes Applied
| # | Description |
|---|-------------|
| 1 | `results.last().unwrap()` -> `.expect("guarded by Show when=")` — documents the invariant |

## Flags
None.
