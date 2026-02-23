# hardener-ui::components::findings_grid
**File:** `crates/hardener-ui/src/components/findings_grid.rs` | **Lines:** 76

## Purpose
Findings table with severity badges and row selection. Clicking a row updates
`selected_finding` in `AppState` to drive the detail panel.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `FindingsGrid` | component | Tabular findings list with severity badges and click-to-select |

## Internal Details
| Item | Description |
|------|-------------|
| Table rows | Iterates `AppState.scan_results` findings, renders severity badge + description |
| Row click | Sets `AppState.selected_finding` signal to the clicked finding |
| Empty state | Renders placeholder message when no findings exist |

## Flags
None.
