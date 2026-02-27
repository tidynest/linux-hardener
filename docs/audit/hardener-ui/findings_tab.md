# hardener-ui::components::findings_tab
**File:** `crates/hardener-ui/src/components/findings_tab.rs` | **Lines:** 160

## Purpose
Wrapper combining `FindingsGrid` and `FindingDetail` into a single tab panel
with finding count header and severity filter controls.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `FindingsTab` | component | Grid + detail layout with finding count header and severity filter |

## Internal Details
| Item | Description |
|------|-------------|
| Layout | Side-by-side: `FindingsGrid` (left) + `FindingDetail` (right) |
| Count header | Reactive derived signal from `AppState.scan_results` total finding count |
| Severity filter | Dropdown filtering findings by severity level via `AppState.severity_filter` |
| Filtered count | Shows "X of Y findings" when filter is active |

## Flags
None.
