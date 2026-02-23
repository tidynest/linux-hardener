# hardener-ui::components::findings_tab
**File:** `crates/hardener-ui/src/components/findings_tab.rs` | **Lines:** 55

## Purpose
Wrapper combining `FindingsGrid` and `FindingDetail` into a single tab panel
with a finding count header.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `FindingsTab` | component | Grid + detail layout with finding count header |

## Internal Details
| Item | Description |
|------|-------------|
| Layout | Side-by-side: `FindingsGrid` (left) + `FindingDetail` (right) |
| Count header | Reactive derived signal from `AppState.scan_results` total finding count |

## Flags
None.
