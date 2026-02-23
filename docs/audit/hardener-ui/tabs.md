# hardener-ui::components::tabs
**File:** `crates/hardener-ui/src/components/tabs.rs` | **Lines:** 102

## Purpose
Reusable WAI-ARIA compliant tab components. Provides correct roles, aria attributes,
and keyboard navigation for accessible tabbed interfaces.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `TabDef` | struct | Tab definition: id, label, optional badge content |
| `TabBar` | component | Horizontal tab strip with `role="tablist"` and `aria-selected` management |
| `TabPanel` | component | Content panel with `role="tabpanel"` and `aria-controls` linkage |

## Internal Details
| Item | Description |
|------|-------------|
| `aria-selected` | Reactive — tracks active tab signal |
| `tabindex` | Active tab gets `0`, inactive tabs get `-1` |
| `aria-controls` | Links each tab button to its corresponding panel ID |

## Flags
None.
