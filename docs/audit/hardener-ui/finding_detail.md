# hardener-ui::components::finding_detail
**File:** `crates/hardener-ui/src/components/finding_detail.rs` | **Lines:** 85

## Purpose
Detailed finding panel showing severity, description, explanation, impact, current vs
expected values, and remediation steps. Renders as a semantic `<aside>` element.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `FindingDetail` | component | Detailed view of a selected finding with severity badge and remediation |

## Internal Details
| Item | Description |
|------|-------------|
| Guard | Wrapped in `<Show when=selected_finding.is_some()>` — no render when nothing selected |
| Severity badge | Uses `SeverityBadge` component |
| Values comparison | Side-by-side display of current value vs expected value |
| Remediation | Ordered list of remediation steps from the finding data |

## Flags
None.
