# hardener-ui::components::severity_badge
**File:** `crates/hardener-ui/src/components/severity_badge.rs` | **Lines:** 39

## Purpose
Colour-coded severity badge. Maps `Severity` enum variants to CSS classes and
display text for consistent severity presentation throughout the UI.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `SeverityBadge` | component | Renders a styled `<span>` with severity-appropriate colour and label |

## Internal Details
| Item | Description |
|------|-------------|
| CSS mapping | Each `Severity` variant → unique CSS class (critical/high/medium/low/info) |
| Text mapping | Each variant → human-readable label |

## Flags
- **STYLE:** Missing `//!` module doc — cosmetic, not fixed.
