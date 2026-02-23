# hardener-ui::components::card
**File:** `crates/hardener-ui/src/components/card.rs` | **Lines:** 79

## Purpose
Reusable card container component with variant and heading level options.
Provides consistent visual structure across dashboard and detail views.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `Card` | component | Container with optional title, class, variant, and heading level |
| `CardVariant` | enum | `Default`, `Compact`, `Empty` — controls padding and border style |
| `HeadingLevel` | enum | `H2`, `H3`, `H4` — semantic heading for card title |

## Internal Details
| Item | Description |
|------|-------------|
| Variant CSS | Each `CardVariant` maps to a CSS class modifier |
| Heading render | Dynamically renders `<h2>`, `<h3>`, or `<h4>` based on `HeadingLevel` |
| `#[allow(dead_code)]` | On enum variants — intentional for API completeness |

## Flags
- **NOTE:** `#[allow(dead_code)]` on `CardVariant` and `HeadingLevel` is documented and intentional — variants exported for downstream use.
