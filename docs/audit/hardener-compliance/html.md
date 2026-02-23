# hardener-compliance::output::html
**File:** `crates/hardener-compliance/src/output/html.rs` | **Lines:** 283

## Purpose
Generates styled HTML compliance reports with embedded CSS for web viewing.

## Dependencies
- Imports from: `crate::output::ReportFormatter`, `crate::report::ComplianceReport`, `hardener_common::types::ControlStatus`
- Used by: CLI report command via `ReportFormatter` trait dispatch

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `HtmlFormatter` | struct | Unit struct, implements `ReportFormatter` |
| `HtmlFormatter::new()` | fn | Constructor |
| `Default` | impl | Delegates to `new()` |

## Data Flow
`ComplianceReport` → header template → title/subtitle/timestamp → summary box → group by section (BTreeMap) → control rows with status class → footer → `String`

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `html_escape` | 133-138 | Escapes `& < > "` for safe HTML insertion |
| `HTML_HEADER` | 140-229 | Full `<head>` with embedded CSS |
| `HTML_FOOTER` | 231-238 | Footer and closing tags |

## Fixes Applied
- Section name `<h2>` now passes through `html_escape()` (XSS defence in depth)
- `control_id` in table cell now passes through `html_escape()` (XSS defence in depth)

## Flags
- **INCONSISTENCY:** Sections sorted alphabetically (BTreeMap) vs pdf.rs numeric sort.
- **STYLE:** `std::collections::BTreeMap` used inline instead of top-level import.
