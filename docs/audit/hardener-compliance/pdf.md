# hardener-compliance::output::pdf
**File:** `crates/hardener-compliance/src/output/pdf.rs` | **Lines:** 707

## Purpose
Generates PDF compliance reports using the krilla library with embedded NotoSans fonts.

## Dependencies
- Imports from: `crate::output::ReportFormatter`, `crate::report::ComplianceReport`, `hardener_common::types::ControlStatus`
- Ext deps: `krilla` (PDF gen), `std::collections::BTreeMap`
- Used by: CLI report command via `ReportFormatter` trait dispatch

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `PdfFormatter` | struct | Unit struct, implements `ReportFormatter` |
| `PdfFormatter::new()` | fn | Constructor |
| `Default` | impl | Delegates to `new()` |

## Data Flow
`ComplianceReport` → `generate_pdf()` → group controls by section → sort by control ID → render title/summary/sections/footer → `Vec<u8>` → Latin-1 char map → `String`

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `generate_pdf` | 139-344 | Main orchestrator: fonts, pages, Y-tracking |
| `draw_summary_box` | 347-504 | Score percentage + pass/fail/NA/manual stats |
| `draw_control` | 507-601 | Single control: ID, status badge, title, findings |
| `draw_horizontal_line` | 604-622 | Thin rectangle as separator |
| `truncate_string` | 625-631 | Char-safe truncation with ellipsis |
| `compare_control_ids` | 634-646 | Numeric dotted-ID comparison (1.5.2 < 1.5.10) |
| `YTracker` | 106-136 | Cursor tracking + page-break detection |

## Fixes Applied
- `truncate_string`: byte-based → char-based (UTF-8 panic fix, same class as cli/output.rs)
- Sort comparator: removed `String::new()` allocation per comparison → `""`

## Flags
- **DESIGN:** Binary PDF returned as `String` via Latin-1 char map (trait constraint).
- **STYLE:** 9 colour helper functions — could be `const` if krilla supported `const fn` constructors.
