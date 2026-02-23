# hardener-compliance::output::csv
**File:** `crates/hardener-compliance/src/output/csv.rs` | **Lines:** 172

## Purpose
Generates CSV compliance reports for spreadsheet analysis.

## Dependencies
- Imports from: `crate::output::ReportFormatter`, `crate::report::ComplianceReport`, `hardener_common::types::ControlStatus`
- Used by: CLI report command via `ReportFormatter` trait dispatch

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `CsvFormatter` | struct | Unit struct, implements `ReportFormatter` |
| `CsvFormatter::new()` | fn | Constructor |
| `Default` | impl | Delegates to `new()` |

## Data Flow
`ComplianceReport` → CSV header row → per-control data rows (framework, ID, title, section, status, finding count) → `String`

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `escape_csv_field` | 110-116 | Wraps fields with commas/quotes/newlines in double-quotes |
| `format_all` | 67-106 | Override: single header + rows from all reports |

## Flags
- **DUPLICATION:** `format()` and `format_all()` share ~30 identical lines of CSV row generation.
