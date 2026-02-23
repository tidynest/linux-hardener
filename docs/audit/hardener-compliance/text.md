# hardener-compliance::output::text
**File:** `crates/hardener-compliance/src/output/text.rs` | **Lines:** 171

## Purpose
Generates human-readable plaintext compliance reports for terminal output.

## Dependencies
- Imports from: `crate::output::ReportFormatter`, `crate::report::ComplianceReport`, `hardener_common::types::ControlStatus`
- Used by: CLI report command (default format) via `ReportFormatter` trait dispatch

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `TextFormatter` | struct | Unit struct, implements `ReportFormatter` |
| `TextFormatter::new()` | fn | Constructor |
| `Default` | impl | Delegates to `new()` |

## Data Flow
`ComplianceReport` → header with `=` separator → group by section (BTreeMap) → per-control line with `[STATUS]` badge → summary footer → `String`

## Flags
- **STYLE:** Status badge widths inconsistent (`[PASS]`=6, `[N/A] `=6, `[FAIL]`=6, `[MANUAL]`=8).
