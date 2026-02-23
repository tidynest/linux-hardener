# hardener-compliance::output::json
**File:** `crates/hardener-compliance/src/output/json.rs` | **Lines:** 153

## Purpose
Generates machine-readable JSON compliance reports for API/automation integration.

## Dependencies
- Imports from: `crate::output::ReportFormatter`, `crate::report::ComplianceReport`, `serde::Serialize`
- Used by: CLI report command via `ReportFormatter` trait dispatch

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `JsonFormatter` | struct | Holds `pretty: bool` flag |
| `JsonFormatter::new()` | fn | Compact output (default) |
| `JsonFormatter::pretty()` | fn | Pretty-printed output |
| `Default` | impl | Delegates to `new()` |

## Internal Types
| Type | Description |
|------|-------------|
| `JsonReport<'a>` | Enriched view: adds `framework_name` and `framework_description` fields |

## Data Flow
`ComplianceReport` → `JsonReport::from_report()` (borrow, enrich with metadata) → `serde_json::to_string[_pretty]` → graceful `unwrap_or_else` fallback → `String`

## Flags
None. Clean serde usage with graceful error handling.
