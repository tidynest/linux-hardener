# hardener-compliance::output::mod
**File:** `crates/hardener-compliance/src/output/mod.rs` | **Lines:** 34

## Purpose
Output module root — declares formatter submodules and defines the `ReportFormatter` trait.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ReportFormatter` | trait | `format(&ComplianceReport) -> String` + default `format_all` |
| `CsvFormatter` | re-export | CSV output |
| `HtmlFormatter` | re-export | HTML output |
| `JsonFormatter` | re-export | JSON output |
| `PdfFormatter` | re-export | PDF output (behind `pdf` feature flag) |
| `TextFormatter` | re-export | Plaintext output |

## Design Note
`PdfFormatter` is gated behind `#[cfg(feature = "pdf")]` — allows building without krilla dependency.

## Flags
None.
