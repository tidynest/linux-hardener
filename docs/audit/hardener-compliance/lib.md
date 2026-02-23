# hardener-compliance::lib
**File:** `crates/hardener-compliance/src/lib.rs` | **Lines:** 37

## Purpose
Crate root — re-exports all public types and declares submodules.

## Public Re-exports
| Item | Source Module |
|------|--------------|
| `OutputFormat`, `ReportConfig`, `Scenario` | `config` |
| `ReportGenerator` | `generator` |
| `CsvFormatter`, `HtmlFormatter`, `JsonFormatter`, `PdfFormatter`, `TextFormatter`, `ReportFormatter` | `output` |
| `ComplianceReport`, `ComplianceSummary`, `ControlResult` | `report` |

## Architecture Diagram
Includes ASCII diagram in module doc showing CLI/GUI → compliance crate flow.

## Flags
None.
