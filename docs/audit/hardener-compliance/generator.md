# hardener-compliance::generator
**File:** `crates/hardener-compliance/src/generator.rs` | **Lines:** 163

## Purpose
Orchestrates compliance report generation by mapping scan findings to framework controls.

## Dependencies
- Imports from: `crate::config::ReportConfig`, `crate::frameworks`, `crate::report::*`, `hardener_core::plugin::Finding`
- Used by: CLI `report` and `report-wizard` commands

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ReportGenerator` | struct | Holds `ReportConfig` |
| `ReportGenerator::new(config)` | fn | Constructor |
| `ReportGenerator::generate(findings)` | fn | Returns `Vec<ComplianceReport>`, one per framework |

## Data Flow
`ReportConfig` → resolve scenario to frameworks → for each framework: fetch control definitions → match findings by `(framework, control_id)` → determine pass/fail → build `ControlResult` → compute `ComplianceSummary` → `ComplianceReport`

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `generate_for_framework` | 37-91 | Core logic: control → finding match → status |

## Flags
None. Clean orchestrator with graceful `unwrap_or_else` for missing sections.
