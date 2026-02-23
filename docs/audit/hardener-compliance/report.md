# hardener-compliance::report
**File:** `crates/hardener-compliance/src/report.rs` | **Lines:** 167

## Purpose
Re-exports compliance report types from `hardener-types` crate.

## Dependencies
- Re-exports: `hardener_types::{ComplianceReport, ComplianceSummary, ControlResult}`
- Used by: All output formatters, `generator.rs`, CLI report commands

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ComplianceReport` | re-export | Framework + timestamp + controls + summary |
| `ComplianceSummary` | re-export | Aggregate stats (pass/fail/NA/manual/score) |
| `ControlResult` | re-export | Single control: ID, title, section, status, findings |

## Data Flow
Types defined in `hardener-types` → re-exported here → used throughout compliance crate.

## Flags
None. Pure re-export with thorough test coverage (10 tests).
