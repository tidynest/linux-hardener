# hardener-compliance::config
**File:** `crates/hardener-compliance/src/config.rs` | **Lines:** 221

## Purpose
Defines report configuration types: scenarios, output formats, and report settings.

## Dependencies
- Imports from: `hardener_common::types::ComplianceFramework`, `clap::ValueEnum`
- Used by: CLI `report` and `report-wizard` commands, `generator.rs`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `Scenario` | enum | 8 variants: Server, Workstation, Government, Healthcare, Financial, Gdpr, All, Custom |
| `Scenario::frameworks()` | fn | Returns `Vec<ComplianceFramework>` for the scenario |
| `Scenario::name()` | fn | Human-readable name |
| `OutputFormat` | enum | 5 variants: Text, Json, Csv, Html, Pdf (derives `ValueEnum` for clap) |
| `OutputFormat::extension()` | fn | File extension string |
| `ReportConfig` | struct | scenario + formats + output_dir |

## Data Flow
User selects scenario → `frameworks()` resolves to framework list → passed to `generator.rs` → each framework produces a report.

## Flags
None. Clean types with comprehensive test coverage (11 tests).
