# hardener-cli::commands::report
**File:** `crates/hardener-cli/src/commands/report.rs` | **Lines:** 205

## Purpose
Non-interactive compliance report generation — scenario/framework selection, scan, format, output.

## Dependencies
- Imports from: `hardener_compliance::*` (report gen), `hardener_plugins::*` (glob), `hardener_core::Context`
- Used by: `main.rs` via `Report` subcommand; `run_scan` reused by `report_wizard.rs`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `run(scenario, framework, report_format, output, cli_format, quiet, executor)` | async fn | Generate compliance report |
| `run_scan(quiet, executor)` | async fn | Scan all plugins, collect findings |

## Data Flow
CLI args → parse scenario/framework → `run_scan()` → `ReportGenerator::generate()` → format → write/stdout

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `parse_scenario` | 175-189 | String → Scenario enum |
| `parse_framework` | 191-205 | String → ComplianceFramework enum |

## Flags
- **DESIGN:** PDF `chars().map(\|c\| c as u8)` truncation (lines 113, 126) — same as report_wizard.rs.
- **GLOB IMPORT:** `use hardener_plugins::*` — only `create_plugin_registry` is used.
- **UNUSED:** `_cli_format` parameter (line 20).
