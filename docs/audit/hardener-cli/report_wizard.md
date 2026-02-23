# hardener-cli::commands::report_wizard
**File:** `crates/hardener-cli/src/commands/report_wizard.rs` | **Lines:** 589

## Purpose
Interactive compliance report wizard — guides user through scenario, format, and output selection.

## Dependencies
- Imports from: `commands::report::run_scan` — reuses scan logic, `hardener_compliance` — report generation
- Used by: `main.rs` via CLI subcommand dispatch

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `run(quiet)` | async fn | Entry point; errors if `quiet=true` |

## Data Flow
User input → `WizardState{scenario, formats, path}` → `run_scan()` → `ReportGenerator::generate()` → format + output

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `print_welcome` | 179-205 | Box-drawn banner |
| `wizard_flow` | 207-217 | Orchestrates 3 selection steps |
| `select_scenario` | 219-262 | Preset or custom framework picker |
| `select_frameworks` | 264-286 | MultiSelect for custom mode |
| `select_output_formats` | 288-332 | MultiSelect for Text/JSON/CSV/HTML/PDF |
| `select_output_path` | 334-359 | Optional file save path |
| `confirm_selections` | 361-416 | Review + confirm dialog |
| `output_reports` | 418-509 | Write/print reports by format |
| `format_name` | 511-519 | OutputFormat → display string |
| `print_summary` | 521-565 | Coloured score per framework |
| `framework_icon` | 567-577 | Framework → emoji |
| `framework_display_name` | 579-589 | Framework → human label |

## Flags
- **DESIGN:** `formatted.chars().map(|c| c as u8)` (lines 473, 490) — PDF binary through String truncates bytes >255. Needs `ReportFormatter` trait to return `Vec<u8>` for binary formats.
- **DUPLICATION:** Framework/format display-name match blocks repeated across 3 locations — could use `Display` trait.
