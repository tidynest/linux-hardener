# hardener-cli::cli
**File:** `crates/hardener-cli/src/cli.rs` | **Lines:** 544

## Purpose
Clap derive-based CLI argument definitions — all subcommands, flags, and value enums.

## Dependencies
- Imports from: `hardener_compliance::OutputFormat` — re-exported as `pub(crate)`
- Used by: `main.rs` — parses args, `commands/*` — destructures subcommand variants

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `Cli` | struct | Root parser with global flags: format, quiet, config, ssh opts |
| `Command` | enum | Scan, Apply, Rollback, Checkpoint, Plugins, Report, Daemon, Systemd, History |
| `CheckpointAction` | enum | List, Create, Delete, Show |
| `DaemonAction` | enum | Start, RunOnce, Status |
| `SystemdAction` | enum | Generate, Install, Uninstall, Status |
| `HistoryAction` | enum | List, Show, Export |
| `ReportFormat` | enum | Text, Json, Csv, Html — **unused in production** |
| `SeverityFilter` | enum | Info, Low, Medium, High, Critical |
| `ScanMode` | enum | Default, Audit, Compliance |

## Data Flow
`main.rs` → `Cli::parse()` → match `cli.command` → dispatch to `commands::*`

## Flags
- **DEAD CODE:** `ReportFormat` enum (lines 258-264) unused in production — `Report.report_format` is `String`, not `ReportFormat`.
- **TYPO:** Line 243 — extra `)` in doc comment.
