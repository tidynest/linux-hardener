# hardener-cli::commands::scan
**File:** `crates/hardener-cli/src/commands/scan.rs` | **Lines:** 229

## Purpose
Executes security scans — plugin filtering, severity filtering, history persistence.

## Dependencies
- Imports from: `hardener_core::{ConfigLoader, Context, PluginMetadata}`, `hardener_plugins`, `hardener_scheduler::ScanHistoryManager`
- Used by: `main.rs` via `Scan` subcommand dispatch

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ScanOptions` | struct | All scan parameters bundled |
| `run(opts)` | async fn | Run scan with filtering and persistence |

## Data Flow
CLI args → `ScanOptions` → load config → registry scan → severity filter → output → persist to DB

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `load_config` | 100-113 | Load or default config (audit mode = default) |
| `severity_filter_to_severity` | 115-123 | CLI enum → core Severity |
| `validate_plugin_filter` | 127-152 | Check plugin names against registry |
| `is_valid_plugin_name` | 155-159 | Fuzzy match: full ID or short prefix |
| `persist_scan_session` | 165-196 | Best-effort DB write |
| `open_history_db` | 199-204 | Open scheduler DB via config |
| `finding_to_scan_finding` | 207-229 | Core Finding → scheduler ScanFinding |

## Flags
- **UNUSED:** `_config` loaded at line 37 but result discarded — scan doesn't pass per-plugin config yet.
- **MISSING:** No `//!` module doc.
