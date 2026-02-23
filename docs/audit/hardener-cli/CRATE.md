# hardener-cli — Crate Audit

**Crate:** `hardener-cli` | **Files:** 14 | **Lines:** 3,191

## Purpose
User-facing CLI binary — parses arguments, dispatches to subcommand handlers, formats output as coloured text or JSON.

## Architecture

```
main.rs
├── cli.rs              (clap arg defs, enums)
├── output.rs           (format multiplexer: JSON / coloured text)
├── ssh_config.rs       (SSH connection parsing)
└── commands/
    ├── mod.rs           (re-exports)
    ├── scan.rs          (security scan + history persistence)
    ├── apply.rs         (hardening apply + checkpoint support)
    ├── checkpoint.rs    (CRUD + rollback)
    ├── report.rs        (non-interactive compliance report)
    ├── report_wizard.rs (interactive wizard)
    ├── daemon.rs        (scheduled scanning daemon)
    ├── history.rs       (scan history viewing/export)
    ├── systemd.rs       (unit file management)
    └── plugins.rs       (plugin listing)
```

## Inter-Module Data Flow

```
CLI args → Cli::parse() → match Command
  ├── Scan    → scan::run()  → registry.scan() → output::scan_results() → persist_scan_session()
  ├── Apply   → apply::run() → registry.apply() → output::apply_results()
  ├── Report  → report::run() → run_scan() → ReportGenerator → format → file/stdout
  ├── Daemon  → daemon::start/run_once() → Daemon::start()/run_once()
  ├── History → history::list/show/export() → ScanHistoryManager → output
  └── ...
```

## Audit Summary

| Metric | Count |
|--------|-------|
| Fixes applied | 19 |
| Design flags deferred | 6 |
| Production unwraps removed | 5 (output.rs) + 1 (compliance pdf.rs) |
| Module docs added | 8 |
| Tests passing | 400 |

## Fixes Applied

| # | File | Fix |
|---|------|-----|
| 1-5 | output.rs | 5x `.unwrap()` → `match` with error fallback |
| 6 | output.rs | Added `//!` module doc |
| 7 | history.rs | `truncate_string` byte-slicing → char-aware (UTF-8 safe) |
| 8 | checkpoint.rs | Typo: "completion" → "completed" |
| 9 | checkpoint.rs | Added `//!` module doc |
| 10 | cli.rs | Extra `)` removed from doc comment |
| 11 | cli.rs | Added `//!` module doc |
| 12 | report.rs | `use hardener_plugins::*` → explicit import |
| 13 | report_wizard.rs | Removed unused `let _failing` binding |
| 14 | scan.rs | Added `//!` module doc |
| 15 | apply.rs | Added `//!` module doc |
| 16 | main.rs | Added `//!` module doc |
| 17 | plugins.rs | Added `//!` module doc |
| 18 | mod.rs | Added `//!` module doc |
| 19 | compliance/pdf.rs | `.unwrap()` → `.expect("0.8 is always in [0.0, 1.0]")` |

## Design Flags (Deferred)

| # | File | Issue |
|---|------|-------|
| D1 | report_wizard.rs, report.rs | PDF `chars().map(\|c\| c as u8)` truncates binary — needs `ReportFormatter` trait to return `Vec<u8>` |
| D2 | checkpoint.rs, apply.rs | `get_checkpoint_manager()` duplicated verbatim |
| D3 | cli.rs | `ReportFormat` enum unused in production |
| D4 | report_wizard.rs | Framework/format display-name matches repeated 3x |
| D5 | scan.rs | `_config` loaded but result unused |
| D6 | apply.rs | Config parse errors silently swallowed |
