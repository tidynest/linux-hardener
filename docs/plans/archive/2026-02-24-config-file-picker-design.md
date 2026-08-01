# Config File Picker: Design

> **Archived.** Historical record, possibly superseded by later work. Retained for history.

**Date**: 2026-02-24
**Status**: Implemented
**Feature**: GUI equivalent of CLI `--config FILE` flag (P3, v0.4.0)

## Overview

Add a config file picker to the Hardening page that lets users select a custom TOML config file. The selected path is passed to all backend operations (scan, apply, rollback, dry-run), mirroring the CLI `--config` behaviour.

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Placement | Hardening page, above Security Profile card | Config controls plugin behaviour: co-located with plugin toggles |
| Behaviour | Store path only (like CLI `--config`) | GUI toggles remain independent; config path fed to `ConfigLoader` |
| Input method | Text input + native file dialog (Browse button) | Power users paste paths; browse helps discovery |
| Feedback | Path + valid/invalid + one-line summary | Compact but confirms the right file was loaded |
| File dialog | `tauri-plugin-dialog` | One dependency, native OS picker, `.toml` filter |

## Data Flow

```
User picks file (browse or type)
    -> invoke_validate_config(path)         [new Tauri command]
    -> Backend: ConfigLoader parses TOML    [returns ConfigSummary]
    -> Frontend: store path + summary in AppState
    -> Subsequent scan/apply/rollback pass configPath to Tauri commands
    -> Backend: inject --config <path> into CLI args (apply/rollback)
               or load via ConfigLoader (scan/dry-run)
```

Two injection points:
- `run_scan` / `run_apply_dry_run`: load config via `ConfigLoader::new().with_cli_config(path).load()`
- `run_apply` / `run_rollback`: append `--config <path>` to CLI args

## New Type

```rust
// hardener-types/src/config_picker.rs
pub struct ConfigSummary {
    pub config_path: String,
    pub config_is_valid: bool,
    pub config_error: Option<String>,
    pub config_enabled_plugins: Vec<String>,
    pub config_directive_count: u32,
    pub config_exception_count: u32,
}
```

## AppState Additions

```rust
pub config_path: RwSignal<Option<String>>,
pub config_summary: RwSignal<Option<ConfigSummary>>,
```

## Tauri Commands (2 new)

1. **`validate_config(path: String) -> ConfigSummary`**, parse TOML, return summary. Read-only, no privileges.
2. **`pick_config_file() -> Option<String>`**: native file dialog via `tauri-plugin-dialog`, filtered to `.toml`.

## UI Component

`ConfigFileCard` in `ConfigureSection`, between guidance text and Security Profile card.

```
+-- Configuration File ------------------------------------+
|                                                          |
|  [~/.config/linux-hardener/config.toml ] [Browse]        |
|                                                          |
|  check Valid . 5 plugins . 3 directives . 1 exception    |
|                                             [Clear]      |
+----------------------------------------------------------+
```

- Text input with placeholder "Using default configuration"
- Browse button opens OS file dialog
- Status line: green check + summary (valid) or red X + error (invalid)
- Clear button resets to default (config_path = None)
- Validates on blur / Enter

## WASM Binding

```rust
pub async fn invoke_validate_config(path: String) -> Result<ConfigSummary, String>
pub async fn invoke_pick_config_file() -> Result<Option<String>, String>
```

## What We Don't Build

- No config file editor (users edit TOML externally)
- No config creation wizard
- No config saving from the GUI
- No merged-config preview

## Error Handling

- File not found: red status with message
- Parse error: red status with TOML error detail
- Browser mode: Browse button hidden, validate returns graceful error
- Empty/cleared: resets to None, shows "Using default configuration"
