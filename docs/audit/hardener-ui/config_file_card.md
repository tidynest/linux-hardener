# hardener-ui::components::config_file_card
**File:** `crates/hardener-ui/src/components/config_file_card.rs` | **Lines:** 163

## Purpose
Config file picker and validation summary card. Allows selecting a configuration file,
validates it via Tauri IPC, and displays a summary of enabled plugins, directive count,
and any validation errors.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ConfigFileCard` | component | Config file selection with validation summary display |

## Internal Details
| Item | Description |
|------|-------------|
| File picker | Text input for config path with browse button |
| Validation | Calls `invoke_validate_config()` on selection, displays `ConfigSummary` |
| Summary display | Shows enabled plugins, directive count, exception count |
| Error display | Shows validation errors if config is invalid |
| State | Updates `AppState.config_path` and `AppState.config_summary` |

## Flags
None.
