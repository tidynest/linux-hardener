# hardener-types::config_picker
**File:** `crates/hardener-types/src/config_picker.rs` | **Lines:** 20 (all production)

## Purpose
Config file picker UI type — provides a validated summary of a configuration file for display in the Leptos frontend.

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ConfigSummary` | struct | Validated config file summary: path, is_valid, error, enabled_plugins, directive_count, exception_count |

## Fields
| Field | Type | Description |
|-------|------|-------------|
| `config_path` | `String` | File path |
| `config_is_valid` | `bool` | Parse result |
| `config_error` | `Option<String>` | Error if invalid |
| `config_enabled_plugins` | `Vec<String>` | Enabled plugins |
| `config_directive_count` | `u32` | Total directives |
| `config_exception_count` | `u32` | Total exceptions |

## Flags
None — minimal, focused struct.
