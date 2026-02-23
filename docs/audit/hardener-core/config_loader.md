# hardener-core::config_loader
**File:** `crates/hardener-core/src/config_loader.rs` | **Lines:** 292 (189 prod, 103 test)

## Purpose
Multi-source configuration loading with cascading precedence: defaults -> system `/etc/` -> user `~/.config/` -> CLI `--config` -> `HARDENER_*` environment variables.

## Dependencies
- Imports from: `crate::config::{GlobalConfig, HardenerConfig, PluginConfig}`, `hardener_common::error`, `dirs`, `toml`
- Used by: `hardener-cli` (config loading at startup), `lib.rs` (re-exported as `ConfigLoader`)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ConfigLoader` | struct | Holds optional CLI config path + skip_defaults flag |
| `ConfigLoader::new()` | fn | Default loader |
| `ConfigLoader::with_cli_config(PathBuf)` | fn | Builder: set CLI config path |
| `ConfigLoader::skip_defaults()` | fn | Builder: skip system/user paths (testing) |
| `ConfigLoader::load()` | fn | Execute full cascade, return merged `HardenerConfig` |
| `ConfigLoader::system_config_path()` | fn | `/etc/linux-hardener/config.toml` |
| `ConfigLoader::user_config_path()` | fn | `~/.config/linux-hardener/config.toml` via `dirs` |

## Data Flow
1. `load()` starts with `HardenerConfig::default()`
2. If `!skip_defaults`: merge system config (optional), merge user config (optional)
3. If CLI path set: merge CLI config (required -- error if missing)
4. Apply `HARDENER_DISABLED_PLUGINS` and `HARDENER_ENABLED_PLUGINS` env vars
5. Return final `HardenerConfig`

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `merge_source(base, path, required)` | 78-91 | Load file if exists, merge; error if required and missing |
| `load_from_file(path)` | 104-120 | `fs::read_to_string` + `toml::from_str` |
| `merge_configs(base, overlay)` | 123-135 | Field-by-field merge of all 8 plugin sections + global |
| `merge_global(base, overlay)` | 138-152 | Overlay replaces base lists if non-empty |
| `merge_plugin(base, overlay)` | 155-169 | Extend directives/custom_directives/exceptions; overlay.enabled wins |
| `apply_env_overrides(config)` | 172-180 | Parse `HARDENER_DISABLED_PLUGINS`, `HARDENER_ENABLED_PLUGINS` |
| `parse_env_list(input)` | 182-188 | Comma-split, trim, filter empty |

## Flags
- None
