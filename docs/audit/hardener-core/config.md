# hardener-core::config
**File:** `crates/hardener-core/src/config.rs` | **Lines:** 286 (154 prod, 132 test)

## Purpose
Configuration structures: root `HardenerConfig` with per-plugin `PluginConfig` sections (enabled, directives, exceptions) and `PolicyException` with expiry checking.

## Dependencies
- Imports from: `serde`, `chrono` (for expiry date parsing)
- Used by: `config_loader.rs` (deserialization target), `plugin_manager.rs` (`get_plugin_config()`), all 8 plugins (receive `&PluginConfig`), `lib.rs` (re-exported)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `HardenerConfig` | struct | Root config: `global` + 8 plugin sections (ssh, kernel, firewall, pam, audit, mac, permissions, services) |
| `HardenerConfig::is_plugin_enabled(&str)` | fn | Checks disabled list (precedence) then enabled list (empty = all) |
| `HardenerConfig::get_plugin_config(&str)` | fn | Match plugin_id string to field reference |
| `GlobalConfig` | struct | `enabled_plugins: Vec<String>`, `disabled_plugins: Vec<String>` |
| `PluginConfig` | struct | `enabled`, `directives`, `custom_directives`, `exceptions` HashMaps |
| `PluginConfig::has_valid_exception(&str)` | fn | Returns non-expired exception for key, or None |
| `PolicyException` | struct | `value`, `allowed`, `reason`, `approved_by`, `approved_date`, `ticket`, `expires` |
| `PolicyException::is_expired()` | fn | Parses `expires` as `%Y-%m-%d`, compares to today |
| `PolicyException::is_valid()` | fn | `allowed && !is_expired()` |

## Data Flow
1. `ConfigLoader::load()` deserializes TOML into `HardenerConfig`
2. `PluginManager::execute_apply()` calls `config.get_plugin_config(plugin_id)` per plugin
3. Plugins call `config.has_valid_exception(key)` to check exemptions during scan/apply
4. `is_plugin_enabled()` used by CLI to skip disabled plugins before registration

## Flags
- **BUG** (line 133): `get_plugin_config()` unknown `plugin_id` fallback returns `&self.ssh` instead of a neutral default. Any unrecognised plugin silently inherits SSH config. Should return a static empty `PluginConfig` or error. Status: **Flagged**.
