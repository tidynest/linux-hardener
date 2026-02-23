# hardener-common::file_utils
**File:** `crates/hardener-common/src/file_utils.rs` | **Lines:** 451 (362 prod, 89 test)

## Purpose
Safe file operations with atomic writes, backup support, and config-file parsing/editing.

## Dependencies
- Imports from: `crate::error` — Result/HardeningError, `tempfile` — atomic write via NamedTempFile, `std::io`/`std::fs`/`std::path`
- Used by: `hardener-plugins` (all 8 plugins read/write config files), `hardener-state` (checkpoint file ops)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `update_file_atomically` | fn | Write content via temp+rename (crash-safe) |
| `read_config_file` | fn | Read file or return error |
| `read_config_file_optional` | fn | Read file, `Ok(None)` if not found |
| `ConfigFormat` | enum | `SpaceSeparated`, `KeyValue`, `Auto` |
| `parse_config_value` | fn | Extract directive value from config content |
| `set_config_directive` | fn | Update or append directive in config content |
| `create_timestamped_backup` | fn | Copy file to `{path}.backup.{unix_ts}` |
| `backup_file` | fn | Copy file to `{path}.backup` |
| `safe_modify_file` | fn | Backup → read → modify → atomic write → cleanup |

## Data Flow
```
read_config_file → content string
  → parse_config_value (extract)
  → set_config_directive (modify in memory)
  → safe_modify_file or update_file_atomically (persist)
```

## Internal Functions
| Function | Lines | Description |
|----------|-------|-------------|
| `strip_prefix_with_case` | 179-187 | Case-insensitive prefix stripping helper |

## Flags
- **BUG (line 272):** `create_timestamped_backup` — error message on `fs::copy` failure says "Failed to get system time" (copy-paste from line 265). Should say "Failed to create backup".
- **DESIGN (lines 213-220):** `set_config_directive` — `KeyValue` branch emits `"{directive} {value}"` (space-separated), identical to `SpaceSeparated`. If a caller passes `ConfigFormat::KeyValue`, output won't contain `=`. May be intentional for SSH-style configs but contradicts the enum name.
- **SILENT (lines 345-347):** `safe_modify_file` — if atomic write succeeds but backup removal fails, returns error. The file was already updated, but the caller sees failure. Consider logging a warning instead of erroring.
