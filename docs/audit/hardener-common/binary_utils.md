# hardener-common::binary_utils
**File:** `crates/hardener-common/src/binary_utils.rs` | **Lines:** 70 (43 prod, 27 test)

## Purpose
Prevents CWE-426 (Untrusted Search Path) by resolving program names to absolute paths from a trusted directory whitelist. Used by plugin executors to ensure hardening commands are not substituted via `$PATH` manipulation.

## Dependencies
- Imports from: `std::path::Path`
- Used by: `hardener-core::executor::local` (LocalExecutor command dispatch)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `TRUSTED_PATH` | const `&[&str]` | `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/local/bin`, `/usr/local/sbin` |
| `resolve_binary(program)` | fn | Returns absolute path if found in TRUSTED_PATH; otherwise returns original name unchanged |

## Data Flow
`resolve_binary("sysctl")` → check if absolute (return as-is) → iterate TRUSTED_PATH → `Path::new(dir).join(program).exists()` → first match → `/usr/sbin/sysctl`

## Tests
| Test | Description |
|------|-------------|
| `absolute_path_returned_unchanged` | `/usr/bin/ls` passes through |
| `resolves_common_binary` | `ls` resolves to an absolute path |
| `nonexistent_binary_returns_original` | Unknown binary returns input unchanged |

## Flags
None — clean, focused module.
