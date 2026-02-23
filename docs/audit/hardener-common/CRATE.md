# hardener-common — Crate Audit

**Crate:** `crates/hardener-common/` | **Files:** 5 | **Lines:** 680 (478 prod, 202 test)

## Purpose
Shared foundation crate — error types, atomic file operations, config parsing, logging init, and type re-exports. Every other crate in the workspace depends on this one.

## Architecture
```
lib.rs ──┬── error.rs        HardeningError enum + Result alias
         ├── file_utils.rs   Atomic writes, config parse/edit, backups
         ├── logging.rs      Tracing subscriber init
         └── types.rs        Re-exports from hardener-types
```

## Inter-Module Data Flow
```
Caller (any crate)
  ├─ read_config_file / read_config_file_optional → String
  │    └─ parse_config_value → Option<String>
  ├─ set_config_directive → modified String
  ├─ safe_modify_file → backup + read + modify + atomic write
  │    ├─ backup_file
  │    └─ update_file_atomically
  └─ All errors → HardeningError → Result<T>
```

## Public Interface Summary
| Module | Items | Key Types |
|--------|-------|-----------|
| error | 2 | `HardeningError` (14 variants), `Result<T>` |
| file_utils | 9 | `ConfigFormat`, 8 functions |
| logging | 1 | `init_logger()` |
| types | 7 | Re-exports from hardener-types |

## Aggregate Flags
| Severity | File | Issue | Status |
|----------|------|-------|--------|
| BUG | file_utils.rs:272 | Copy-paste error message in `create_timestamped_backup` | Fixed |
| TYPO | logging.rs:14 | Grave accent `ìnfo` → `info` | Fixed |
| MISSING | lib.rs | No `//!` module doc | Fixed |
| DESIGN | file_utils.rs:213-220 | `set_config_directive` KeyValue writes space-separated | Flagged |
| SILENT | file_utils.rs:345-347 | `safe_modify_file` errors on backup cleanup failure | Flagged |
| LOSSY | error.rs:70-74 | `From<anyhow::Error>` maps all to `Executor` | Flagged |

## Unwraps
Zero production `.unwrap()` calls.

## Verdict
Clean crate. 3 issues fixed, 3 design-level flags deferred for later decision.
