# hardener-cli::commands::state
**File:** `crates/hardener-cli/src/commands/state.rs` | **Lines:** 109 (all production)

## Purpose
Centralised state initialisation for database, signing key, and audit logger. Extracts the duplicated `get_checkpoint_manager()` pattern from `apply.rs` and `checkpoint.rs` into a single shared module (resolves design flag D2).

## Constants
| Name | Value | Description |
|------|-------|-------------|
| `SYSTEM_KEY_DIR` | `/etc/linux-hardener` | Root signing key directory |
| `SYSTEM_DATA_DIR` | `/var/lib/linux-hardener` | Root checkpoint database directory |
| `LEGACY_KEY_PATH` | `/var/lib/linux-hardener/signing.key` | Pre-migration key location |
| `SYSTEM_LOG_PATH` | `/var/log/linux-hardener/audit.log` | Root audit log path |

## Public Interface
| Function | Lines | Description |
|----------|-------|-------------|
| `resolve_paths()` | 24-51 | Returns `(db_path, key_path)` based on effective UID — root separates key from DB |
| `migrate_legacy_key()` | 55-67 | Moves signing key from `/var/lib/` to `/etc/` if legacy path exists |
| `get_checkpoint_manager()` | 69-74 | Creates `CheckpointManager` with DB pool + `CheckpointSigner` |
| `effective_user()` | 80-86 | Returns effective username for audit logging |
| `get_audit_logger()` | 92-109 | Creates `AuditLogger` at system or user path |

## Data Flow
```
resolve_paths() → (db_path, key_path)
                    │           │
                    ▼           ▼
              init_db(db)   CheckpointSigner::new_with_path(key)
                    │           │
                    └─────┬─────┘
                          ▼
                  CheckpointManager::new(pool, signer)
```

## Design Notes
- Root: key at `/etc/linux-hardener/signing.key` (0400), DB at `/var/lib/linux-hardener/checkpoints.db`
- Non-root: both in `$XDG_DATA_HOME/linux-hardener/`
- Used by: `apply.rs`, `checkpoint.rs`, `history.rs`

## Flags
None.
