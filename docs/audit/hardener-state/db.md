# hardener-state::db
**File:** `crates/hardener-state/src/db.rs` | **Lines:** 201 (118 prod, 83 test)

## Purpose
Database initialisation: creates SQLite pool, applies schema (checkpoints + scan history tables + indexes).

## Dependencies
- Imports from: `sqlx::sqlite` (pool, options), `hardener_common::error`
- Used by: CLI `main.rs` (checkpoint DB), Tauri backend (scan history DB)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `DEFAULT_DB_PATH` | const | `/var/lib/linux-hardener/checkpoints.db` |
| `init_db(path)` | async fn | Creates DB file + pool, applies schema, returns `SqlitePool` |

## Data Flow
`init_db()` → create parent dir → `SqliteConnectOptions::new()` → `SqlitePoolOptions::new().max_connections(5)` → `connect_with()` → execute SCHEMA → return pool

## Schema Overview
- `checkpoints` (id TEXT PK, name, timestamp, username, signature BLOB, created_at)
- `file_states` (id AUTOINCREMENT, checkpoint_id, file_path, content BLOB, permissions, owner_uid/gid)
- `scan_sessions` (id TEXT PK, started_at, completed_at, total_findings, total_plugins, status)
- `scan_results` (id AUTOINCREMENT, session_id FK → scan_sessions ON DELETE CASCADE, plugin_id, success, duration_us, error_message)
- `scan_findings` (id AUTOINCREMENT, result_id FK → scan_results ON DELETE CASCADE, finding_id, category, severity, title, description, ...)
- 5 indexes on timestamp, checkpoint_id, started_at, session_id, result_id

## Flags
- **SCHEMA MISMATCH** (line 25): `file_states.checkpoint_id` declared as `INTEGER` but references `checkpoints.id` which is `TEXT`. Works due to SQLite type affinity, but misleading.
- **TYPO** (line 3): "Use SQLite" → "Uses SQLite".
