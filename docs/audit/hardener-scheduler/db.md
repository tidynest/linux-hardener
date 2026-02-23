# hardener-scheduler::db
**File:** `crates/hardener-scheduler/src/db.rs` | **Lines:** 603

## Purpose
SQLite persistence for scheduled scan history using `sqlx`. Manages sessions, findings, and notification log. Schema embedded as `const SCHEMA_SQL`. Dynamic query building in `list_sessions()`.

## Dependencies
- Imports from: `chrono`, `hardener_common::error`, `sqlx`, `serde`, `uuid`
- Used by: `runner.rs`, `notification/dispatcher.rs`

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ScanHistoryManager` | struct | Database manager wrapping `SqlitePool` |
| `ScanSession` | struct | Session row from database |
| `ScanFinding` | struct | Finding input structure |
| `ScanFindingRow` | struct | Finding row from database |
| `SessionFilter` | struct | Query filter criteria |
| `SeverityCounts` | struct | Aggregated severity breakdown |

## Flags
- **BUG** (line 237): Fixed — `cleanup()` used `WHERE deleted_at < ?` but schema has no `deleted_at` column; changed to `started_at`. Time-based cleanup was silently a no-op.
- **FIXED** (line 163): `format!(" LIMIT {}", limit)` injected value into SQL string; changed to bind parameter.
- **STYLE** (line 375): `started_at_utc()` returns epoch on invalid timestamp via `unwrap_or_default()`.
- **STYLE** (line 386): `plugins()` returns empty vec on corrupted JSON via `unwrap_or_default()`.
