# hardener-state::audit
**File:** `crates/hardener-state/src/audit.rs` | **Lines:** 1,022 (463 prod, 559 test)

## Purpose
Tamper-proof audit logger using SHA-256 hash chain. Each entry hashes `previous_hash || serialised_data`, creating an append-only log where modifying any entry breaks the chain.

## Dependencies
- Imports from: `crate::HashChain` (hash computation), `chrono` (timestamps), `tokio::fs` (async file I/O), `serde_json` (serialisation)
- Used by: CLI apply/rollback commands, checkpoint operations (any action that needs an audit trail)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `ActionType` | enum | Scan, Apply, Rollback, ConfigChange, CheckpointCreate, CheckpointDelete |
| `ActionResult` | enum | Success, Failure |
| `AuditEntry` | struct | Single log entry: timestamp, action, user, target, result, details, hash |
| `AuditEntry::new()` | fn | Creates success entry |
| `AuditEntry::new_failure()` | fn | Creates failure entry with error message in details |
| `AuditEntry::add_detail()` | fn | Adds key-value detail to entry |
| `AuditEntry::serialise_for_hash()` | fn | **DEAD CODE** — never called; hashing is done inline in logger |
| `QueryFilter` | struct | Builder-pattern filter: action_type, user, start/end time, result |
| `AuditLogger` | struct | Holds file + hash chain behind tokio Mutexes |
| `AuditLogger::new(path)` | async fn | Opens/creates log file in append mode |
| `AuditLogger::log_action()` | async fn | Logs success/failure entry with hash chain |
| `AuditLogger::log_failure()` | async fn | Logs failure with error message |
| `AuditLogger::verify_integrity(path)` | async fn | Reads all entries, recomputes chain, detects tampering |
| `AuditLogger::query(path, filter)` | async fn | Returns entries matching filter criteria |

## Data Flow
`log_action()/log_failure()` → lock hash chain → serialise tuple → `chain.next_hash()` → create `AuditEntry` → serialise to JSON → append to file → `chain.update()`

## Flags
- **DEAD CODE** (line 120-131): `serialise_for_hash()` — never called. All hash computation is inline in `log_action`/`log_failure`.
- **TOCTOU** (line 277 vs 68): `Utc::now()` called once for hash input, then again in `AuditEntry::new()`. Stored timestamp differs from hashed timestamp. Not exploitable, but breaks hash-data correspondence.
- **SILENT FAILURE** (line 130): `unwrap_or_default()` on `serde_json::to_vec()` returns empty vec on serialisation failure, producing a wrong hash silently.
- **TYPO** (line 46): "Use who" should be "User who".
- **TYPO** (line 140): `filter_end_time` doc says "minimum" — should say "maximum".
