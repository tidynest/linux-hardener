# hardener-scheduler::json_store
**File:** `crates/hardener-scheduler/src/json_store.rs` | **Lines:** 205

## Purpose
Timestamped JSON file storage for scan result exports. Writes pretty-printed JSON with SHA-256 integrity hashes. Supports listing, reading, verification, and retention-based cleanup.

## Dependencies
- Imports from: `chrono`, `hardener_common::error`, `ring::digest`, `serde`, `hex`, `tokio::fs`
- Used by: `runner.rs` (JSON export step)

## Public Interface
| Item | Kind | Description |
|------|------|-------------|
| `JsonStore` | struct | Manages JSON files in an output directory |
| `JsonStore::write()` | async fn | Writes data as timestamped JSON, returns (path, hash) |
| `JsonStore::list()` | async fn | Lists JSON files newest-first |
| `JsonStore::read()` | async fn | Reads and deserialises a JSON file |
| `JsonStore::verify()` | async fn | Checks file hash against stored hash |
| `JsonStore::cleanup()` | async fn | Deletes old files, keeping most recent N |

## Flags
- **TYPO** (line 13): Fixed — struct doc was leftover "Placeholder (!)".
- **BUG** (line 39): Fixed — `&session_id[..8]` panicked on short strings; replaced with safe `session_id.len().min(8)` truncation.
