# hardener-state — Crate Audit

**Version:** 0.3.3 | **Files:** 9 | **Lines:** ~2,550 total
**Role:** State persistence layer — checkpoints, rollback, audit logging, scan history.

## Architecture Overview

```
lib.rs (re-exports)
├── checkpoint.rs      ── types: CheckpointId, Checkpoint, FileState, RollbackResult
├── scan_history.rs    ── types: ScanSessionId, ScanStatus, ScanSession
├── db.rs              ── SQLite init: schema, pool (shared by checkpoint + scan)
├── signing.rs         ── Ed25519 key management (generate/load/sign/verify)
├── hash_chain.rs      ── SHA-256 chain for tamper-proof audit log
├── audit.rs           ── AuditLogger: append-only log with hash chain
├── manager.rs         ── CheckpointManager: create/rollback/CRUD
└── scan_manager.rs    ── ScanHistoryManager: GUI scan persistence
```

## Inter-Module Data Flow

```
CLI/Tauri → init_db() → SqlitePool
                           ├─→ CheckpointManager(pool, CheckpointSigner)
                           │     ├── create_checkpoint() → capture files → sign → store
                           │     └── rollback() → get checkpoint → restore files
                           └─→ ScanHistoryManager(pool)
                                 ├── start_session() → store_results() → complete_session()
                                 └── get_latest_scan() / list_sessions()

AuditLogger(file_path) → log_action()/log_failure() → HashChain.next_hash() → append JSON
                        → verify_integrity() → re-walk chain → bool
```

## Security Surface

| Component | Risk | Mitigation |
|-----------|------|------------|
| Signing key (`signing.rs`) | Key theft → forged checkpoints | Stored at `/etc/linux-hardener/signing.key` with 0400 perms; AES-256-GCM encrypted at rest |
| Audit log (`audit.rs`) | Log tampering | SHA-256 hash chain; `verify_integrity()` detects modifications |
| File restore (`manager.rs`) | Rollback writes arbitrary files as root | Scoped to previously-captured paths; requires root privileges |
| SQLite DB (`db.rs`) | DB corruption | Schema with foreign keys + ON DELETE CASCADE; pool max 5 connections |

## Aggregate Public Interface

| Module | Structs | Enums | Functions |
|--------|---------|-------|-----------|
| checkpoint | 4 (CheckpointId, Checkpoint, FileState, FileRestoreResult, RollbackResult) | 1 (FileRestoreAction) | — |
| scan_history | 2 (ScanSessionId, ScanSession) | 1 (ScanStatus) | — |
| db | — | — | 1 (init_db) |
| signing | 1 (CheckpointSigner) | — | — |
| hash_chain | 1 (HashChain) | — | — |
| audit | 2 (AuditEntry, QueryFilter) + 1 (AuditLogger) | 2 (ActionType, ActionResult) | — |
| manager | 1 (CheckpointManager) | — | — |
| scan_manager | 1 (ScanHistoryManager) | — | — |

## Audit Findings

| # | File | Severity | Finding | Resolution |
|---|------|----------|---------|------------|
| 1 | audit.rs:120-131 | Medium | Dead `serialise_for_hash()` — never called | **Deleted** |
| 2 | audit.rs:130 | Medium | `unwrap_or_default()` in dead code | Resolved by #1 |
| 3 | audit.rs:277/68 | Design | TOCTOU: two `Utc::now()` calls — hashed vs stored timestamps differ | **Flagged — defer** |
| 4 | audit.rs:46 | Low | Typo "Use who" | **Fixed** |
| 5 | audit.rs:140 | Low | Doc says "minimum" for end_time | **Fixed** |
| 6 | manager.rs:417 | Low | SQL `WHERE id =?` spacing | **Fixed** |
| 7 | scan_manager.rs:232 | Medium | `unwrap_or_default()` hides corrupted JSON | **Added tracing::warn** |
| 8 | scan_manager.rs:235 | Medium | `unwrap_or_default()` hides corrupted JSON | **Added tracing::warn** |
| 9 | scan_manager.rs:364,387 | Low | Silent enum fallbacks for unknown strings | **Flagged — defer** |
| 10 | signing.rs:1,3 | Low | Module doc typos | **Fixed** |
| 11 | db.rs:25 | Low | Schema: INTEGER should be TEXT for FK | **Fixed** |
| 12 | db.rs:3 | Low | Module doc typo | **Fixed** |
| 13 | hash_chain.rs:1 | Low | Missing module doc | **Added** |
| 14 | hash_chain.rs:11 | Low | "32-bit" → "32-byte" | **Fixed** |
| 15 | lib.rs:23-36 | Medium | Dead `add()`/`it_works` cargo template | **Deleted** |

**Totals:** 13 fixed, 2 deferred (design flags)

## Verification

- `RUSTFLAGS="-D warnings" cargo check -p hardener-state --all-features` — clean
- `cargo clippy -p hardener-state --all-features -- -D warnings -D clippy::unwrap_used` — clean
- `cargo test --workspace` — 400 passed, 0 failed (down 1 from deleted `it_works`)
