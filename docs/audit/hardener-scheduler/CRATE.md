# hardener-scheduler Audit Summary
**Crate:** `crates/hardener-scheduler` | **Files:** 11 | **Lines:** ~3,580

## Architecture
Cron-based scanning daemon. `Daemon` manages lifecycle (start/stop/signal handling), `ScanRunner` orchestrates plugin scans → severity filtering → JSON export → DB persistence → notifications. Notification subsystem uses `Notifier` trait with email (SMTP/lettre) and webhook (Slack/Discord/Generic) implementations. Systemd unit generator for alternative scheduling.

## Per-File Documentation
| File | Lines | Doc |
|------|-------|-----|
| `runner.rs` | 616 | [runner.md](runner.md) |
| `db.rs` | 603 | [db.md](db.md) |
| `daemon.rs` | 382 | [daemon.md](daemon.md) |
| `notification/webhook.rs` | 360 | [notification_webhook.md](notification_webhook.md) |
| `systemd.rs` | 276 | [systemd.md](systemd.md) |
| `config.rs` | 258 | [config.md](config.md) |
| `notification/mod.rs` | 242 | [notification_mod.md](notification_mod.md) |
| `json_store.rs` | 205 | [json_store.md](json_store.md) |
| `notification/email.rs` | 197 | [notification_email.md](notification_email.md) |
| `notification/dispatcher.rs` | 142 | [notification_dispatcher.md](notification_dispatcher.md) |
| `lib.rs` | 24 | [lib.md](lib.md) |

## Fixes Applied (9)
| # | File | Line | Severity | Fix |
|---|------|------|----------|-----|
| 1 | db.rs | 237 | Bug | `WHERE deleted_at` → `WHERE started_at` (column doesn't exist; cleanup was no-op) |
| 2 | db.rs | 163 | SQL hygiene | `format!(" LIMIT {}")` → bind parameter |
| 3 | daemon.rs | 187 | Typo | "Crate" → "Create" in comment |
| 4 | webhook.rs | 45 | Typo | "replace" → "replaced" in doc |
| 5 | systemd.rs | 34 | Typo | "path to the given schedule" → "path to the hardener binary" |
| 6-9 | systemd.rs | 153,160,167,174 | Antipattern | `parse().is_ok()` + `parse().unwrap()` → nested `match` (4 unwraps removed) |
| 10 | json_store.rs | 13 | Typo | Leftover "Placeholder (!)" struct doc |
| 11 | json_store.rs | 39 | Bug | `&session_id[..8]` panics on short strings; safe truncation |
| 12 | dispatcher.rs | 72 | Typo | "in parallel" → "sequentially" (doc matched reality) |

## Design Flags (deferred)
| # | File | Issue |
|---|------|-------|
| D1 | db.rs:375 | `started_at_utc()` returns epoch (1970) for invalid timestamps via `unwrap_or_default()` |
| D2 | db.rs:386 | `plugins()` returns empty vec on corrupted JSON via `unwrap_or_default()` |
