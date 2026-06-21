# Session Handoff — 2026-06-21

> **Read this first.** Point-in-time handoff for the next development session and
> assistant. Living task list is [NEXT.md](NEXT.md); roadmap is [ROADMAP.md](ROADMAP.md).
> Project is **v1.0.5** (a backlog of changes has accumulated under CHANGELOG
> `[Unreleased]` — a version cut is a reasonable near-term housekeeping step).

---

## TL;DR

Two bodies of work completed since the 2026-06-19 handoff, **all merged to `main`
and pushed to both remotes** (GitHub + GitLab at `ef415f2`):

1. **Compliance-mapping accuracy — finished end-to-end.** CIS catalogue hygiene,
   an unsourced CIS id removed, HIPAA citations corrected against upstream SSG,
   and GDPR verified clean. The compliance reporting is now both *honest* (no
   false passes) and *credible* (mappings match their sources).
2. **Multi-host SSH — slice 1 (per-host history persistence) shipped.** Built via
   the full brainstorm → spec → plan → subagent-driven execution → review flow.
   `hardener batch scan` now persists each host's results to the scan-history
   database, keyed by host, and they read back with `history list --host <key>`.

**Next agreed priority: per-host trend tracking** (Multi-host slice 2) — the
natural follow-on now that per-host history is persisted.

---

## What shipped this session (on `main`, pushed)

Commit range `2ac00c0`..`ef415f2`. Two themes:

### A. Compliance-mapping accuracy

| Commit | Change |
|--------|--------|
| `95c21ae` | Curate CIS SSH crypto controls `5.2.14`–`5.2.16` (Kex/Ciphers/MACs) into `cis.rs`. NOTE the phase-3 coverage-merge already gave Option-B `Pass` for these — the curated entries are standard *completeness*, not a Pass fix. |
| `ac3b7a0` | Parse a `:port` suffix in ad-hoc `batch --ssh user@host:port` (was always 22). IPv6-safe; bracketed `[::1]:port` is the documented ceiling. |
| `44941e0` | Fix the desktop crate: Tauri compliance commands still called the pre-phase-3 1-arg `ReportGenerator::new`. Ported to `(config, compliance_coverage())`. Also bumped `tauri` 2.11.2→2.11.3 (lockfile). The old "desktop won't build / frontend dist" note was **stale** — `crates/hardener-ui/dist` exists; this API break was the real blocker. |
| `9dc4ed5` | Remove the kernel plugin's **unsourced** CIS `1.6.1` on `fs.protected_*links` — upstream SSG carries no CIS ref for those sysctls, and `1.6.1` is the MAC subsection header (curated has `1.6.1.1-.4`). Kept the sourced NIST/STIG. |
| `1f83629` | Correct HIPAA on kernel exploit-mitigation sysctls: `164.312(c)(1)` (Integrity) was wrong. SSG cites `164.312(a)` where it maps these at all, never `(c)(1)`. Re-cited ASLR/`dmesg_restrict`/`suid_dumpable` → `(a)(1)`; dropped the SSG-unsourced `kptr_restrict`/`ptrace_scope`/`protected_*links`. |
| `c6bbb51` | Align permissions/MAC HIPAA: both already carried `164.312(a)(1)` next to a `(c)(1)`; dropped the redundant `(c)(1)` to match SSG's `(a)` preference. Tests now assert `(c)(1)` is absent. |

GDPR was reviewed and found **clean** — the `TM-*` scheme is the project's own and
internally consistent; `Art.32(1)(a)` is correctly scoped to SSH crypto only.

### B. Multi-host SSH — per-host history persistence (slice 1)

Commits `946b27c`..`ef415f2`. Spec at
`docs/superpowers/specs/2026-06-21-per-host-history-persistence-design.md`;
plan at `docs/superpowers/plans/2026-06-21-per-host-history-persistence.md`
(both untracked — `docs/superpowers/` is gitignored).

- `946b27c` — **WAL + busy_timeout** on the history pool (`hardener-scheduler/src/db.rs`) so concurrent per-host writes are safe.
- `b680108` — `report.rs` `scan_grouped()` returns `Vec<(PluginMetadata, Vec<Finding>)>` so `plugin_id` survives; `run_scan` flattens it (signature unchanged); `finding_to_scan_finding` moved to `report.rs` `pub(crate)` (shared by `scan` + `batch`).
- `14dca62` — `batch.rs` threads `Option<Arc<ScanHistoryManager>>` + `host_key`; `persist_host` writes a `create_session("batch", host_key, plugins)` → `complete_session` per host, **best-effort**.
- `606a9ab`, `ef415f2` — review follow-ups: differentiated the two history-disabled warnings; `fail_session` if completion errors (no orphaned `running` rows).

**Verification at handoff:** 147 `hardener-scheduler` + `hardener-cli` tests pass;
clippy + fmt clean; `cargo build --workspace` (incl. desktop bin) clean.

---

## Start here next session: per-host trend tracking (Multi-host slice 2)

**Goal:** surface a per-host security-score timeline (and likely a CLI view) from
the history now being persisted.

**Entry point:** `hardener_scheduler::db` already stores every batch/CLI scan as a
session row (`host_identifier`, `started_at`, `status`, counts) plus its findings.
A trend is `(host_key, timestamp, score, severity counts)` over those rows.

**The one deliberately-deferred decision** (from the slice-1 spec's "out of scope"
and the NEXT.md follow-up): the **score/severity storage shape** —
1. *Derive on query* from the persisted findings/sessions (no new table), or
2. a denormalised `scan_scores` table recorded at scan time (the old
   `2026-03-27-multi-host-management.md` plan's approach).

Brainstorm this first (it's a real fork), then spec → plan → execute like slice 1.
The scoring function and `SeverityCounts` already exist; a query-derived first cut
is the lazier path and keeps storage decisions reversible.

**Also resolve while here:** the **Debug-vs-Display** serialisation follow-up
(below) — it touches the same persisted columns trends will read, so decide it
before trend data accumulates further.

---

## Architecture the next assistant needs

**Two SQLite databases — don't conflate them:**
- `hardener_state::db` → `checkpoints.db` — checkpoints / rollback / audit trail.
  Has its *own* `scan_sessions` table **without** a host column. Not the history store.
- `hardener_scheduler::db` → `scheduler.db` — **the scan-history store**, host-aware.
  This is what `scan`, `history`, and now `batch` use.

**`hardener_scheduler::db::ScanHistoryManager` (the history API):**
- `new(path)` — pool now opens with **WAL** + 5s `busy_timeout`.
- `create_session(trigger_type, host, plugins) -> session_id` (`host` = the `host_identifier` column).
- `complete_session(id, &[ScanFinding], json_path, hash)` / `fail_session(id, error)`.
- `list_sessions(&SessionFilter { host, status, since, until, limit })` — host-filtered reads already exist (`history list --host` is wired to this).

**Batch persistence (`crates/hardener-cli/src/commands/batch.rs`):**
- `scan_all` → `scan_one` → `scan_with_executor` thread `Option<Arc<ScanHistoryManager>>`.
- `host_key` = inventory `name`, else `user@host:port` for ad-hoc (heuristic: ad-hoc profiles have `name == hostname`).
- `persist_host` is best-effort (returns `()`, logs via `warn!`, can never change a `HostOutcome`).

**Scan helper (`crates/hardener-cli/src/commands/report.rs`):**
- `scan_grouped()` keeps per-plugin grouping; `run_scan()` flattens it; `finding_to_scan_finding()` is the shared `Finding -> ScanFinding` converter (`pub(crate)`).

**Compliance (unchanged this session except the mapping fixes):**
- Per-control coverage: each plugin's `coverage()` is aggregated by
  `hardener_plugins::compliance_coverage()` and **injected** into
  `ReportGenerator::new(config, coverage)` (CLI, desktop, scheduler all do this).
- `generator.rs` folds coverage into the catalogue for *every* framework (incl. CIS):
  covered → `Pass`/`Fail`, else `ManualReview`.
- Curated catalogues: **CIS + ISO 27001 only** (`frameworks::curated_controls`).
  Non-CIS are derived from coverage.
- HIPAA / GDPR / ISO are the project's **interpretive** layer (SSG rarely carries
  them); CIS/STIG/NIST/PCI are sourced from ComplianceAsCode/SSG and cited inline.

---

## Invariants & gotchas (do not break)

- **Best-effort persistence:** a history-write failure must never change a scan
  result. `persist_host` has no error return path — keep it that way.
- **Safe-failure compliance mappings:** a wrong/imperfect mapping may only ever
  cause a false *failure*, never a false *pass*. Source ids from
  ComplianceAsCode/SSG (`github.com/ComplianceAsCode/content`, the rule
  `references:` blocks) and cite the rule id in a `// SSG:` comment. Prefer
  *omitting* a mapping over guessing — the HIPAA fixes this session followed
  exactly this (verified via `gh api` on the rule.yml files).
- **`host_key` limitations:** renaming an inventory host starts a fresh timeline
  (the key *is* the identity); an inventory host deliberately named after its own
  hostname is keyed by `user@host:port` (documented in `scan_one`).
- **Debt — Debug vs Display serialisation (OPEN):** `finding_to_scan_finding`
  writes `severity`/`category` to history via `{:?}` (`"Critical"`, `"FileSystem"`),
  not the official `Display` strings (`"CRITICAL"`, `"File System"`). Pre-existing
  (single-host `scan` writes the same), so switching needs a one-time decision on
  existing rows. Tracked in NEXT.md; resolve alongside the trends slice.
- **Pre-commit gate (`rust-sec-ci`):** prints ~91 production + ~42 test naming
  warnings (abbreviations, a few British-spelling flags on *official* NIST/ISO
  control titles kept on purpose). These are pre-existing and harmless — the gate
  passes at **0 errors**. Don't "fix" them.
- **Two remotes, one push:** `origin` has a dual push URL (GitHub **and** GitLab),
  so `git push origin main` publishes to both. The pre-*push* gate runs
  fmt/clippy/cargo-audit; fix the report or `git push --no-verify`, never disable
  `core.hooksPath`.
- **Desktop crate builds** (`cargo check/build -p linux-hardener-desktop`) because
  `crates/hardener-ui/dist` exists; a full bundled `tauri build` still re-runs
  `trunk build --release` via `beforeBuildCommand`.
- **Conventions:** no AI attribution anywhere (commits/code/comments); `cargo fmt`
  before commits; Rust let-chains, never nested `if`; British spelling in prose;
  never run Playwright/GUI tests on the host (nspawn containers only);
  `docs/superpowers/` is gitignored (specs/plans live there untracked).

---

## How to verify

```bash
cargo test  -p hardener-scheduler -p hardener-cli -p hardener-plugins -p hardener-compliance
cargo clippy -p hardener-scheduler -p hardener-cli --all-targets
cargo fmt --check
cargo build --workspace          # incl. the desktop bin (dist already built)
```
All clean at handoff.

---

## Remaining work (priority order, from NEXT.md)

1. **Multi-host SSH — per-host trend tracking** (slice 2). *Start here.*
2. Multi-host SSH — regression alerts (needs trends first).
3. Multi-host SSH — `batch report` / `batch apply` subcommands.
4. Multi-host SSH — desktop multi-host view (largest GUI effort).
5. Debug-vs-Display history serialisation decision (small; do with trends).
6. RHEL 10 / per-version compliance profiles; cross-distro re-validation (needs containers + root, human-run).
7. More frameworks (SOC 2 / FedRAMP / NIST 800-171); deeper HIPAA/GDPR interpretive review.
8. Version cut for the accumulated `[Unreleased]` changelog; external security audit.

---

## Git state at handoff

- `main` = `ef415f2`, **pushed to both remotes** (GitHub + GitLab); working tree
  clean apart from two unrelated untracked paths (`.rust-sec-ci.toml`,
  `docs/superpowers/`).
- The `feat/per-host-history-persistence` branch was FF-merged and deleted.
