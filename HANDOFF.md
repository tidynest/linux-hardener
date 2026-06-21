# Session Handoff — 2026-06-22

> **Read this first.** Point-in-time handoff for the next development session and
> assistant. Living task list is [NEXT.md](NEXT.md); roadmap is [ROADMAP.md](ROADMAP.md).
> Project is **v1.0.5** with a large backlog accumulated under CHANGELOG
> `[Unreleased]` — a version cut is a reasonable near-term housekeeping step.

---

## TL;DR

Three Multi-host SSH slices shipped this session, **all merged to `main`** (FF):

1. **Per-host trend tracking (CLI).** `hardener history trends --host <key>` — a
   derive-on-query timeline (completed scans oldest-first: per-severity counts,
   Δtotal, and a `better`/`worse`/`same` direction by severity priority). No new
   table, no stored score.
2. **Regression CI gate (CLI).** `hardener history regressions [--host]` — compares
   each host's two newest completed scans, exits `1` if any regressed (gate CI),
   `0` clean. `--format json`.
3. **Scheduler-driven regression notifications.** The daemon notifies via the
   configured email/webhook channels when a scheduled scan is *worse than the
   host's previous scan*. New `notify_mode` config: `findings` (default, old
   behaviour) / `regression` (quiet-until-change) / `both`. Built brainstorm →
   spec → plan → subagent-driven (6 units, 2-stage review each + a final
   whole-feature review).

**Git state:** `main` = `6f506b7` (+ this handoff commit). Was **18 commits ahead
of origin**; this session ends by **pushing to both remotes** (GitHub + GitLab).

**Next agreed priority:** `batch report` / `batch apply` subcommands, then the
desktop multi-host view (largest GUI effort).

---

## What shipped this session

| Commits | Slice |
|---------|-------|
| `675b2fd` | `history trends --host` — per-host timeline (direct on main) |
| `9ca0534` | `history regressions [--host]` — regression CI gate (direct on main) |
| `9d3773e`..`6f506b7` (15) | scheduler regression notifications (branch, FF-merged + deleted) |

### Scheduler regression notifications — architecture the next assistant needs

**Config** (`hardener-scheduler/src/config.rs`): `NotificationConfig` gains
`notify_mode: NotifyMode` — enum `Findings` (`#[default]`) / `Regression` / `Both`,
`#[serde(rename_all = "lowercase")]`. The struct keeps `#[derive(Default)]` +
`#[serde(default)]`, so an omitted key deserialises to `Findings` (old behaviour;
fully backward compatible).

**Shared severity-compare primitives** (`hardener-scheduler/src/db.rs`) — used by
BOTH the CLI and the daemon (no duplication):
- `SeverityTuple = (i64, i64, i64, i64, i64)` = (critical, high, medium, low, info).
- `ScanSession::severity_tuple()`.
- `above_floor(t, floor)` — zeroes counts below `floor` (Critical keeps only
  critical; Info keeps all).
- `trend_direction(prev, cur) -> &'static str` — `"better"`/`"worse"`/`"same"`;
  used by the CLI `trends` *display* only.
- `is_worse(prev, cur) -> bool` — `cur > prev`; the typed check used by all *logic*
  (CLI `find_regressions` and the daemon). Callers pre-zero with `above_floor`.

**Policy** (`hardener-scheduler/src/notification/mod.rs`): pure
`alert_decision(mode, floor, previous: Option<&ScanSession>, current: &ScanSummary)
-> (bool /*send*/, Option<RegressionInfo>)`:
- `absolute = (Findings|Both) && meets_severity_threshold(current, floor)`
- `regressed = (Regression|Both) && previous && is_worse(above_floor(prev,floor), above_floor(cur,floor))`
- returns `(absolute || regressed, regressed ? Some(delta) : None)`.
- A floor-regression always also meets the absolute threshold, so `Both` sends
  once (annotated), never twice.

**Dispatch** (`notification/dispatcher.rs`): the dispatcher owns the decision.
`dispatch(&self, summary, previous: Option<&ScanSession>)` resolves the floor ONCE
at construction (empty `notify_min_severity` ⇒ `Critical`) and uses that same value
for both the absolute and regression checks. It clones+annotates the summary only
when a regression is present (non-regression path is allocation-free). `send_test`
sends to all channels UNCONDITIONALLY (bypasses the gate) — used by the desktop
"test notification" button so `notify_mode=regression` doesn't no-op it.

**Runner** (`runner.rs`): after `complete_session`, fetches
`db.previous_completed_session(host, exclude_id)` and passes it to `dispatch`.
**Best-effort** — a lookup `Err` becomes `None` (warn + continue); it can NEVER
fail the scan.

**Rendering:** `RegressionInfo` (deltas = current − previous) on `ScanSummary`;
email gets a `[REGRESSION]` subject prefix + a delta block; webhook generic payload
gets a `regression` object (null when absent) and Slack/Discord get a
`[REGRESSION] ` title marker.

---

## Invariants & gotchas (do not break)

- **Best-effort persistence/notification:** a history-write, regression-lookup, or
  notify failure must NEVER change a scan result. The lookup + dispatch run *after*
  `complete_session`; keep the warn-and-continue shape.
- **One floor:** the dispatcher resolves `notify_min_severity` (empty ⇒ Critical)
  once; `alert_decision` uses that for both checks. Do NOT re-derive a floor
  elsewhere (bare `parse_severity("")` returns Medium — a mismatch).
- **Self-dedup is stateless:** a regression fires only on the transition scan
  (the next scan's baseline is the now-worse state ⇒ `same` ⇒ silent). Do NOT add
  an "already alerted" flag/table.
- **Test notifications bypass the gate:** the desktop "test" path must use
  `dispatcher.send_test(...)`, never `dispatch(...)`.
- **`previous_completed_session` assumes the caller passes the newest scan** as
  `exclude_id` (reads only the 2 newest completed sessions). True for the runner.
- **`docs/superpowers/` is UNTRACKED, not gitignored** (prior handoffs said
  gitignored — wrong; `git check-ignore` returns nothing and `git add -A` WOULD
  catch specs/plans). Stage specs/plans out manually.
- **Whole-workspace build catches what per-crate builds miss:** the plan missed a
  4th `ScanSummary` site + a 2nd `dispatch` caller in `src-tauri`; only
  `cargo build --workspace` surfaced them. Always run it before claiming done.
- **Debug-vs-Display history serialisation (OPEN, in NEXT.md):**
  `finding_to_scan_finding` writes `severity`/`category` via `{:?}` not `Display`.
  Trends/regressions read the numeric `*_count` columns (case-insensitively
  derived), so they are UNAFFECTED — it's a cosmetic per-finding string issue.
- **Pre-commit gate (`rust-sec-ci`):** prints ~91 production + ~48 test naming
  warnings (abbreviations, a few British-spelling flags on official control
  titles). Pre-existing, 0 errors — do NOT "fix" them.
- **Two remotes, one push:** `origin` has a dual push URL (GitHub + GitLab). The
  pre-*push* gate runs fmt/clippy/cargo-audit; fix the report or
  `git push --no-verify`, never disable `core.hooksPath`.
- **Conventions:** no AI attribution anywhere; `cargo fmt` before commits; Rust
  let-chains, never nested `if`; British spelling in prose; Playwright/GUI tests in
  nspawn containers only.

---

## How to verify

```bash
cargo test  -p hardener-scheduler -p hardener-cli
cargo clippy -p hardener-scheduler -p hardener-cli --all-targets
cargo fmt --check
cargo build --workspace          # incl. the desktop bin (dist already built)
```
All clean at handoff (96 scheduler + 71 CLI tests pass).

---

## Remaining work (priority order, from NEXT.md)

1. **Multi-host SSH — `batch report` / `batch apply` subcommands.** *Start here.*
2. Multi-host SSH — desktop multi-host view (largest GUI effort).
3. Debug-vs-Display history serialisation decision (small).
4. RHEL 10 / per-version compliance profiles; cross-distro re-validation (needs
   containers + root, human-run).
5. More frameworks (SOC 2 / FedRAMP / NIST 800-171); deeper HIPAA/GDPR review.
6. Version cut for the accumulated `[Unreleased]` changelog; external security audit.

---

## Git state at handoff

- `main` = `6f506b7` plus this handoff commit; **pushed to both remotes** (GitHub +
  GitLab) at session end. Working tree clean apart from untracked `.rust-sec-ci.toml`
  and `docs/superpowers/`.
- Branch `feat/scheduler-regression-notifications` was FF-merged and deleted.
- Spec/plan for this session's feature:
  `docs/superpowers/specs/2026-06-22-scheduler-regression-notifications-design.md`,
  `docs/superpowers/plans/2026-06-22-scheduler-regression-notifications.md` (untracked).
