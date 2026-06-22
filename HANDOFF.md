# Session Handoff — 2026-06-22 (batch report shipped → batch apply next)

> **Read this first.** Point-in-time handoff for the next development session and
> assistant. Living task list is [NEXT.md](NEXT.md); roadmap is [ROADMAP.md](ROADMAP.md).
> Project is **v1.0.5** with a large backlog accumulated under CHANGELOG
> `[Unreleased]` — a version cut is a reasonable near-term housekeeping step.

---

## TL;DR

- **Shipped this session:** `hardener batch report` (Multi-host SSH slice) — merged
  to `main` (FF, 8 commits). Read-only fleet compliance assessment.
- **Start here next:** `hardener batch apply` — the last batch subcommand. See the
  **launchpad** below. **Begin with brainstorming** (it has real blast radius);
  do NOT jump to code.
- **Correction to prior handoffs (verified this session):** single-host *remote*
  apply already works — `apply.rs` runs over any `SystemExecutor`, and the CLI
  builds an `SshExecutor` from `--ssh`. So `sudo hardener --ssh user@host apply
  --all` already hardens a remote host. `batch apply` is **not** net-new remote
  plumbing; the open problems are narrower (privilege model, per-host
  checkpoints, blast-radius UX) — detailed below.
- **Git:** `main` at `9e9ddaa`, **9 commits ahead of `origin`, push pending** —
  the assistant can't push (SSH passphrases); the user pushes. `origin` has a dual
  push URL (GitHub + GitLab); one `git push origin main` hits both.

---

## What shipped this session — `hardener batch report`

Assess many hosts against a framework (`--framework`) or scenario preset
(`--scenario`, default `server` = CIS + STIG) concurrently → a **fleet posture
table** (one row per `(host, framework)`: compliance score + pass/fail/manual/N-A
control counts) + a per-framework rollup. Tiered exit (`0` compliant / `1` any
failing control / `2` any host error) gates CI. `--format json`, `--output`.
**Read-only** — never mutates a host.

**Architecture (thin by design):** a post-processor over `batch scan`, not a new
engine. `scan_all` already returns per-host `Vec<Finding>`;
`ReportGenerator::generate(&[Finding])` is pure over those. `run_report` →
`resolve_and_scan(...)` (the shared host-resolve + concurrent-scan +
history-persist block, **hoisted out of `batch scan`'s `run`** so both share one
copy; takes a `verb` for the progress line) → one shared `ReportGenerator` →
`host_report` per outcome (pure; `Failed` passed through untouched) →
`render_report_{text,json}` + `ReportRollup` → `report_exit_code`.
`resolve_scenario` (`commands/report.rs`, `pub(crate)`) is the single shared
framework/scenario→`Scenario` resolver for both report commands.

| Commits (FF-merged, branch `feat/batch-report` deleted) | |
|---|---|
| `47d5482` | extract shared `resolve_scenario` |
| `7ccba14` | posture types + tiered `report_exit_code` |
| `5e6ee26` | fleet rollup + text/json renderers |
| `0c87c22` | `run_report` over the scan engine |
| `e927d34` | review follow-up: hoist `resolve_and_scan`, flatten `resolve_scenario` |
| `065d919` | `BatchAction::Report` CLI variant |
| `fb9c873` | dispatch arm + CHANGELOG/NEXT |
| `9e9ddaa` | multi-framework-per-host rollup test |

Spec/plan (untracked): `docs/superpowers/specs/2026-06-22-batch-report-design.md`,
`docs/superpowers/plans/2026-06-22-batch-report.md`.

---

## ▶ Launchpad: `hardener batch apply` (next slice)

**Goal:** apply hardening to many remote hosts in one concurrent run. This is the
**dangerous** batch command (it mutates production fleets), so it earns a full
brainstorm → spec → plan → subagent-driven cycle. Do not shortcut it.

### What already exists (reuse, don't rebuild)

- **Remote apply works single-host.** `commands/apply.rs::run(plugin_filter, all,
  dry_run, format, quiet, executor)` runs `plugin.apply(&mut ctx, cfg)` (or
  `plugin.validate` when `dry_run`) over whatever `executor` it's handed. The CLI
  (`main.rs`) builds an `SshExecutor` from `--ssh`. The executor abstraction means
  apply commands transparently run over SSH. So per-host apply = give `apply::run`
  an `SshExecutor` for that host.
- **The batch concurrency engine.** `commands/batch.rs` has `resolve_hosts` /
  `parse_inline` (host-set resolution), `scan_one` / `scan_with_executor` (connect
  via `SshExecutor` then do per-host work, failure-isolated), `scan_all` (bounded
  concurrency via `Semaphore` + `JoinSet`, input-order preserved via
  `assemble_ordered`), and `HostOutcome` (per-host result envelope, `Scanned` /
  `Failed`). `resolve_and_scan` wraps resolve + `scan_all`. The **host iteration**
  is fully reusable; only the per-host *operation* (scan vs apply) differs.
- **Inventory + flags.** `--all` / `--host` / `--ssh` / `--concurrency` /
  `--output`, global `--format`, `--ssh-key`, `--ssh-timeout`, `--ssh-no-verify`
  are all already parsed and threaded for `batch scan`/`batch report` — mirror the
  `BatchAction::Report` variant + dispatch arm.

### The real open problems (the brainstorm must resolve these)

1. **Privilege model.** `apply.rs:23` gates on **local** `geteuid().is_root()`
   (`bail!` unless root or `--dry-run`). For a remote target that check is wrong —
   root is needed on the **remote** host, as the SSH user. For `batch apply`,
   either drop the local-euid gate for remote targets and rely on the remote
   user's privileges (apply commands fail over SSH if unprivileged), or add an
   explicit privilege precheck per host. Decide this deliberately; don't inherit
   the local check blindly.
2. **Per-host checkpoints & rollback.** Single-host apply builds a checkpoint
   manager via `get_checkpoint_manager()` writing to the **local**
   `/var/lib/linux-hardener/checkpoints.db` (`Context::with_executor_and_checkpoint`).
   Across a fleet this needs a decision: where does each host's pre-apply
   checkpoint live (local, keyed by host? remote, on each host?), and what does
   rollback mean for a batch (roll back one failed host? the whole fleet? never
   auto-roll-back, just report?). This is the crux of the design.
3. **Blast-radius UX.** Recommend `--dry-run` (validate-only) as the **default**,
   with real application requiring an explicit opt-in flag (e.g. `--apply` /
   `--confirm`). A typo must not silently harden 50 production boxes. (Single-host
   apply has no such guard because the local root + interactive context implies
   intent; a fleet needs an explicit gate.)
4. **Failure policy & exit codes.** Per-host isolation like `batch scan` (a failed
   host is a row, never aborts the fleet), with a tiered exit. Note the
   partial-apply reality: if host A succeeds and host B fails, A stays changed —
   document it; do not attempt fleet-wide atomicity.
5. **History/audit.** `batch scan`/`report` persist each host's scan to history
   best-effort. Decide whether `batch apply` records apply actions to history/audit
   per host (the single-host path already writes the local audit log).

### Suggested first move
`/ponytail` → brainstorm. The decomposition question is mostly settled (apply
over the existing batch engine), so the brainstorm's real work is items 1–3 above
(privilege, checkpoint/rollback, dry-run-default UX). Keep `batch apply` as its
own sub-project; don't fold the desktop multi-host view into it.

---

## Invariants & gotchas (do not break)

- **`batch report`/`scan` are READ-ONLY.** Only `batch apply` may mutate — and only
  behind the blast-radius gate decided in its brainstorm.
- **Best-effort persistence:** a history-write/lookup/notify failure must NEVER
  change a host's outcome or the exit code (inherited from `scan_all` /
  `persist_host`). Keep the warn-and-continue shape.
- **Per-host isolation:** a dead host becomes a `Failed` row (prefill +
  `assemble_ordered`), never aborts the fleet.
- **Honest assessment in `report_exit_code`:** only `failing > 0` raises to `1`;
  `ManualReview`/`NotApplicable` are NEVER failures; any host error → `2`.
- **One framework catalogue:** all framework/scenario parsing goes through
  `resolve_scenario`. Don't add a second parse path.
- **`hardener-cli` is a binary, not a lib:** test with `cargo test -p hardener-cli`
  (NOT `--lib`). 79 unit tests.
- **`Scenario` is imported in the `tests` module only** in `batch.rs` (the non-test
  path infers the type). Don't hoist it (unused-import in the bin build).
- **Pre-commit gate (`rust-sec-ci`):** ~91 production + ~48 test naming warnings
  (abbreviations, a couple British-spelling flags on official control titles).
  Pre-existing, **0 errors** — do NOT "fix" them.
- **`docs/superpowers/` is UNTRACKED, not gitignored** (`git check-ignore` returns
  nothing; `git add -A` WOULD catch specs/plans). Stage them out manually.
- **`cargo build --workspace` catches what per-crate misses** (desktop bin `dist`
  already built). Run it before claiming done.
- **Conventions:** no AI attribution anywhere; `cargo fmt` before commits; Rust
  let-chains, never nested `if`; British spelling in prose; Playwright/GUI tests in
  nspawn containers only.

---

## How to verify

```bash
cargo test  -p hardener-cli              # 79 unit tests
cargo clippy -p hardener-cli --all-targets
cargo fmt --check
cargo build --workspace                  # incl. the desktop bin
hardener batch report --ssh nobody@127.0.0.1:1 --framework cis --format json; echo $?   # failed host, exit 2
```
All clean at handoff; full `cargo test --workspace` 0 failed.

---

## Remaining work (priority order, from NEXT.md)

1. **`batch apply`** — see the launchpad above. *Start here, brainstorm first.*
2. Desktop multi-host view (largest GUI effort).
3. **Trivial doc nit (background task flagged):** single-host `report --help`
   `--framework` doc (`crates/hardener-cli/src/cli.rs` ~line 109) omits
   `iso27001`; both commands parse it fine via the shared `parse_framework`. 1-word
   fix.
4. Debug-vs-Display history serialisation (`finding_to_scan_finding` writes
   `severity`/`category` via `{:?}` not `Display`; pre-existing, cosmetic;
   trends/regressions read the numeric `*_count` columns so they're unaffected).
5. RHEL 10 / per-version compliance profiles; cross-distro re-validation (needs
   containers + root, human-run).
6. More frameworks (SOC 2 / FedRAMP / NIST 800-171); deeper HIPAA/GDPR review.
7. Version cut for the accumulated `[Unreleased]` changelog; external security audit.

---

## Git state at handoff

- `main` at `9e9ddaa`, **9 commits ahead of `origin/main`, push pending** (user
  pushes — SSH passphrases). One `git push origin main` reaches both GitHub and
  GitLab (dual push URL). The pre-*push* gate runs fmt/clippy/cargo-audit; fix the
  report or `git push --no-verify`, never disable `core.hooksPath`.
- Branch `feat/batch-report` was FF-merged and deleted. Working tree clean apart
  from untracked `.rust-sec-ci.toml` and `docs/superpowers/`.
