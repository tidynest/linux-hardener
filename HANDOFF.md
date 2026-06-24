# Session Handoff — 2026-06-24 (desktop fleet view shipped → remaining multi-host slices next)

> **Read this first.** Point-in-time handoff for the next development session and
> assistant. Living task list is [NEXT.md](NEXT.md); roadmap is [ROADMAP.md](ROADMAP.md).
> Project is **v1.0.5** with a large backlog under CHANGELOG `[Unreleased]` — a
> version cut is a reasonable near-term housekeeping step.

---

## TL;DR

- **Shipped + PUSHED this session:** *remote-correct checkpoints* — checkpoint
  capture **and** restore now run through the `SystemExecutor`, so a remote
  `--ssh apply` + `rollback` snapshots/restores the **remote** host. This fixed a
  latent bug (rollback was restoring the **controller**, never the remote target).
  Checkpoints are host-keyed; rollback refuses cross-host restore. 9 commits,
  `main` == `origin` == `4d5c6e6` on **both** remotes (github + gitlab `tidynest`).
- **Shipped this session (latest):** `hardener batch apply` — apply hardening
  across a fleet concurrently. **Dry-run default; `--execute` mutates.** Per-host
  privilege probe (uid 0 or passwordless sudo) gates execute only + isolates a
  non-privileged host; auto host-keyed checkpoints per host; per-host best-effort
  audit; tiered exit (0/1/2). Built on a generalized engine (`run_on_all<T>`) and
  a shared `apply_host` extracted from single-host `apply::run`. 13 commits
  `0fc9f16..1721760`, FF-merged to `main`, branch deleted. **PUSHED 2026-06-23**
  to both remotes (github + gitlab `tidynest`); `main` == `origin` == `00b60c2`.
- **Shipped this session (latest):** `hardener batch rollback` — roll back a fleet
  concurrently to each host's latest per-plugin checkpoint. **Dry-run default;
  `--execute` restores.** Same per-host privilege probe + isolation as `batch
  apply`; restores reuse host-keyed checkpoints (cross-host restore refused);
  best-effort per-host audit; tiered exit (0/1/2). Built brainstorm→spec→plan,
  implemented directly from the plan's exact code, then gated behind an
  **independent whole-feature review** which caught one CRITICAL: the services
  plugin's id (`service-minimisation`) did not match its checkpoint name
  (`services-hardening-pre-apply`), so rollback was a **silent no-op for services**
  (false success). Fixed by aligning to the universal `{plugin_id}-pre-apply`
  convention + a writer-contract doc + a registry-wide regression test. 5 commits
  `23cb59a..113f13b`, FF-merged to `main`, branch deleted. **PUSHED 2026-06-24**
  to both remotes (github + gitlab `tidynest`); tip is now `b5e59d6`, **CI green**.
  Full `cargo test --workspace` 637 passed; clippy `-D warnings` + fmt clean.
  **Post-merge fmt follow-up (`b5e59d6`):** the post-review services rename
  (`service-minimisation-pre-apply`) crossed 100 cols; per-crate `cargo fmt` had
  run but not a final `cargo fmt --all`, so CI's `fmt --check` caught it. Lesson:
  run `cargo fmt --all` + `cargo clippy --workspace` before the final push — the
  local pre-commit gate validates naming only, not fmt/clippy.
- **Shipped this session (latest):** *desktop fleet view* — a read-only **Fleet**
  GUI page that scans several saved inventory hosts concurrently and shows each
  host's severity posture (per-host crit/high/med/low/info tallies, expandable to
  findings). Built in-process by reusing the single-host scan path
  (`scan_with_executor` extracted from `run_remote_scan`; generic bounded-concurrent
  `scan_fleet`; `run_fleet_scan` Tauri command). Read-only is **structural** (scan
  takes `&Context`; the fleet context carries no checkpoint/audit). 8 commits
  `ea0161c..e356bae`, FF-merged to `main`, branch deleted. Opus whole-feature review
  = READY TO MERGE; full workspace test/clippy/fmt/build green. Fleet apply/rollback
  + compliance-score columns deferred (CLI-only). Spec/plan (gitignored):
  `docs/superpowers/specs/2026-06-24-desktop-fleet-view-design.md`,
  `docs/superpowers/plans/2026-06-24-desktop-fleet-view.md`.
- **Also shipped:** version cut **1.1.0** (`5ef150c`) — the `[Unreleased]` changelog
  folded into `[1.1.0] - 2026-06-24`; workspace + tauri + doc version strings bumped,
  lockfile synced. Tag + push left to you (release boundary).
- **Start here next:** remaining multi-host slices — fleet **apply/rollback** in the
  GUI (own brainstorm; mutation in a GUI is a different risk class), compliance-score
  columns on the fleet view, ad-hoc `--ssh` hosts, live per-host progress, per-host
  history persistence from the GUI. (The read-only fleet *scan* view is now DONE.)
- **Why batch apply came after the checkpoint fix:** brainstorming `batch apply`
  surfaced the checkpoint bug. Per the user's "max safety" call, the foundation
  was fixed first so `batch apply` builds on correct, host-keyed rollback.

---

## What shipped — remote-correct checkpoints

**The bug:** `hardener-state::CheckpointManager` captured/restored via `std::fs`
(the **controller's** filesystem), while apply runs over an
`Arc<dyn SystemExecutor>` that may be an `SshExecutor` (the **remote** host). So
single-host `--ssh apply` + `rollback` snapshotted and restored the wrong
machine — remote rollback was a silent no-op. Uncaught because every apply/
rollback test runs the binary *inside* a container (executor and checkpoint = the
same box).

**The fix (architecture):**
- The executor abstraction (`SystemExecutor` + `FileMetadata` + `CommandOutput` +
  `MockExecutor`) moved from `hardener-core` to **`hardener-common`**, re-exported
  from `core` (broke a `core → state` cycle so `state` can reference the trait).
  `LocalExecutor`/`SshExecutor` stay in `core`.
- Trait gained `read_dir`; `FileMetadata` gained `uid`/`gid` (ssh extends
  `stat -c '%F %a %s %u %g'`).
- `CheckpointManager` capture/restore are now async and go through the executor
  (`read_file`/`write_file`/`file_metadata`/`read_dir`/`chmod`/`chown`/`rm`).
  Signing/digest and the `FileState` shape are **unchanged** (signatures verify).
- `host_key` column on `checkpoints` + idempotent in-place migration;
  `host_key_for(executor)` (in `hardener-common`) is the **single source of
  truth** for the key — used by capture, rollback, and the CLI.
- Cross-host guard: `rollback` refuses when `checkpoint.host_key != host_key_for(executor)`.

| Commits (FF-merged, branch deleted) | |
|---|---|
| `f4ba39e` | relocate executor abstraction → `hardener-common` |
| `ee9813e` | `read_dir` + `FileMetadata` `uid`/`gid` |
| `edf2202` | `host_key` column + migration |
| `599d524` | executor-aware capture + host_key |
| `e62f8b2` | executor-aware restore + cross-host guard |
| `4a3638f` | thread executor into call sites + CLI |
| `b33ab4b` | `#[ignore]` remote apply→rollback test |
| `14f30df` | docs |
| `4d5c6e6` | review polish (single-home `host_key_for`; ceiling comment) |

Spec/plan (gitignored): `docs/superpowers/specs/2026-06-22-remote-correct-checkpoints-design.md`,
`docs/superpowers/plans/2026-06-22-remote-correct-checkpoints.md`.

**Verification gap (deliberate):** the red→green proof
`remote_apply_then_rollback_restores_remote_file`
(`crates/hardener-plugins/tests/ssh_integration_tests.rs`) is `#[ignore]` — it
needs a **booted** container as an SSH target. Containers exist at
`/var/lib/machines/hardener-test{,-debian,-fedora,-rhel,-opensuse}` (sshd +
`root:test`) but run via `--pipe` (no IP). Boot one with networking, then:
```
SSH_TEST_HOST=<ip> SSH_TEST_USER=root SSH_TEST_PASSWORD=test \
  cargo test -p hardener-plugins --test ssh_integration_tests -- --ignored remote_apply_then_rollback
```

---

## ▶ Launchpad: `hardener batch apply` (next slice)

**Goal:** apply hardening to many remote hosts in one concurrent run. The
**dangerous** batch command — it earns a full brainstorm → spec → plan →
subagent-driven cycle. Do not shortcut it.

### What already exists (reuse, don't rebuild)
- **Single-host remote apply works AND now has correct rollback.**
  `commands/apply.rs::run(...)` runs `plugin.apply`/`plugin.validate` over any
  executor; `main.rs` builds an `SshExecutor` from `--ssh`. After this slice, the
  per-host checkpoint/rollback that apply creates targets the **remote** host and
  is **host-keyed** — that was the missing foundation.
- **The batch concurrency engine.** `commands/batch.rs`: `resolve_hosts` /
  `parse_inline`, `scan_one` / `scan_with_executor`, `scan_all` (bounded
  concurrency, input-order preserved, failure-isolated), `HostOutcome`,
  `resolve_and_scan`. The host-iteration is fully reusable; only the per-host
  *operation* (scan vs apply) differs.
- **Inventory + flags** (`--all` / `--host` / `--ssh` / `--concurrency` /
  `--output`, global `--format` / `--ssh-key` / `--ssh-timeout` /
  `--ssh-no-verify`) are parsed and threaded — mirror the `BatchAction::Scan/Report`
  variants + dispatch arm.

### The open problems (the brainstorm must resolve these) — NARROWED
Per-host checkpoint/rollback is **no longer open** (this slice solved it). What
remains:
1. **Privilege model.** `apply.rs:23` gates on **local** `geteuid().is_root()` —
   wrong for a remote target (root is needed on the **remote** host, as the ssh
   user). Decide deliberately: drop the local-euid gate for remote and rely on
   the remote user's privileges (remote ops fail if unprivileged), or precheck
   per host. **Related ceiling from this slice:** remote restore's
   `chmod`/`chown`/`rm` run **without** `sudo` (only `write_file` uses
   `sudo tee`), so non-root remote restore degrades to content-only (see the
   `ponytail:` comment in `restore_file_state_tracked`). The privilege model
   should cover remote-root for the whole apply+rollback path.
2. **Blast-radius UX.** Make `--dry-run` (validate-only) the **default**; real
   application behind an explicit opt-in (`--apply` / `--confirm`). A typo must
   not harden 50 production boxes.
3. **Failure policy & exit codes.** Per-host isolation like `batch scan` (a failed
   host is a row, never aborts the fleet) + tiered exit. Partial apply is
   non-atomic (host A succeeds, B fails → A stays changed) — document it.
4. **History/audit.** `batch scan`/`report` persist each host's scan best-effort.
   Decide whether `batch apply` records apply actions to history/audit per host
   (the single-host path already writes the **local** audit log).

### Suggested first move
`/ponytail` → brainstorm. Decomposition is mostly settled (apply over the existing
batch engine + the now-correct checkpoint foundation); the brainstorm's real work
is items 1–2 (privilege model + dry-run-default UX). Keep `batch apply` its own
sub-project; don't fold the desktop multi-host view into it.

---

## Invariants & gotchas (do not break)

- **Checkpoint capture/restore go through the executor** — never `std::fs` for
  file content. The only local `std::fs` in the restore path is the symlink
  allowlist guard (local-only by design).
- **`host_key_for(executor)` is the single source of the host key** — don't
  re-inline `is_remote() ? description() : "local"`. The cross-host rollback guard
  depends on it never drifting.
- **Signing/digest + `FileState` shape are frozen** — changing them breaks
  signature verification of existing checkpoints.
- **Executor abstraction lives in `hardener-common`**, re-exported from
  `hardener-core`. `hardener-state` may depend on `common` but NOT `core` (cycle).
- **`batch report`/`scan` are READ-ONLY.** Only `batch apply` may mutate — behind
  the blast-radius gate decided in its brainstorm.
- **Best-effort persistence** never changes a host's outcome or the exit code.
- **`hardener-cli` is a binary, not a lib:** `cargo test -p hardener-cli` (NOT `--lib`).
- **Pre-commit gate** = naming validation (0 errors; pre-existing warnings fine).
  **Pre-push gate (`rust-sec-ci`)** runs `cargo clippy -- -D warnings` + fmt +
  audit — a `tests` module before non-test items (`items_after_test_module`) or a
  stray lint will reject the push. Run `cargo clippy --workspace --all-targets -- -D warnings`
  before claiming done. Fix the report or `git push --no-verify`; never disable
  `core.hooksPath`.
- **`docs/superpowers/` and `.rust-sec-ci.toml` are GITIGNORED** (changed since
  older notes) — `git add -A` no longer risks staging specs/plans.
- **`cargo build --workspace`** catches what per-crate misses (desktop bin). Run
  it before claiming done.
- **Conventions:** no AI attribution anywhere; `cargo fmt` before commits; Rust
  let-chains, never nested `if`; British spelling in prose; Playwright/GUI tests
  in nspawn containers only.

---

## How to verify

```bash
cargo test --workspace                       # 622 passed, 0 failed, 38 ignored
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build --workspace                      # incl. the desktop bin
# remote proof (needs a booted container as SSH target):
SSH_TEST_HOST=<ip> SSH_TEST_USER=root SSH_TEST_PASSWORD=test \
  cargo test -p hardener-plugins --test ssh_integration_tests -- --ignored remote_apply_then_rollback
```
All clean at handoff (the remote test is the one host-dependent step).

---

## Remaining work (priority order, from NEXT.md)

1. **`batch apply`** — see the launchpad above. *Start here, brainstorm first.*
2. Desktop multi-host view (largest GUI effort).
3. ~~Trivial doc nit: `report --help` `--framework` omits `iso27001`.~~
   **Resolved/verified 2026-06-24** — `cli.rs:109` already lists `iso27001`, and the
   string matches `parse_framework` exactly. No change needed; close the background task.
4. Debug-vs-Display history serialisation (`finding_to_scan_finding` writes
   severity/category via `{:?}`; pre-existing, cosmetic).
5. RHEL 10 / per-version compliance profiles; cross-distro re-validation
   (needs containers + root, human-run).
6. More frameworks (SOC 2 / FedRAMP / NIST 800-171); deeper HIPAA/GDPR review.
7. Version cut for the accumulated `[Unreleased]` changelog; external security audit.

---

## Git state at handoff

- `main` == `e356bae`, **10 commits ahead of `origin/main` (`b5e59d6`)** — UNPUSHED.
  Stack = handoff doc (`fd67ef6`) + version cut 1.1.0 (`5ef150c`) + 8 fleet-view
  commits (`ea0161c..e356bae`). Push is yours (SSH passphrase): one
  `git push origin main` hits both GitHub + GitLab (`tidynest`, dual push URL).
- Branch `feat/desktop-fleet-view` was FF-merged and deleted. Working tree clean
  except a stray untracked `librust_out.rlib` at repo root (pre-existing build
  artifact — `rm` it or gitignore; unrelated to this work). `docs/superpowers/` +
  `.rust-sec-ci.toml` remain gitignored.
