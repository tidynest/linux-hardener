# Session Handoff — 2026-06-28 (desktop Fleet Apply shipped → remaining = GUI polish slices)

> **Read this first.** Point-in-time handoff for the next development session.
> Living task list is [NEXT.md](NEXT.md); roadmap is [ROADMAP.md](ROADMAP.md);
> data-flow source of truth is [docs/DATA_FLOW.md](docs/DATA_FLOW.md).
> Project is **v1.1.0** with accumulated work under CHANGELOG `[Unreleased]`.

---

## TL;DR

- **Shipped + PUSHED since the last handoff (two slices):**
  1. **Desktop fleet compliance-score columns** — the read-only Fleet *scan* view
     now shows a colour-coded CIS score per host plus an all-6-framework breakdown
     in the row expander. Derived in-process from the already-scanned findings (no
     extra SSH). New shared `FleetFrameworkPosture` type.
  2. **Desktop Fleet Apply page** — the first remote *mutation* in the GUI: apply
     and roll back hardening across saved hosts. It **shells out** to the audited
     `hardener batch apply`/`rollback --format json` (no pkexec — remote uses SSH
     creds; mirrors the non-pkexec `run_apply_dry_run` spawn), parses the per-host
     `ApplyOutcome`/`RollbackOutcome` JSON **exit-code-agnostically** (the batch CLI
     exits non-zero on per-host failures yet still emits valid JSON), and gates
     Execute behind a **mandatory dry-run + confirm modal**.
- **Git state:** `main` == `origin` (GitHub) == GitLab == **`9a5e1bf`** — fully
  pushed to both remotes (`tidynest`, dual push URL → one `git push origin main`
  hits both). Working tree clean.
- **Verification at handoff:** `cargo fmt --check` + `clippy --workspace
  --all-targets -D warnings` + `build --workspace` + `test --workspace`
  **648 passed / 0 failed / 38 ignored** — all clean.
- **Start here next:** remaining desktop-fleet GUI polish slices (each its own
  small brainstorm): **ad-hoc `--ssh user@host` hosts** in the Fleet/Fleet-Apply
  pages (today both only use saved inventory hosts), **live per-host progress**
  (today results appear batch-after-all; would need Tauri events/streaming, the
  deferred Approach-C path), **per-host history from the GUI** (the CLI persists
  history; surface it in the desktop). Then the non-GUI backlog (below).

---

## What shipped — Fleet Apply page (architecture)

**Approach B — the GUI never reimplements mutation.** The CLI's `batch
apply`/`rollback` logic lives in the CLI **bin** and calls `std::process::exit`,
so it cannot be linked in-process. The GUI therefore spawns the `hardener` binary
and parses its JSON.

- **Tauri commands** (`src-tauri/src/commands.rs`): `run_fleet_apply` /
  `run_fleet_rollback` (thin wrappers over a private generic `run_fleet_mutation<T>`)
  + `list_plugins` (for the plugin selector). `run_fleet_mutation` validates inputs
  (`validate_ipc_string` per host, `validate_plugin_ids` allowlist per plugin,
  empty-hosts guard), builds args via `build_batch_args`, spawns via
  `tokio::process::Command` (no pkexec), and parses via `parse_outcomes` **without
  checking the exit code**.
- **Shared types** (`hardener-types`): `ApplyOutcome`/`ApplyStatus`/`RollbackOutcome`/
  `RollbackStatus` were moved here from the CLI bin (+`Deserialize`); the CLI
  re-exports them, so its `Serialize` JSON output is byte-identical and the GUI can
  parse it.
- **Page** (`crates/hardener-ui/src/pages/fleet_apply_page.rs`): mode toggle
  (apply | roll back), host + plugin multiselect (empty plugins = all), the
  mandatory-dry-run gate (`selection_key`/`previewed_key`/`can_execute`/`invalidate`
  — Execute is enabled only for the exact selection that was previewed, and the
  gate resets after an execute), confirm modal, results. Route `/fleet-apply`.

**Process:** brainstorm → spec → plan → subagent-driven (6 tasks, spec + code-quality
review each, + opus final whole-feature review = READY TO MERGE). Spec/plan
(gitignored): `docs/superpowers/specs/2026-06-28-fleet-apply-rollback-gui-design.md`,
`docs/superpowers/plans/2026-06-28-fleet-apply-rollback-gui.md`. 7 feature commits
`e8aec2b..9a5e1bf` FF-merged to `main`, branch deleted.

**Deferred ceilings (in the spec, intentionally not built):** live per-host
progress streaming; ad-hoc `--ssh` hosts in the GUI; a pre-execute privilege probe
surfaced in the preview (the CLI's privilege probe is execute-only, so a host that
connects but lacks root/sudo surfaces as `Failed` only in execute results, not the
dry-run preview); typed-phrase confirmation.

---

## Invariants & gotchas (do not break)

- **Mutation only ever happens inside the audited CLI.** The GUI builds args +
  parses JSON; it never reimplements apply/rollback/checkpoint logic.
- **Exit-code-agnostic parse.** `run_fleet_mutation` must NOT gate on
  `output.status.success()` — `batch apply/rollback` exit non-zero on per-host
  failures yet emit valid JSON; the array is the source of truth.
- **No pkexec for remote.** Remote privilege is the SSH user's (probed by the CLI);
  pkexec stays for local-host mutation only.
- **Saved-profile auth.** Fleet commands pass only host names; the CLI resolves
  `~/.config/linux-hardener/hosts.toml` (shared inventory, CLI + GUI).
- **`hardener-cli` is a BIN, not a lib** → `cargo test -p hardener-cli` (NOT `--lib`).
- **`#[cfg(test)] mod` must be the LAST item in a file** — a test module before
  other items trips clippy `items_after_test_module` under the `-D warnings` gate.
- **`docs/superpowers/` + `.rust-sec-ci.toml` are GITIGNORED.**
- **Pre-commit gate** = naming validation (0 errors; ~98 pre-existing warnings are
  fine). **Pre-push gate `rust-sec-ci`** = clippy `-D warnings` + fmt + audit. Run
  `cargo clippy --workspace --all-targets -- -D warnings` + `cargo build --workspace`
  (catches the desktop bin) before claiming done.
- **CSS/markup only ships after `trunk build`** — `cargo build` uses the committed
  `crates/hardener-ui/dist`, so the new page renders only after a frontend rebuild
  at bundle time.
- **Push is the user's** (SSH passphrases; assistant cannot). Dual push URL.
- Conventions: no AI attribution; `cargo fmt` before commits; Rust let-chains never
  nested `if`; British spelling in prose.

---

## Remaining work (priority order, from NEXT.md)

1. **Desktop-fleet GUI polish:** ad-hoc `--ssh` hosts; live per-host progress;
   per-host history from the GUI. (Fleet scan, compliance columns, and
   apply/rollback are all DONE.)
2. New frameworks: SOC 2 / FedRAMP / NIST 800-171 (additive, follows the existing
   plugin-coverage pattern).
3. RHEL 10 / per-version compliance profiles; cross-distro re-validation (needs
   containers + root, human-run).
4. Debug-vs-Display history serialisation (`finding_to_scan_finding` writes
   severity/category via `{:?}`) — pre-existing, cosmetic.
5. External security audit; version cut for the accumulated `[Unreleased]` changelog.

---

## How to verify

```bash
cargo test --workspace                       # 648 passed, 0 failed, 38 ignored
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build --workspace                      # incl. the desktop bin
```
All clean at handoff. (The Fleet Apply page's full GUI behaviour is verified in an
nspawn container, per the Playwright-in-container rule; the `selection_key` gate
logic has a host-runnable unit test.)

---

## Git state at handoff

- `main` == `origin/main` == GitLab == **`9a5e1bf`** — fully pushed, nothing
  outstanding. Working tree clean. No open feature branches from this work
  (`feat/fleet-apply-rollback-gui` was FF-merged and deleted).
