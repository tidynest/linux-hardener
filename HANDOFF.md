# Session Handoff — 2026-06-28 (Fleet Apply GUI shipped + full doc-currency sweep → next: doc debt + GUI polish)

> **Read this first.** Point-in-time handoff for the next development session.
> Living task list is [NEXT.md](NEXT.md); roadmap is [ROADMAP.md](ROADMAP.md);
> data-flow source of truth is [docs/DATA_FLOW.md](docs/DATA_FLOW.md).
> Project is **v1.1.0**. `main` is fully pushed.

---

## TL;DR

- **Shipped this session (two things):**
  1. **Desktop Fleet Apply page** — first remote *mutation* in the GUI: apply and
     roll back hardening across saved hosts over SSH. It **shells out** to the
     audited `hardener batch apply`/`rollback --format json` (no pkexec — remote
     uses SSH creds), parses the per-host `ApplyOutcome`/`RollbackOutcome` JSON
     **exit-code-agnostically**, and gates Execute behind a **mandatory dry-run +
     confirm modal**.
  2. **Full living-doc currency sweep** — audited every living doc; corrected 13
     for stale feature-status (see "What shipped" below). The point-in-time
     snapshot docs were deliberately left and are itemised under **Remaining work
     A** so the next session can finish them.
- **Git state:** `main` == `origin` (GitHub) == GitLab == **`9613a52`** — fully
  pushed to both remotes (`tidynest`, dual push URL → one `git push origin main`
  hits both). Working tree clean.
- **Verification:** `cargo fmt --check` + `clippy --workspace --all-targets
  -D warnings` + `build --workspace` + `test --workspace` **648 passed / 0 failed
  / 38 ignored** — all clean (at the Fleet Apply merge; doc commits since are
  text-only).
- **Start here next:** pick from **Remaining work** below. Two buckets — (A)
  documentation debt deferred from the sweep, (B) the feature backlog. Both are
  independent; A's items are mostly deliberate/human-run passes, B's are
  brainstorm→spec→plan feature slices.

---

## What shipped this session

**1. Fleet Apply page** (architecture — Approach B, "the GUI never reimplements
mutation"):
- **Tauri commands** (`src-tauri/src/commands.rs`): `run_fleet_apply` /
  `run_fleet_rollback` (thin wrappers over a private generic `run_fleet_mutation<T>`)
  + `list_plugins`. `run_fleet_mutation` validates inputs (`validate_ipc_string`
  per host, `validate_plugin_ids` allowlist per plugin, empty-hosts guard), builds
  args via `build_batch_args`, spawns via `tokio::process::Command` (no pkexec),
  parses via `parse_outcomes` **without checking the exit code**.
- **Shared types** moved to `hardener-types` (+`Deserialize`): `ApplyOutcome` /
  `ApplyStatus` / `RollbackOutcome` / `RollbackStatus`; CLI re-exports them.
- **Page** `crates/hardener-ui/src/pages/fleet_apply_page.rs` (route `/fleet-apply`):
  mode toggle, host + plugin multiselect (empty = all), mandatory-dry-run gate
  (`selection_key`/`previewed_key`/`can_execute`/`invalidate`, reset after execute),
  confirm modal, results.
- Spec/plan (gitignored): `docs/superpowers/specs/2026-06-28-fleet-apply-rollback-gui-design.md`,
  `docs/superpowers/plans/2026-06-28-fleet-apply-rollback-gui.md`. Built
  brainstorm→spec→plan→subagent-driven (6 tasks, 2-stage review each + opus final).
  7 feature commits `e8aec2b..9a5e1bf` FF-merged, branch deleted.

**2. Doc-currency sweep** — corrected (all pushed): SECURITY.md (removed two FALSE
"Known Limitations" — SSH crypto + multi-framework compliance are both done),
GUI_CLI_PARITY_PLAN + SSH_REMOTE_SCANNING (dropped "fleet apply/compliance columns
are CLI-only" claims), ARCHITECTURE (6→7 pages, +ISO 27001, executor now in
`hardener-common`), cli.md (added the whole `batch` section + `history
trends`/`regressions` + `iso27001`), CONTRIBUTING/testing.md/REMEDIATION_TRACKER
(framework list, test counts 505/428→648), README/FILE_MAP/ROADMAP/HANDOFF.
Audited-current (no change): CONFIG_DESIGN, THEME_DESIGN_GUIDE, INSTALL,
building/releasing/documentation.md, scripts/README, NAMING_CONVENTIONS.

---

## Remaining work — A. Documentation debt (deferred from the sweep)

These were deliberately left; each needs a deliberate or human-run pass, not a
quick edit:

1. **`docs/audit/**`** — ✅ **Resolved 2026-06-28: retired.** Decision was
   regenerate-vs-retire; regenerate proved a phantom option (no generator ever
   existed — the auto-update tooling only fixes dates/FILE_MAP/version/compliance
   counts, it never produced this corpus). It was a stale per-file *mirror* of
   source (purpose/submodules/public-interface tables), superseded by the code
   itself + `cargo doc`, and already missing all post-Feb work. `git rm -r
   docs/audit/` (141 files). Its only still-live signal — 3 open deferred-cleanup
   flags — was salvaged into [NEXT.md](NEXT.md) (§"P3 — Deferred code cleanups");
   dangling refs in FILE_MAP/NEXT fixed.
2. **`docs/DISTRIBUTION_VALIDATION.md`** — body still records "v0.3.3 binary".
   Needs a real **v1.1.0 cross-distro re-validation**: arch, debian, fedora, rhel,
   openSUSE **Leap 16** (15.x reached EOL April 2026). Human-run (nspawn containers
   + root); the doc's own header already flags this.
3. **`docs/security-audit/REMEDIATION_TRACKER.md`** — Section 4 (defence-in-depth)
   SAM table lacks per-SAM "Fixed" status. The resolved SAMs are enumerated in
   `docs/plans/remaining-work.md` §2 (SAM-020 / 061 / 062 / 063 / 069 / 070 / 074 /
   076). Needs a deliberate security reconciliation pass — don't guess statuses.
   (Test-count `428→648` already fixed.)

---

## Remaining work — B. Feature backlog (from NEXT.md / ROADMAP)

1. **Multi-host GUI polish** (each its own small brainstorm): ad-hoc
   `--ssh user@host` hosts in the Fleet / Fleet-Apply pages (today both only use
   saved inventory hosts); **live per-host progress** (today results appear
   batch-after-all — would need Tauri events/streaming, the deferred Approach-C
   path noted in the Fleet Apply spec); **per-host history surfaced in the GUI**
   (the CLI persists it; the desktop doesn't show it yet).
2. **New frameworks:** SOC 2 / FedRAMP / NIST 800-171 (additive — follows the
   existing plugin-declared-coverage pattern).
3. **RHEL 10 / per-version compliance profiles** (DISA RHEL 10 STIG V1R1, CIS
   RHEL 10 v1.0.1 exist). Likely overlaps the generic frameworks + family detection.
4. **Debug-vs-Display history serialisation** (`finding_to_scan_finding` writes
   severity/category via `{:?}`) — pre-existing, cosmetic; needs a one-time
   decision on existing rows.
5. **External security audit**; version cut for the accumulated `[Unreleased]`
   changelog.

---

## Invariants & gotchas (do not break)

- **Mutation only ever happens inside the audited CLI.** The GUI builds args +
  parses JSON; it never reimplements apply/rollback/checkpoint logic.
- **Exit-code-agnostic parse** — `run_fleet_mutation` must NOT gate on
  `output.status.success()` (`batch apply/rollback` exit non-zero on per-host
  failures yet emit valid JSON).
- **No pkexec for remote** — remote privilege is the SSH user's; pkexec stays for
  local-host mutation only. Saved-profile auth (`~/.config/linux-hardener/hosts.toml`).
- **`hardener-cli` is a BIN** → `cargo test -p hardener-cli` (NOT `--lib`).
- **`#[cfg(test)] mod` must be the LAST item in a file** — a test module before
  other items trips clippy `items_after_test_module` under the `-D warnings` gate.
- **`docs/superpowers/` + `.rust-sec-ci.toml` are GITIGNORED.**
- Pre-commit gate = naming validation (0 errors; ~98 pre-existing warnings fine).
  Pre-push gate `rust-sec-ci` = clippy `-D warnings` + fmt + audit. Run
  `cargo clippy --workspace --all-targets -- -D warnings` + `cargo build --workspace`
  (catches the desktop bin) before claiming done.
- **CSS/markup only ships after `trunk build`** — `cargo build` uses the committed
  `crates/hardener-ui/dist`.
- **Push is the user's** (SSH passphrases; assistant cannot). Dual push URL.
- Conventions: no AI attribution; `cargo fmt` before commits; Rust let-chains never
  nested `if`; British spelling in prose.

---

## How to verify

```bash
cargo test --workspace                       # 648 passed, 0 failed, 38 ignored
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build --workspace                      # incl. the desktop bin
```

---

## Git state at handoff

- `main` == `origin/main` == GitLab == **`9613a52`** — fully pushed, nothing
  outstanding. Working tree clean. No open feature branches from this work.
