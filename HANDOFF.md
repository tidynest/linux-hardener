# Session Handoff — 2026-06-28 (v1.1.0 cross-distro re-validated → next: container rebuilds + a meticulous test-coverage sweep)

> **Read this first.** Point-in-time handoff for the next development session.
> Living task list is [NEXT.md](NEXT.md); roadmap is [ROADMAP.md](ROADMAP.md);
> data-flow source of truth is [docs/DATA_FLOW.md](docs/DATA_FLOW.md).
> Project is **v1.2.0** (released to GitHub, GitLab, and AUR on 2026-07-01). `main` is pushed and in sync with both remotes.

---

## TL;DR

- **Shipped this session (5 commits, `ec135ae` → `a7b62bb`, all on `main`, NOT pushed):**
  1. **Retired `docs/audit/**`** — 141 stale Feb per-file mirror docs (no generator,
     superseded by source + `cargo doc`); salvaged 3 live deferred flags into NEXT.
  2. **Reconciled the security tracker** — `REMEDIATION_TRACKER.md` §4 now has a real
     **Status** column (20 Fixed, 1 Deferred); code-verified **SAM-039** is genuinely
     undone (per-command Tauri capability ACLs) and marked Deferred, not Fixed.
  3. **README overhaul** — desktop **screenshots** (Dashboard/Analysis/Hardening,
     captured from a freshly-built v1.1.0 app), flat-square **badges**, collapsible
     **TOC**, **roadmap fold**, and currency fixes (660 tests, 7 frameworks, 7 pages).
  4. **Cross-distro v1.1.0 re-validation** — ran the full CLI suite under
     `nspawn --pipe` across all 5 containers; **found + fixed** stale `daemon status`
     test/doc drift (CLI renamed positional count → `--limit`); **confirmed** by a
     second run (Debian + Rocky 123/123, all daemon tests green). Updated
     `DISTRIBUTION_VALIDATION.md` honestly (no fabricated 123/123).
  5. **Diagnosed the residual flake** — intermittent JSON-grep failure in
     `run_test_output`; product verified correct. **Since root-caused + fixed**
     (uncommitted) → the `sed` ANSI-strip aborted under openSUSE's minimal locale;
     dropped it, `grep -a` on the file. Suite now **125/125 × 5**. See P2 below.
- **The next session has two TOP priorities** (below): **(1) container rebuilds**
  for the distro-version refresh, and **(2) a meticulous, first-class test-coverage
  sweep** — the scripts predate compliance frameworks, batch CLI, fleet pages, SSH
  crypto, and remote checkpoints, and have large, confirmed gaps.
- **Push is the user's** (SSH passphrase; dual push URL → GitHub + GitLab).

---

## TOP PRIORITY 1 — Container rebuilds (distro-version refresh)

The 2026-06-28 re-validation ran on the **February container set** (Arch rolling,
Debian 12, Fedora 41, Rocky 9, openSUSE **Leap 15.6**). The v1.1.0 *binary* is
validated, but the **distro versions are stale** — and openSUSE Leap 15.x reached
**EOL April 2026**. Recreate the containers on current releases, then re-run.

**Targets:** Debian **13 "Trixie"**, Fedora **44**, RHEL family via Rocky/Alma **10**
(or keep Rocky 9 + add 10), openSUSE **Leap 16**, Arch (rolling — recreate to refresh).
Ubuntu 26.04 is covered by the Debian family but consider an explicit container.

**How:** the creation scripts already exist — `scripts/create-{debian,fedora,rhel,opensuse}-container.sh`
and `scripts/create-test-container.sh` (Arch). They need their pinned release/repo
URLs bumped to the targets above (e.g. openSUSE 15.6 → 16; Debian bookworm → trixie;
Fedora 41 → 44; Rocky 9 → 10). This is **root + network + bootstrap heavy** (pacstrap
/ debootstrap / dnf / zypper / podman export) — schedule it deliberately, watch CPU/heat.

**Then re-validate (the binary build is fast; containers are the slow part):**
```bash
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
sudo ./scripts/run-cross-distro-tests.sh --apply          # CLI suite
sudo ./scripts/run-cross-distro-tests.sh --gui            # GUI/Playwright (separate, heavier)
```
Update the **container set / version columns** in `docs/DISTRIBUTION_VALIDATION.md`
(Summary, Container Setup table, per-distro sections, GUI summary) to the new releases.

> ⚠️ **sudo gotcha:** the assistant cannot elevate (no tty + Arch's tty-scoped sudo).
> The privileged commands above must be **run by the user**; the assistant prepares,
> parses `test-results/summary.txt` + logs, and updates the docs.

---

## TOP PRIORITY 2 — Meticulous test-coverage sweep (make every suite first-class)

The test scripts were written **before** much of today's feature surface existed.
A coverage audit this session found **large, confirmed gaps**. Treat this as a
first-class engineering pass: audit **every** suite/script against the **current**
feature set, then fill the gaps with high-quality tests. Nothing half-measured.

### Confirmed gaps (starting points — not exhaustive; audit for more)

> **AUDIT (2026-06-28): most unit-test "gaps" below are ALREADY COVERED — this
> list was written pessimistically.** Verified present, do NOT re-write:
> `select_algorithms` (2 tests, `ssh_mock_tests.rs`), `find_regressions`
> (`history.rs`), `compliance_coverage` (`lib.rs`),
> `validate_ipc_string`/`validate_plugin_ids` (~40 tests, `validation.rs`),
> `build_batch_args` + `parse_outcomes` (`commands.rs` test mod), ISO 27001
> (`compliance/tests/framework_tests.rs`), **Compliance Option-B honesty**
> (`compliance/tests/assessment_honesty.rs` — unassessed→ManualReview, assessed→
> Pass/Fail). The Tauri-layer *"no tests dir exists"* claim is **false**.
> **Genuinely absent + assistant-relevant:** the bash suite has **no `batch`
> nor `history trends`/`regressions`** cases, and the 4 fleet/remote/scheduler
> **GUI specs** are unwritten. Both need multi-host fixtures, container runs, or
> design decisions — not autonomously verifiable on this host (suite needs root;
> GUI needs nspawn). Remote-checkpoint + `#[ignore]` root-SSH integration tests
> not re-audited this pass.

**`scripts/full-test-suite.sh` (the 127-test CLI suite, per container):**
- ✅ **ISO/IEC 27001:2022** — added `iso27001` to `FRAMEWORKS` (now 7); passes on all 5 distros. (`validate_compliance_docs.py` counts frameworks dynamically — no hardcoded total to update.) Suite grew 123 → 125 (→ 127 with the history cases below).
- ❌ **Multi-host batch CLI** — `batch scan` / `batch report` / `batch apply` / `batch rollback` have **zero** coverage. (Needs a localhost/loopback or multi-container fixture.)
- ✅ **History trends / regressions** — added `history trends --host "$(hostname)"` + `history regressions` cases to section 11. Patterns accept the clean no-data line, so they pass regardless of whether a fresh container has persisted history yet. Verified 127/127 × 5.
- ❌ **SSH crypto hardening** — the new `KexAlgorithms`/`Ciphers`/`MACs` (incl. PQ) apply path has **no explicit assertion** (algorithm intersection, `sshd -t` pre-write validation). Also write the deferred **`#[ignore]` root integration test for the full SSH apply path** (flock-bound — see NEXT P1 / git history); it was flagged "not lost" and is still unwritten.
- ❌ **Remote-correct checkpoints** — capture/restore *through the executor*, host-keyed, cross-host refusal: not exercised.
- ❌ **Compliance Option-B semantics** — assert that an *unassessed* control reports `ManualReview` (never a false `Pass`), and that an assessed control reports `Pass`/`Fail` for every framework.
- ✅ **JSON-grep flake fixed.** Root cause was NOT stderr-fold/capture (those fixes didn't help) — the `sed 's/ANSI//g'` pre-filter intermittently emitted nothing under openSUSE's minimal locale (proven: direct `grep -ac` on the captured file matched 8/240/3 while `sed | grep` missed). Dropped the pointless pre-strip (ANSI never splits matched tokens); `run_test_output` now `grep -aqE`s the file directly. A `diag:` line (exit/bytes/head) stays in the fail path. Clean **125/125 × 5**.

**GUI Playwright (`gui-tests/tests/`) — now 9 specs** (added fleet, fleet-apply, remote, scheduler; **113/113 on all 5 distros**):
- ✅ **`fleet.spec.js`** — read-only multi-host scan, CIS% column, row expander, failed-host row (7 tests).
- ✅ **`fleet-apply.spec.js`** — mode toggle, host+plugin select, **mandatory dry-run gate** incl. re-arm on selection change, confirm modal, results (9 tests).
- ✅ **`remote.spec.js`** — host list, connect/scan/disconnect, add-host form, two-step delete (7 tests).
- ✅ **`scheduler.spec.js`** — enable toggle, schedule select, save, email/webhook subsections, test-notification (6 tests).
- ✅ Extended `tauri-mock.js` with the 3 fleet IPC commands (`run_fleet_scan`/`apply`/`rollback`) **and a Map→object arg normaliser**: bindings that build args with `serde_json::json!{}` serialise them as a JS **Map**, so the mock's `args.field` was always undefined — this had silently broken the never-tested remote/scheduler mocks too. (The old note that the mock "already mocks fleet" was wrong; fleet was added this pass.)
- ⚠️ Still no dedicated `compliance`/`history` GUI specs — those flows live inside `analysis.spec.js` (compliance tab) and `hardening.spec.js` (history tab).

**Desktop functional (`scripts/tauri-functional-test.sh`):** **zero** `fleet` / `fleet-apply` coverage. Add page-load + IPC-path tests for both new pages.

**Tauri command layer (`src-tauri/src/commands.rs`) — no tests directory exists.**
- `run_fleet_apply` / `run_fleet_rollback` / `run_fleet_mutation<T>` / `list_plugins`: unit-test `validate_ipc_string`, `validate_plugin_ids` (allowlist + empty-hosts guard), `build_batch_args`, and **`parse_outcomes` exit-code-agnostic parsing** (batch exits non-zero on per-host fail yet emits valid JSON — this invariant MUST have a test).

**Rust workspace (`cargo test --workspace`, 660 passing):** audit per-crate that **every feature added since the last test pass has unit/integration coverage** — SSH crypto helpers (`select_algorithms`), per-host history/trends/regression cores (`find_regressions`), compliance coverage aggregation (`compliance_coverage()`), ISO 27001 control catalogue, the executor relocation to `hardener-common`. Add what's missing.

**Validators (`scripts/validate_*.py`):** confirm `validate_compliance_docs.py` counts ISO 27001; `validate_tauri_docs.py` covers the new fleet commands; `validate_cli_docs.py` covers `batch` + `history trends/regressions`.

### Definition of done for this sweep
Every framework, every CLI subcommand, every GUI page, and every Tauri command has
a test that fails if it breaks. Cross-distro suite green (127, after the container rebuilds bump it again) on the
**rebuilt** containers. No silently-skipped feature. Update `DISTRIBUTION_VALIDATION.md`
test-category tables + counts to match reality.

---

## Remaining work — full backlog (everything not worked this session)

### Doc / validation leftovers
- ✅ **GUI cross-distro re-run** — `--gui` suite green on all 5 distros (2026-06-29), now 113 tests incl. the new fleet/remote/scheduler specs.
- ✅ **AUR / package version bump** — done. Repo packaging (PKGBUILD/RPM/DEB/.SRCINFO) and the AUR clone (`~/RustroverProjects/aur-linux-system-hardener`) are at **1.2.0**; the `v1.2.0` tag is pushed and the AUR package published. The AUR badge live-fetches the published version and now shows 1.2.0.

### Feature backlog (from ROADMAP / NEXT)
- **Multi-host GUI polish** (each its own small brainstorm):
  - ad-hoc `--ssh user@host` hosts in the **Fleet** and **Fleet Apply** pages (today both only use saved inventory hosts).
  - **live per-host progress** (today results appear batch-after-all → needs Tauri events/streaming, the deferred "Approach-C" in the Fleet Apply spec).
  - **per-host history surfaced in the GUI** (the CLI persists it; the desktop doesn't show it yet).
- **New compliance frameworks:** SOC 2 / FedRAMP / NIST 800-171 (additive — follow the plugin-declared-coverage pattern).
- **RHEL 10 / per-version compliance profiles** (DISA RHEL 10 STIG V1R1, CIS RHEL 10 v1.0.1 exist) — overlaps the generic frameworks + family detection; pairs naturally with the RHEL-10 container rebuild above.
- **Debug-vs-Display history serialisation** — `finding_to_scan_finding` (in `report.rs`) writes `severity`/`category` via `{:?}` (Debug → `"Critical"`/`"FileSystem"`) not `Display` (`"CRITICAL"`/`"File System"`). Pre-existing, cosmetic; needs a one-time decision on existing persisted rows. Trends are unaffected (numeric counts).
- **Real desktop-environment testing** — GNOME / KDE / XFCE **pkexec/polkit-agent** behaviour (open `[ ]` in README's v0.4.0 roadmap). Cannot run in nspawn; needs actual DE sessions. Human-run QA.
- **External security audit** (third-party).
- **Performance optimisation** (scan speed).
- **Version cut** for the accumulated `[Unreleased]` changelog once the above land.

### README polish + visual leftovers (deferred from this session's audit)
Readability:
- Fold the ~95-line **CLI usage** block into per-verb `<details>` sections (scan / report / apply / checkpoint / history / daemon / systemd).

Visual (the "other visual things to improve" the user asked for, not yet surfaced/applied):
- Swap the plain `Complete` / `Supported` **status cells** (Features + Multi-Distribution tables) for ✓ glyphs or small shields for scannability.
- A **logo / wordmark** — there's none; the header is text + badges only. A small SVG mark (in keeping with the dark/teal "Midnight Teal" app aesthetic, *less GitHub-like, more personal* per the user's standing preference) would lift first impression.
- The **Architecture** section is an **ASCII tree** — consider a real rendered diagram (the crate dependency graph especially) as an image.
- Add a live **CI/build badge** once GitHub Actions visibility is confirmed (deliberately skipped this session to avoid a `build: unknown` badge if the workflow path/visibility differs).

All cosmetic; the user deprioritised the first two earlier, but everything here remains un-done.

### Deferred code cleanups (salvaged from the retired Feb audit — see NEXT P3)
- `crates/hardener-core/src/context.rs:29` — `#[allow(dead_code)] shared_data` field on `PluginContext` is never read; drop it (and the `allow`) or wire it up.
- `crates/hardener-core/src/registry.rs` — repeated identical `RwLock` read-error handling; extract a helper.
- `crates/hardener-state/src/scan_manager.rs:355` — `unwrap_or_default()` silently swallows corrupted-JSON deserialisation; log/surface instead.

### Deferred security item (from the §4 reconciliation)
- **SAM-039** — explicit per-command **Tauri capability ACLs**. Still deferred post-v1.0 (requires refactoring all commands into a dedicated Tauri plugin); `default.json` grants only `core:default` + `dialog:default`. Existing `PrivilegedOpGuard` + pkexec + IPC validation deemed sufficient for v1.x. Revisit when doing the GUI work above.

---

## Invariants & gotchas (do not break)

- **sudo cannot be driven by the assistant** (no tty + tty-scoped sudo on Arch) — the user runs privileged container/test commands; the assistant preps + parses + updates docs.
- **Cross-distro needs the musl static binary** — a glibc binary built on Arch fails on older-glibc distros. Build `--target x86_64-unknown-linux-musl` first; `full-test-suite.sh` runs the *static binary*, no per-distro recompile.
- **`daemon status` uses `--limit <N>`** now (not a positional count) — don't reintroduce the old form in tests/docs.
- **`run_fleet_mutation` must stay exit-code-agnostic** — `batch apply/rollback` exit non-zero on per-host failure yet emit valid JSON; never gate on `output.status.success()`.
- **Mutation only ever happens inside the audited CLI** — the GUI builds args + parses JSON; it never reimplements apply/rollback/checkpoint logic. **No pkexec for remote** (SSH user's privilege); pkexec is local-host only.
- **`hardener-cli` is a BIN** → `cargo test -p hardener-cli` (NOT `--lib`).
- **`#[cfg(test)] mod` must be the LAST item in a file** (clippy `items_after_test_module` under `-D warnings`).
- **`docs/superpowers/` + `.rust-sec-ci.toml` are GITIGNORED**; **`test-results/` is gitignored** (root-owned run artifacts — never commit).
- **CSS/markup only ships after `trunk build`** — `cargo build` embeds the committed `crates/hardener-ui/dist`. (Today's screenshots used a fresh `trunk build` + `cargo build -p linux-hardener-desktop`.)
- Pre-commit gate = naming validation (0 errors; ~98 prod + ~51 test pre-existing warnings are fine). Pre-push gate `rust-sec-ci` = clippy `-D warnings` + fmt + audit. Before claiming done: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo build --workspace`.
- Conventions: **no AI attribution** (commits/code/comments); `cargo fmt` before commits; Rust **let-chains, never nested `if`**; **British spelling** in prose.

---

## How to verify

```bash
cargo test --workspace                       # 660 passed, 0 failed, 38 ignored (will grow with the sweep)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build --workspace                      # incl. the desktop bin

# Cross-distro (user-run, root) — after container rebuilds:
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
sudo ./scripts/run-cross-distro-tests.sh --apply
sudo ./scripts/run-cross-distro-tests.sh --gui
```

---

## Git state at handoff

- `main` == **`a7b62bb`**, **5 commits ahead** of `origin` (GitHub) and GitLab — **unpushed**
  (`ec135ae`, `bee3a2a`, `ea1a0c4`, `8b1fb2d`, `a7b62bb`). Working tree clean.
- Push is the **user's** step (SSH passphrase; dual push URL → one `git push origin main`
  hits GitHub + GitLab). No open feature branches from this work.
