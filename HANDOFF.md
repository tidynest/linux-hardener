# Session Handoff — 2026-07-01 (v1.2.1 released to GitHub + GitLab + AUR → next: container rebuilds + test-coverage sweep)

> **Read this first.** Point-in-time handoff for the next development session.
> Living task list is [NEXT.md](NEXT.md); roadmap is [ROADMAP.md](ROADMAP.md);
> data-flow source of truth is [docs/DATA_FLOW.md](docs/DATA_FLOW.md).
> Project is **v1.2.1**, released to GitHub, GitLab, and AUR on 2026-07-01.
> `main` is pushed and in sync with both remotes; working tree clean.

---

## TL;DR — shipped this session (2026-07-01)

All landed on `main`, pushed, and released. Each non-trivial slice went
brainstorm → spec → plan → subagent-driven (implementer + spec-review +
code-quality-review) → merge → delete branch.

1. **CIS compliance coverage completion.** 11 curated CIS controls moved off
   `ManualReview` → `report --framework cis` now **6 ManualReview (was 17)**; the
   remainder are honest bucket-3 (cron.allow, sshd_config perms, SSH Protocol 2,
   SELinux bootloader/policy, X11). Controls: permissions 6.1.2–6.1.5, kernel
   3.2.2–3.2.4, services 2.1.1 (xinetd), firewall 3.4.1.1, pam 5.3.2/5.3.3. Each
   gained a checkpoint-protected apply action + unit tests. (Closed issue **#9**.)
2. **PAM / permissions no-loosen hardening.** shadow/gshadow use an allowed-bits
   **mask** (stricter mode compliant; apply only strips disallowed bits — never
   loosens; honoured in scan, apply, AND the `validate` dry-run). faillock `deny`
   / pwhistory `remember` use a **threshold** (`PamCompare::AtMost/AtLeast`); a
   stricter existing value is compliant and apply writes the CIS boundary only on
   a genuine violation. Scan reads the **effective** value — an inline
   `pam_faillock.so`/`pam_pwhistory.so` arg in the PAM stack overrides
   `/etc/security/*.conf`; a stricter per-host override is honoured (clamped);
   apply refuses to auto-edit the PAM stack.
3. **Polkit DE test tooling + packaging fix.** New `scripts/detect-polkit-agent.sh`
   + `test-polkit-matrix.sh` + GNOME/KDE/XFCE/no-agent wrappers +
   `docs/de-compatibility.md`. Fixed a real bug: **`polkit` was missing from the
   PKGBUILD (and AUR) `depends`** → added it + per-DE `optdepends` + RPM
   `Recommends`/`Supplements` + Debian `Suggests`. (Closed issue **#15**.)
4. **Two new RUSTSEC advisories** (caught by the release `cargo deny` gate):
   **0190** (anyhow `downcast_mut` unsound) → fixed by bumping `anyhow` 1.0.100
   → 1.0.103; **0192** (`ttf-parser` unmaintained, transitive krilla→rustybuzz
   PDF, no upgrade) → accepted in `deny.toml`.
5. **Version + doc consistency + releases.** Aligned every version reference +
   README badge; audited all docs. Released **1.2.0**, then a **1.2.1** patch
   (the v1.2.0 source tarball bundled a README still showing the 1.1.0 badge —
   the fix landed just after the tag). All three channels on **1.2.1**.
   Public version went 1.0.5 → 1.2.0 → 1.2.1 (1.1.0 cut in-tree, never published).

- **Push is the user's** (SSH passphrase; dual push URL → GitHub + GitLab; AUR is
  a separate SSH clone/key — see Invariants).

---

## TOP PRIORITY 1 — Container rebuilds (distro-version refresh)

The last cross-distro validation ran on the **February container set** (Arch
rolling, Debian 12, Fedora 41, Rocky 9, openSUSE **Leap 15.6**). openSUSE Leap
15.x reached **EOL April 2026**. Recreate the containers on current releases,
then re-run. (Tracked as issue **#10**, P1.)

**Targets:** Debian **13 "Trixie"**, Fedora **44**, Rocky/Alma **10** (or keep 9
+ add 10), openSUSE **Leap 16**, Arch (recreate to refresh).

**How:** creation scripts exist — `scripts/create-{debian,fedora,rhel,opensuse}-container.sh`
and `scripts/create-test-container.sh` (Arch). Bump their pinned release/repo
URLs to the targets. Root + network + bootstrap heavy — schedule deliberately,
watch CPU/heat.

**Then re-validate:**
```bash
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
sudo ./scripts/run-cross-distro-tests.sh --apply          # CLI suite
sudo ./scripts/run-cross-distro-tests.sh --gui            # GUI/Playwright
```
Update the container set / version columns in `docs/DISTRIBUTION_VALIDATION.md`.

> ⚠️ **sudo gotcha:** the assistant cannot elevate (no tty + Arch's tty-scoped
> sudo). The user runs the privileged commands; the assistant preps, parses
> `test-results/summary.txt` + logs, and updates the docs.

---

## TOP PRIORITY 2 — Test-coverage sweep (make every suite first-class)

Audit **every** suite/script against the **current** feature set, then fill gaps
with high-quality tests. (Tracked as issue **#13**, P2, for the batch CLI part.)

### Confirmed gaps (starting points — audit for more)

Already covered — do NOT re-write: `select_algorithms`, `find_regressions`,
`compliance_coverage` + the **11 new CIS pairs** (`lib.rs`), permissions
`violates`/`target_mode` mask + `pam_violates`/`breaches_threshold`/`clamp_target`
+ inline-pam.d + no-loosen (all in `pam_mock_tests.rs` / permissions unit tests
added this session), `validate_ipc_string`/`validate_plugin_ids`,
`build_batch_args`/`parse_outcomes`, ISO 27001, Option-B honesty.

**Genuinely absent:**
- **Bash CLI suite (`scripts/full-test-suite.sh`)** — still **no `batch`
  scan/report/apply/rollback** cases (needs loopback/multi-container fixture).
  History trends/regressions cases were added (127/127 × 5 on the Feb set).
- **SSH crypto hardening** — no explicit assertion for the `KexAlgorithms`/
  `Ciphers`/`MACs` (incl. PQ) apply path; the deferred `#[ignore]` root SSH
  integration test is still unwritten.
- **Remote-correct checkpoints** — capture/restore through the executor,
  host-keyed, cross-host refusal: not exercised by an automated suite.
- **Polkit DE testing (issue #18, PARTIAL)** — tooling shipped + `bash -n` clean +
  detect/matrix ran green on the Hyprland host, but **actual GNOME/KDE/XFCE
  session runs need real DE VMs** (or nspawn can't do it). Human-run QA.
- **Desktop functional (`scripts/tauri-functional-test.sh`)** — no fleet /
  fleet-apply coverage.

### Definition of done
Every framework, CLI subcommand, GUI page, and Tauri command has a test that
fails if it breaks. Cross-distro suite green on the **rebuilt** containers.

---

## Remaining backlog (from ROADMAP / NEXT / GitHub issues)

- **Multi-host GUI polish** (issue #12): ad-hoc `--ssh user@host` hosts in Fleet /
  Fleet Apply; live per-host progress (Tauri events/streaming — the deferred
  "Approach-C"); per-host history surfaced in the GUI.
- **New compliance frameworks** (issue #16): SOC 2 / FedRAMP / NIST 800-171 —
  additive, follow the plugin-declared-coverage pattern (adjacent to this
  session's CIS work).
- **SAM-039** (issue #22): per-command Tauri capability ACLs — deferred security
  item; requires refactoring commands into a dedicated Tauri plugin. `default.json`
  grants only `core:default` + `dialog:default`; `PrivilegedOpGuard` + pkexec +
  IPC validation deemed sufficient for v1.x.
- **RHEL 10 compliance profiles** (issue #11) — pairs with the RHEL-10 container.
- **Debug-vs-Display history serialisation** (issue #17) — `finding_to_scan_finding`
  (`report.rs`) writes severity/category via `{:?}` not `Display`; cosmetic,
  needs a decision on existing persisted rows. Trends unaffected (numeric).
- **Docker container image** (issue #14, P3).
- **External security audit** (issue #19), **performance optimisation** (issue #20),
  **deferred code cleanups** (issue #21), **README polish** (issue #23).

### README polish + visual leftovers (issue #23, deferred)
- Fold the CLI usage block into per-verb `<details>` sections.
- ✓ glyphs / shields for the plain `Complete`/`Supported` status cells.
- A logo / wordmark (dark/teal "Midnight Teal" aesthetic — *less GitHub-like, more
  personal* per the user's standing preference).
- A rendered Architecture diagram (replace the ASCII tree).
- A live CI/build badge now that GitHub Actions is confirmed green.

---

## Invariants & gotchas (do not break)

- **sudo cannot be driven by the assistant** — the user runs privileged
  container/test commands; the assistant preps + parses + updates docs.
- **Cross-distro needs the musl static binary** — build
  `--target x86_64-unknown-linux-musl` first.
- **PAM/permissions never loosen** — shadow/gshadow use the allowed-bits mask;
  faillock/pwhistory use the threshold + effective-value (inline pam.d overrides
  `.conf`); apply never auto-edits `/etc/pam.d/*`.
- **`run_fleet_mutation` must stay exit-code-agnostic** — `batch apply/rollback`
  exit non-zero on per-host failure yet emit valid JSON; never gate on
  `output.status.success()`.
- **Mutation only inside the audited CLI** — the GUI builds args + parses JSON;
  no pkexec for remote (SSH user's privilege); pkexec is local-host only.
- **`hardener-cli` is a BIN** → `cargo test -p hardener-cli` (NOT `--lib`).
- **`#[cfg(test)] mod` must be the LAST item in a file** (clippy
  `items_after_test_module` under `-D warnings`).
- **`docs/superpowers/` + `.rust-sec-ci.toml` + `test-results/` are GITIGNORED.**
- **CSS/markup only ships after `trunk build`** — `cargo build` embeds the
  committed `crates/hardener-ui/dist`.
- **Release process:** `scripts/release.sh` bumps code/docs/CHANGELOG + commits +
  tags + pushes, but **does NOT bump packaging** (PKGBUILD/RPM/Debian) or AUR —
  both are manual each release (bump `pkgver`, regen `.SRCINFO`; AUR:
  `updpkgsums` against the pushed tag, strip the SKIP comment, push). On a
  **patch** bump, move only CURRENT-version markers (badge, "Current Phase",
  code, packaging, `**Version:**`, "Current Version"); leave MILESTONE markers
  (roadmap `### vX` headings, "Fleet (vX)", "see vX" refs) and historical
  validation records (`DISTRIBUTION_VALIDATION.md`).
- **AUR maintainer clone:** `~/RustroverProjects/aur-linux-system-hardener`
  (remote `ssh://aur@aur.archlinux.org/...`, `id_ed25519`, branch `master`). NOT
  `~/.cache/yay/...` (https, read-only, stale).
- **Pre-push gate `rust-sec-ci`** = clippy `-D warnings` + fmt + audit. Release
  checklist additionally requires **`cargo deny check`** (advisories/bans/licenses/
  sources). Pre-commit gate = naming validation (0 errors; ~99 prod + ~61 test
  pre-existing abbreviation warnings are non-blocking).
- Conventions: **no AI attribution** (commits/code/comments); `cargo fmt` before
  commits; Rust **let-chains, never nested `if`**; **British spelling** in prose.

---

## How to verify

```bash
cargo test --workspace                       # 660 passed, 0 failed, 38 ignored
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build --workspace                      # incl. the desktop bin
cargo deny check                             # advisories/bans/licenses/sources (release gate)

# Cross-distro (user-run, root) — after container rebuilds:
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
sudo ./scripts/run-cross-distro-tests.sh --apply
sudo ./scripts/run-cross-distro-tests.sh --gui
```

---

## Git state at handoff

- `main` == **`9f7437f`**, in sync with `origin` (GitHub) and GitLab. Working
  tree clean (before this handoff commit). Tag **`v1.2.1`** pushed; GitHub release
  built with 3 binaries (x86_64, x86_64-musl, aarch64); CI + CodeQL green.
- **AUR** at 1.2.1 (`b8922bb` in `~/RustroverProjects/aur-linux-system-hardener`).
- Push is the **user's** step (SSH passphrase; dual push URL → one
  `git push origin main` hits GitHub + GitLab). No open feature branches.
