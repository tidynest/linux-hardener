# Session Handoff — 2026-07-02 (v1.2.2 released to GitHub + GitLab → next: repo packaging + AUR bump, then backlog)

> **Read this first.** Point-in-time handoff for the next development session.
> Living task list is [NEXT.md](NEXT.md); roadmap is [ROADMAP.md](ROADMAP.md);
> data-flow source of truth is [docs/DATA_FLOW.md](docs/DATA_FLOW.md).
> Project code is **v1.2.2**, tag pushed to GitHub + GitLab on 2026-07-02.
> `main` is pushed and in sync with both remotes; working tree clean.
> **Repo packaging (PKGBUILD/RPM/Debian) + AUR are still at 1.2.1 — bump them
> (see TOP PRIORITY 1).**

---

## TL;DR — shipped this session (2026-07-02)

1. **Rollback data-loss fix (`v1.2.2`).** A cross-distro run surfaced two coupled
   bugs in checkpoint rollback:
   - The executor masked file mode `& 0o777`, so a **0000-perm file** (Arch ships
     `/etc/shadow` + `/etc/gshadow` as `0000`) was captured as mode `0` — the
     "did not exist at checkpoint" sentinel — and rollback **`rm`'d it**. Fixed:
     `local.rs` returns the full `st_mode`; `ssh.rs` ORs the `%F` type bit into
     mode (extracted a pure `parse_stat_metadata`).
   - `/etc/{passwd,group,shadow,gshadow}` (CIS 6.1.2–6.1.5) were checkpointed by
     the permissions plugin but **absent from `DEFAULT_ROLLBACK_PREFIXES`**
     (`manager.rs`) → permissions apply→rollback Phase-1 aborted **exit 1 on
     every distro**. Fixed: allow-list them.
   - Regression tests at unit (`local.rs`/`ssh.rs`), executor, and **end-to-end
     manager rollback** levels (the last proven non-vacuous: mode 0 →
     `rm /etc/shadow`). `CHANGELOG [1.2.2]`.
2. **Container refresh (issue #10) — DONE + validated 5/5 × 127/127.** New set:
   Debian 13 Trixie, Fedora 44, Rocky 10, openSUSE Leap 16.0; Arch rolling. The
   Fedora/Rocky/openSUSE `create-*-container.sh` were **rewritten to
   `podman export`** (see Invariants for why host dnf/zypper bootstrap now fails).
3. **RUSTSEC-2026-0097** (`rand` 0.8.5 unsound) accepted in `deny.toml` — flagged
   version is a build-time transitive (tauri-build→cssparser→phf_generator); the
   first-party key-gen path (`signing.rs`) uses `rand` 0.9.3, condition not met.
4. **Released 1.2.2** to GitHub + GitLab (tag `v1.2.2`, `release.sh patch`, CI +
   CodeQL green). Prior public line: 1.0.5 → 1.2.0 → 1.2.1 → **1.2.2**.

- **Push is the user's** (SSH passphrase; dual push URL → GitHub + GitLab; AUR is
  a separate SSH clone/key — see Invariants).

---

## TOP PRIORITY 1 — Finish the 1.2.2 release (repo packaging + AUR)

`release.sh` bumped code/docs/CHANGELOG/tag but **not** the distro packaging or
AUR. Both are still at 1.2.1 and must be bumped to 1.2.2:

1. **Repo packaging** — bump `pkgver` 1.2.1 → 1.2.2 in `packaging/PKGBUILD`, the
   RPM spec, `packaging/debian/changelog`; regen `.SRCINFO`
   (`makepkg --printsrcinfo > packaging/.SRCINFO`). Commit + push.
2. **AUR** (maintainer clone `~/RustroverProjects/aur-linux-system-hardener`):
   `cp packaging/PKGBUILD <clone>/` → `updpkgsums` (fills `sha256sums` from the
   pushed v1.2.2 source tarball) → strip the SKIP-regen comment →
   `makepkg --printsrcinfo > .SRCINFO` → `git commit -am` + push.

> ⚠️ **sudo gotcha:** the assistant cannot elevate (no tty + Arch's tty-scoped
> sudo). The user runs privileged/container commands and the pushes; the
> assistant preps + parses + updates docs.

---

## TOP PRIORITY 2 — Test-coverage sweep (issue #13, P2)

Audit every suite/script against the current feature set, fill gaps. Progress
this session narrowed the list:

**Now covered (do NOT re-write):** the rollback 0000-perm + allowlist paths
(`local.rs`/`manager.rs`/`ssh.rs` unit + end-to-end); `parse_stat_metadata`;
plus the prior set (`select_algorithms`, `compliance_coverage` + the 11 CIS
pairs, permissions mask + `pam_violates`/`clamp_target` + inline-pam.d,
`build_batch_args`/`parse_outcomes`, ISO 27001). The **cross-distro lifecycle**
(apply→verify→rollback per plugin) now runs green on all 5 refreshed distros.

**Still genuinely absent:**
- **Bash CLI suite (`scripts/full-test-suite.sh`)** — no `batch`
  scan/report/apply/rollback cases (needs loopback/multi-container fixture).
- **SSH crypto apply path** — `parse_stat_metadata` + `select_algorithms` +
  `validate_sshd_config` are unit-tested, but the full `KexAlgorithms`/`Ciphers`/
  `MACs` apply-to-`sshd_config` path is only exercised in containers, not a
  focused test (the flock on the real file blocks a clean MockExecutor test).
- **Polkit DE testing (issue #18, PARTIAL)** — tooling shipped; real GNOME/KDE/
  XFCE session runs still need DE VMs.
- **Desktop functional** — no fleet / fleet-apply coverage.

### Definition of done
Every framework, CLI subcommand, GUI page, and Tauri command has a test that
fails if it breaks. Cross-distro suite green on the refreshed containers ✓.

---

## Remaining backlog (from ROADMAP / NEXT / GitHub issues)

- **Multi-host GUI polish** (issue #12): ad-hoc `--ssh user@host` hosts in Fleet /
  Fleet Apply; live per-host progress (Tauri events/streaming — deferred
  "Approach-C"); per-host history surfaced in the GUI.
- **New compliance frameworks** (issue #16): SOC 2 / FedRAMP / NIST 800-171 —
  additive, follow the plugin-declared-coverage pattern.
- **SAM-039** (issue #22): per-command Tauri capability ACLs — deferred security
  item; needs commands refactored into a dedicated Tauri plugin.
- **RHEL 10 compliance profiles** (issue #11) — now pairs with the live Rocky-10
  container.
- **Debug-vs-Display history serialisation** (issue #17) — `finding_to_scan_finding`
  (`report.rs`) writes severity/category via `{:?}` not `Display`; cosmetic.
- **Follow-up: rand 0.8→0.9** — RUSTSEC-2026-0097 is accepted (build-time
  transitive), but bumping the transitive out would clear it entirely.
- **Docker container image** (issue #14, P3); **external security audit** (#19),
  **performance optimisation** (#20), **deferred code cleanups** (#21),
  **README polish** (#23).

---

## Invariants & gotchas (do not break)

- **sudo cannot be driven by the assistant** — the user runs privileged
  container/test commands + the pushes; the assistant preps + parses + updates docs.
- **Container bootstrap = `podman export` for Fedora/Rocky/openSUSE** (Debian
  still `debootstrap`, Arch `pacstrap`). WHY host dnf/zypper bootstrap fails on
  Arch: rpm sets `%_pkgverify_level all` (`/usr/lib/rpm/macros`) → host-dnf
  `--installroot` always fails GPG and `dnf --nogpgcheck` can't override the
  rpm-level policy; Leap 16 `zypper --root` dies on the `filesystem` usrmerge
  scriptlet. `podman export` runs scriptlets/keys natively (host has podman 5.8.3;
  host `dnf` no longer needed). Images: `docker.io/library/fedora:44`,
  `docker.io/rockylinux/rockylinux:10`, `docker.io/opensuse/leap:16.0`.
- **Checkpoint rollback** — the stored mode `0` means "absent at checkpoint →
  remove on restore"; executors must return the **full `st_mode`** (type bit
  included) so an existing 0000-perm file is never mistaken for absent. Any path a
  plugin checkpoints must be in `DEFAULT_ROLLBACK_PREFIXES` or Phase-1 aborts.
- **Cross-distro needs the musl static binary** — build
  `--target x86_64-unknown-linux-musl` first.
- **PAM/permissions never loosen** — shadow/gshadow use the allowed-bits mask;
  faillock/pwhistory use the threshold + effective-value; apply never auto-edits
  `/etc/pam.d/*`.
- **`run_fleet_mutation` must stay exit-code-agnostic** — `batch apply/rollback`
  exit non-zero on per-host failure yet emit valid JSON; never gate on
  `output.status.success()`.
- **`hardener-cli` is a BIN** → `cargo test -p hardener-cli` (NOT `--lib`).
- **`#[cfg(test)] mod` must be the LAST item in a file** (clippy
  `items_after_test_module` under `-D warnings`).
- **`docs/superpowers/` + `.rust-sec-ci.toml` + `test-results/` are GITIGNORED.**
- **CSS/markup only ships after `trunk build`** — `cargo build` embeds the
  committed `crates/hardener-ui/dist`.
- **Release process:** `release.sh` bumps code/docs/CHANGELOG + commits + tags +
  pushes, but **NOT packaging or AUR** (both manual — see TOP PRIORITY 1), and it
  misses four current-version doc markers: **README badge + "Current Phase",
  NEXT "Current Version", `docs/DATA_FLOW.md` `**Version:**`** — bump those by
  hand. On a patch bump only CURRENT-version markers move; leave MILESTONE
  markers (roadmap `### vX` headings, "Fleet (vX)", "see vX") and historical
  validation records.
- **AUR maintainer clone:** `~/RustroverProjects/aur-linux-system-hardener`
  (remote `ssh://aur@aur.archlinux.org/...`, `id_ed25519`, branch `master`). NOT
  `~/.cache/yay/...`.
- **Pre-push gate `rust-sec-ci`** = clippy `-D warnings` + fmt + audit. Release
  checklist additionally requires **`cargo deny check`**. Pre-commit gate = naming
  validation (0 errors; ~99 prod + ~62 test pre-existing abbreviation warnings
  are non-blocking).
- Conventions: **no AI attribution**; `cargo fmt` before commits; Rust
  **let-chains, never nested `if`**; **British spelling** in prose.

---

## How to verify

```bash
cargo test --workspace                       # 667 passed, 0 failed, 38 ignored
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build --workspace                      # incl. the desktop bin
cargo deny check                             # advisories/bans/licenses/sources (release gate)

# Cross-distro (user-run, root) — containers refreshed this session, 5/5 green:
cargo build --release --target x86_64-unknown-linux-musl -p hardener-cli
sudo ./scripts/run-cross-distro-tests.sh --apply
```

---

## Git state at handoff

- `main` == **`3581f80`** (`chore(release): bump version to 1.2.2`) + a docs sync
  commit, in sync with `origin` (GitHub) and GitLab (main ↔ master). Working tree
  clean. Tag **`v1.2.2`** pushed to both; `Release` workflow builds the 3 binaries
  (x86_64, x86_64-musl, aarch64) + GitHub release; CI + CodeQL green.
- **Repo packaging + AUR still at 1.2.1** — the immediate next step (TOP PRIORITY 1).
- Push is the **user's** step (SSH passphrase; dual push URL → one
  `git push origin main` hits GitHub + GitLab). No open feature branches.
