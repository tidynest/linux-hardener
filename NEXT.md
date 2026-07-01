# Next Development Session — Linux System Hardener

---

## Current State (as of 2026-07-01)

**v1.2.1 released** (2026-07-01) to GitHub, GitLab, and AUR — a docs/badge patch
on top of v1.2.0. The public version jumped 1.0.5 → 1.2.0 → 1.2.1 (1.1.0 was cut
in-tree but never published).

v1.2.0 shipped: multi-host batch CLI (`batch scan/report/apply/rollback`),
per-host history/trends/regression detection, scheduler regression alerts,
ISO/IEC 27001:2022 compliance framework, multi-framework mappings across all 8
plugins, CIS coverage completion (11 controls now Pass/Fail; `report --framework
cis` shows 6 `ManualReview`, down from 17), PAM/permissions assessment
improvements (faillock/pwhistory threshold comparison; shadow/gshadow
allowed-bits mask), SSH crypto hardening (KexAlgorithms/Ciphers/MACs incl. PQ),
remote-correct checkpoints, Fleet GUI (scan posture + apply/rollback), and polkit
DE test tooling. `cargo test --workspace` = **660 passed / 0 failed / 38 ignored**.

### Key completed milestones (cumulative through v1.2.0):

- **All 13 audit bugs fixed** (BUG-01 through BUG-13)
- **All 7 infrastructure issues resolved** (INFRA-01 through INFRA-07)
- **Trait refactor complete** — `Config` unit struct deleted, `HardeningPlugin` trait now accepts `&PluginConfig`
- **Cross-distro validation** — 127-test suite passes on Arch, Debian, Fedora, Rocky Linux 9, openSUSE
- **Live testing fixes** (2026-02-23) — checkpoint directory permissions, vfat detection, scan history, auditd reload
- **PluginConfig wiring complete** (2026-02-23) — all 8 plugins consume directives/exceptions
- **GUI/CLI feature parity complete** (2026-02-24) — scan filtering, checkpoint CRUD, report export, scan history, audit/compliance modes
- **Scheduler UI complete** (2026-02-24) — schedule config, notification config, email/webhook, test notification
- **UI polish pass complete** (2026-02-24) — side-by-side layouts, card standardisation, responsive fixes
- **Packaging infrastructure** (2026-02-25) — AUR PKGBUILD, RPM spec, Debian packaging, systemd units, polkit policy
- **Test quality pass** (2026-02-25) — 178+ assertion messages, 80+ println removed, net -422 lines
- **High Contrast theme** (2026-02-25) — WCAG AAA accessibility theme (7:1+ contrast ratios)
- **Man page** (2026-02-25) — `data/hardener.1` troff man page for all commands
- **Security remediation** (2026-02-26) — all 53 security findings resolved (see `docs/security-audit/REMEDIATION_TRACKER.md`)
- **Code quality pass** (2026-02-27) — 27 code quality findings fixed, shared helper extraction, 10 packaging fixes
- **Documentation** (2026-02-27) — SECURITY.md updated, INSTALL.md created for 5 distro families
- **v1.0.3 parallel test runners** (2026-02-28) — `run-gui-tests-parallel.sh`, `run-cross-distro-tests-parallel.sh`, `run-desktop-tests.sh`, `run-all-tests-parallel.sh`
- **v1.0.2 merged branches** (2026-02-28) — `cli-ux-perfection` (CLI crash fixes, stderr routing, idempotent dirs, user-mode systemd) + `feature/desktop-testing-ux` (keyboard nav, ARIA, clipboard, TabBar migration, 95 desktop tests)
- **Desktop tests**: 49 UX tests + 46 functional tests + 21 Node.js tests all passing
- **660 unit/integration tests pass**, clippy clean, native + WASM builds clean

### Trait refactor summary (commits `81c13ad`, `d029629`, `b87fb1c`):

- Core: deleted `Config`, trait methods accept `&PluginConfig`, `PluginManager` uses `&HardenerConfig`
- All 8 plugins updated to new trait signature
- SSH plugin is the **pilot**: fully consumes `config.directives` for overrides and `config.has_valid_exception()` for exemptions
- 35 test locations updated across 16 test files

### Live testing fixes (2026-02-23):

| Commit | Fix |
|--------|-----|
| `06c9ab4` | Checkpoint directory permissions, metadata-only snapshots, vfat chmod detection |
| `44ebe2f` | CLI scan persists results to history database |
| `5edece5` | Audit plugin uses `augenrules --load` instead of `systemctl restart auditd` |

### Infrastructure issues resolved:

| Issue | Description | Resolution |
|-------|-------------|------------|
| INFRA-01 | Uncommitted work | ✅ All committed |
| INFRA-02 | SSH auth to remotes | ✅ Resolved (user keeps SSH URLs) |
| INFRA-03 | Version mismatch 0.3.2→0.3.3 | ✅ Fixed (`14ad7f4`) |
| INFRA-04 | GUI/Tauri excluded from CI | ✅ WASM CI check job added (`fee6124`) |
| INFRA-05 | Overlapping planning docs | ✅ Consolidated (`795718b`) |
| INFRA-06 | Tauri CSP disabled | ✅ CSP + capabilities added (`1aefc69`) |
| INFRA-07 | Workspace dep inconsistencies | ✅ Centralised (`14ad7f4`) |

**Build status**: `cargo check`, `cargo check -p hardener-ui --target wasm32-unknown-unknown`, `cargo test`, and `cargo clippy` all pass clean.

---

## What's next (priority order)

> Refreshed 2026-07-01. Items are open unless marked Done.

### P0 — Compliance assessment coverage (phase 2)

**Phase 1 — Done.** Unassessed controls report `ManualReview` not a false `Pass`.

**Phase 2 — Done.** All 8 plugins now tag findings with STIG, NIST 800-53,
PCI-DSS, HIPAA, GDPR and ISO 27001:2022 control IDs (sourced from
ComplianceAsCode/SSG and the project catalogues, cited inline) alongside CIS, so
every framework fails on insecure systems. Failure mode is safe: a wrong mapping
causes a false *fail*, never a false pass. Design notes:
[docs/plans/2026-06-19-compliance-coverage-phase2.md](docs/plans/2026-06-19-compliance-coverage-phase2.md).

**Phase 3 (derive + Option B) — Done.** Coverage is now per-control and
plugin-declared: each plugin exposes `coverage()`, aggregated by
`hardener_plugins::compliance_coverage()` and injected into `ReportGenerator`
(the framework-level `AUTOMATED_FRAMEWORKS`/`is_automated` API is gone). A
control the engine assesses reports `Pass`/`Fail` for *every* framework (Option
B); one it does not assess reports `ManualReview`. Non-CIS catalogues
(`stig.rs`/`nist.rs`/`pci.rs`/`hipaa.rs`/`gdpr.rs`) are deleted and derived from
coverage, so each report uses a single id scheme with no placeholder noise. CIS
and ISO 27001 keep their curated catalogues (full standard, unassessed controls →
`ManualReview`). Verified end-to-end (`hardener report --framework STIG`).

**Compliance — remaining follow-ups (not lost):**
- **HIPAA/GDPR confidence** — review done (2026-06-20). Inventoried all HIPAA/GDPR mappings (8 plugins) and SSG-cross-checked the questionable ones. SSH/PAM/audit/firewall/permissions/MAC/services sound; GDPR `TM-*` scheme + `Art.32(1)(a)` (encryption→SSH crypto only) consistent. **Fixed:** kernel cited HIPAA `164.312(c)(1)` (Integrity) on exploit-mitigation sysctls — re-cited the SSG-referenced ones (ASLR/`dmesg_restrict`/`suid_dumpable`) to `164.312(a)(1)` and dropped the unsourced ones (`kptr_restrict`/`ptrace_scope`/`protected_*links`). **Permissions/MAC alignment — done:** both already carried `164.312(a)(1)` alongside `(c)(1)`; the redundant `(c)(1)` is dropped so they match SSG's `164.312(a)` preference. Absence is locked in by regression assertions in both plugins' tests.
- **CIS catalogue hygiene** — done. `5.2.14`–`5.2.16` (strong Kex/Ciphers/MACs) are now in the curated `cis.rs`. Note: Option-B `Pass` visibility was *already* working for any plugin-emitted CIS id via the phase-3 coverage merge (the generator folds coverage into the catalogue for CIS too) — the curated entries are for standard completeness, not to fix a missing `Pass`. The bare CIS `1.6.1` the kernel plugin emitted for `fs.protected_hardlinks/symlinks` has been **removed**: the upstream SSG rules carry no CIS reference (only NIST/STIG), so the mapping was unsourced and collided with the curated `1.6.1.1`–`1.6.1.4` MAC controls. Sourced NIST/STIG mappings retained.

### P1 — SSH crypto-algorithm hardening — Done

The SSH plugin now hardens `KexAlgorithms`/`Ciphers`/`MACs` including post-quantum
kex (`mlkem768x25519-sha256`, `sntrup761x25519-sha512`). It auto-detects host
support via `ssh -Q kex|cipher|mac` and writes only the intersection with a strong
allow-list (`select_algorithms`) — so it can never set an unknown algorithm (no
lockout) or a weak one (no downgrade); empty intersection → leave host default.
`validate_sshd_config` runs `sshd -t -f <temp>` before any write/restart and
aborts on failure. Pure helpers are unit-tested with `MockExecutor`.

**Small follow-up (not lost):** consider an `#[ignore]` root integration test for
the full apply path (still flock-bound, see git history). (Obsolete `Protocol 2`
directive now removed.)

### P1 — ISO/IEC 27001:2022 framework — Done

`iso27001.rs` now defines the 93 Annex A:2022 controls across the 4 themes
(Organizational 37, People 8, Physical 14, Technological 34) with official clause
numbers and titles, wired into `frameworks::get_controls`. Plugin findings map to
the Technological controls (8.24 crypto, 8.5 auth, 8.20 networks, 8.15 logging,
8.9 config, 8.3 access), so ISO 27001 reports assess real state.

### P2 — RHEL 10 compliance profiles

DISA RHEL 10 STIG V1R1 (2026-06-02) and CIS RHEL 10 v1.0.1 now exist. Distro
detection already routes RHEL 10 through the Red Hat family; add the profile data.

### P2 — Multi-host SSH management

CLI batch-scan slice — **Done.** `hardener batch scan` scans many hosts
concurrently (`--all` / `--host` from the shared inventory, ad-hoc `--ssh`,
`--concurrency`), with a per-host + rollup report and tiered CI exit codes
(0 clean / 1 findings / 2 host or usage error). The inventory
(`~/.config/linux-hardener/hosts.toml`) is shared with the desktop GUI.

Per-host history persistence slice — **Done.** `batch scan` persists each host's
results to the scheduler history db keyed by host (inventory name, or
`user@host:port` for ad-hoc hosts), best-effort; the pool uses SQLite WAL for safe
concurrent writes. Read back with `history list --host <key>`. Spec/plan under
`docs/superpowers/`.

Per-host trend tracking slice — **Done.** `hardener history trends --host <key>`
derives a per-host timeline on query from the persisted sessions (no new table,
no stored score): completed scans oldest-first with per-severity counts, the
change in total findings, and a `better`/`worse`/`same` direction computed by
severity priority. `--format json` emits the points. Unit-tested direction logic
plus a live render against a real host.

Regression alerts slice — **Done (CLI).** `hardener history regressions [--host]`
compares each host's two newest completed scans and reports the ones whose latest
is worse (same severity-priority compare as trends), exiting `1` when any
regression is found so it can gate CI (`0` otherwise). Unit-tested detection.
The detection core (`find_regressions`) is reusable by a future scheduler-driven
alert; wiring regressions into the daemon's email/webhook notifications is the
remaining, larger half of "alerts".

Scheduler regression notifications slice — **Done.** The daemon notifies via the
configured email/webhook channels when a scheduled scan regresses against the
host's previous scan. `notify_mode` = `findings` (default) / `regression` /
`both`; measured at the `notify_min_severity` floor; self-deduping. Spec + plan
under `docs/superpowers/`.

Batch report slice — **Done.** `hardener batch report` assesses many hosts against
a compliance framework (`--framework`) or scenario preset (`--scenario`,
defaulting to `server`) concurrently and prints a fleet posture table (per
`(host, framework)`: score + pass/fail/manual/N-A counts) plus a per-framework
rollup. Tiered exit code (0 compliant / 1 failing control / 2 host error) gates
CI; `--format json` and `--output` supported. Reuses the `batch scan` engine
verbatim (connection, concurrency, isolation, history persistence). Spec/plan
under `docs/superpowers/`.

Remote-correct checkpoints slice — **Done.** Checkpoint capture and restore
now run through the active `SystemExecutor`, so `apply --ssh` and
`rollback --ssh` snapshot and restore the **remote** host rather than the
controller. Checkpoints are keyed by host; rollback refuses to restore one
host's checkpoint onto another. The executor abstraction (`SystemExecutor`,
`FileMetadata`, `CommandOutput`, `MockExecutor`) moved from `hardener-core`
into `hardener-common` (re-exported from core for source compatibility);
`SystemExecutor` gained `read_dir`, `FileMetadata` gained `uid`/`gid`.

Batch apply slice — **Done.** `hardener batch apply` applies hardening across
many hosts concurrently. Dry-run by default; `--execute` performs real changes.
A per-host privilege probe (uid 0 or passwordless `sudo`) gates `--execute` and
isolates non-privileged hosts as failed without aborting the rest. Each host
that executes receives an automatic host-keyed checkpoint and a best-effort
audit-log entry. Tiered exit: 0 all clean / 1 apply or validation failure /
2 connect, privilege or usage error. Flags mirror `batch scan`.

Batch rollback slice — **Done.** `hardener batch rollback` rolls back many hosts
concurrently to their latest per-plugin checkpoint
(`<plugin-id>-pre-apply`). Dry-run by default; `--execute` restores. Same
per-host privilege probe and isolation as `batch apply`; restores reuse the
host-keyed checkpoints (a checkpoint is never restored onto a different host) and
write a best-effort audit entry. Tiered exit: 0 all clean / 1 a checkpoint
restore failure / 2 connect, privilege or usage error.

Desktop fleet view (read-only) — **Done.** A new **Fleet** page in the desktop
GUI scans several saved inventory hosts concurrently and shows each host's
severity posture (per-host critical/high/medium/low/info tallies, expandable to
that host's findings). Reuses the single-host scan path in-process; per-host
failure is isolated. Deferred follow-ups: ~~fleet apply/rollback in the GUI~~
(shipped 2026-06-28 — see Fleet Apply page), ad-hoc `--ssh` hosts, live
per-host progress, per-host history persistence from the GUI. Emergency
per-host rollback remains available via `sudo hardener --ssh <host> rollback`.
Per-host CIS score columns plus a per-framework breakdown in the row expander
shipped 2026-06-24.

**Follow-up (from review):** `finding_to_scan_finding` (now in `report.rs`)
serialises `severity`/`category` to the history db via `{:?}` (Debug), which
yields variant identifiers (`"Critical"`, `"FileSystem"`) rather than the official
`Display` strings (`"CRITICAL"`, `"File System"`) and would shift if a variant is
renamed. Pre-existing (single-host `scan` writes the same). Trends are **not**
affected — they read the numeric `*_count` columns, which `complete_session`
derives case-insensitively, not the per-finding severity string. Switching to
`Display` still needs a one-time decision about existing persisted rows; defer to
a dedicated change.

### P3 — Docker container image

Ship a `Dockerfile`/image so the hardener runs in containers / CI without a full
distro install (user request, 2026-06-29). Reuse the existing
`x86_64-unknown-linux-musl` static binary → a tiny distroless/Alpine image, no
glibc. Decide on pickup: **scan/report read-only is the safe default**; *apply*
would need `--privileged` + host namespaces (`--pid=host`, host `/etc`, `/sys`)
to mutate the real host, which undercuts container isolation — likely document
as discouraged/unsupported. Add a `docker` row to `DISTRIBUTION_VALIDATION.md`
once it exists.

### P3 — Deferred code cleanups

Minor, pre-existing; salvaged from the Feb crate audit before its snapshot was
retired (`docs/audit/**` removed 2026-06-28 — a stale per-file mirror of source,
superseded by the code itself + `cargo doc`; these three flags were its only
still-live signal):

- [`hardener-core/src/context.rs`](crates/hardener-core/src/context.rs) — the
  `#[allow(dead_code)] shared_data` field on `PluginContext` is never read; drop
  the field and the `allow`, or wire it up.
- [`hardener-core/src/registry.rs`](crates/hardener-core/src/registry.rs) —
  repeated identical `RwLock` read-error handling; extract a helper.
- [`hardener-state/src/scan_manager.rs`](crates/hardener-state/src/scan_manager.rs)
  — a `unwrap_or_default()` silently swallows corrupted-JSON deserialisation; log
  or surface the error instead.

### P3 — Maintenance / currency

| Item | Detail | Status |
|------|--------|--------|
| Distro validation refresh | v1.1.0 binary **re-validated** on the existing containers 2026-06-28 (CLI suite; analysis in `docs/DISTRIBUTION_VALIDATION.md` §v1.1.0 Re-validation). **Version refresh still pending**: recreate containers for Debian 13, Fedora 44, RHEL 10, openSUSE Leap 16 (Leap 15.6 EOL April 2026). GUI suite re-run green on all 5 distros (2026-06-29, 113 tests). | 🟡 Partial |
| Cross-distro JSON-grep flake | **Root cause: the `sed` ANSI-strip in `run_test_output`** (NOT stderr-fold/capture — those fixes did not help). It piped captured output through `sed 's/ANSI//g'` before `grep`; under openSUSE's minimal-container locale that `sed` intermittently emitted nothing, masking fields that were present (proven: direct `grep -ac` matched 8/240/3 while `sed \| grep` missed). Dropped the pointless pre-strip (ANSI never splits matched tokens); now `grep -aqE`s the captured file directly, with a `diag:` line on the fail path. Suite green 125/125 × 5. | ✅ Done (837963b) |
| `tauri` 2.11.2 → 2.11.3 | Latest patch (2026-06-17); no CVE, routine bump | ✅ Done (lockfile, 2026-06-20) |
| Desktop crate compile fix | Tauri compliance commands ported to the phase-3 `ReportGenerator::new(config, coverage)` signature; `cargo check -p linux-hardener-desktop` clean | ✅ Done (2026-06-20) |
| External security audit | Third-party review | ⬜ Pending |
| Performance optimisation | Scan speed improvements | ⬜ Pending |

---

## Completed in earlier sessions

### 1. PluginConfig wiring — COMPLETED (2026-02-23)

All 8 plugins now fully consume `PluginConfig` directives and exceptions. Two families:

- **Value-override** (directives + exceptions): SSH, Kernel, Firewall, PAM, Permissions
- **Binary** (exceptions only): Services, Audit, MAC

| Plugin | Commit | Status |
|--------|--------|--------|
| SSH (pilot) | `d029629` | Done |
| Kernel | `ca53286` | Done |
| Firewall | `820f406` | Done |
| PAM | `95bf62b` | Done |
| Services | `f97e33b` | Done |
| Permissions | `d01432a` | Done |
| Audit | `2ec356a` | Done |
| MAC | `ef0f8f6` | Done |

### 2. GUI/CLI Feature Parity (v0.4.0) — COMPLETED (2026-02-24)

See `docs/GUI_CLI_PARITY_PLAN.md` — all 6 phases complete.

| Phase | Feature | Priority | Status |
|-------|---------|----------|--------|
| Phase 1 | Dry-run preview | P0 | Done |
| Phase 2 | Scan filtering (severity dropdown, plugin selection) | P0 | Done |
| Phase 3 | Checkpoint management (create/delete) | P1 | Done |
| Phase 4 | Report export (format selection, file save) | P1 | Done |
| Phase 5 | Scan history tab | P2 | Done |
| Phase 6 | Audit/compliance mode toggles | P2 | Done |

### 3. Remaining polish items

| Item | Source | Priority | Status |
|------|--------|----------|--------|
| ~~JSON output for `checkpoint rollback` command~~ | ~~ROADMAP.md v0.3.2 H~~ | Done | `5167e5a` |
| ~~Polkit policy file for nicer dialog text~~ | ~~ROADMAP.md v0.3.2 H~~ | Done | 2026-02-25 |
| ~~High Contrast theme (WCAG AAA)~~ | ~~ROADMAP.md v0.3.2 C~~ | Done | 2026-02-25 |
| ~~Extract inline tests to `tests/` dirs~~ | ~~ROADMAP.md tech debt~~ | Done | 2026-02-25 |
| AUR/deb/rpm package building & upload | ROADMAP.md v1.0.0 | Medium | Specs ready |

### 4. v1.0.0 production readiness

| Item | Priority | Status |
|------|----------|--------|
| Security audit (internal: 53/53 complete) | Critical | Done — third-party review pending |
| Package distribution (deb, rpm, AUR) | High | Specs ready, build scripts created |
| Comprehensive user documentation | High | Man page + INSTALL.md done |
| Performance optimisation | Medium | Pending |

---

## Project Summary

**Linux System Hardener** is a comprehensive Linux security automation tool written in Rust:

- **11 Crates** (10 core + 1 Tauri app)
- **8 Security Plugins**: Kernel, SSH, Firewall, PAM, Services, Audit, Permissions, MAC
- **660 Passing Tests**
- **Multi-Distribution Support**: Debian, Red Hat, Arch, SUSE families
- **Current Version**: 1.2.1 (released to GitHub, GitLab, and AUR)
- **WASM Support**: GUI frontend compiles to `wasm32-unknown-unknown`

For version history and detailed feature tracking, see [ROADMAP.md](ROADMAP.md).
For coding standards, workflow, and conventions, see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Codebase Architecture

### Workspace Structure

```
/home/bakri/RustroverProjects/linux-system-hardener/
├── Cargo.toml (workspace root)
├── .cargo/config.toml       # WASM rustflags for getrandom
├── crates/
│   ├── hardener-types/      # WASM-compatible shared type definitions
│   ├── hardener-cli/        # CLI interface (entry point)
│   ├── hardener-core/       # Core scanning/execution engine
│   ├── hardener-plugins/    # 8 security hardening plugins
│   ├── hardener-scheduler/  # Daemon for scheduled scanning
│   ├── hardener-state/      # Checkpoint/audit trail (Ed25519 signed)
│   ├── hardener-compliance/ # PDF report generation (pdf feature)
│   ├── hardener-common/     # Shared utilities/errors
│   ├── hardener-distro/     # Distribution abstraction
│   └── hardener-ui/         # Leptos WASM frontend
├── src-tauri/               # Desktop application
├── docs/                    # Comprehensive documentation
└── scripts/                 # Utility scripts
```

### Crate Dependency Graph

```
hardener-cli (entry point)
  ├── hardener-core (engine)
  ├── hardener-plugins (scanners/appliers)
  ├── hardener-compliance (reporting)
  ├── hardener-scheduler (daemon)
  ├── hardener-state (audit trail)
  └── hardener-common (shared)

hardener-types (WASM-safe, no system deps)
  └── serde, chrono only

hardener-core
  ├── hardener-types
  ├── hardener-common
  └── hardener-state (optional)

hardener-plugins
  └── hardener-core

hardener-compliance
  ├── hardener-types
  ├── hardener-core (default-features = false)
  └── krilla (optional, pdf feature)

hardener-ui (WASM frontend)
  └── hardener-types (only!)

hardener-scheduler
  ├── hardener-core
  ├── hardener-plugins
  └── hardener-common
```

---

*This document is prepared for continuity between development sessions.*

**Last Updated**: 2026-07-01
