# Next Development Session — Linux System Hardener

---

## Current State (as of 2026-06-19)

**v1.0.5 released.** All major features complete. Since v1.0.3: edition 2024
(v1.0.4) and a security dependency pass (v1.0.5 — `tauri` 2.11.2, `lettre`
0.11.22, `rustls-webpki` 0.103.13; cargo-deny gate added).

**Open audit finding (2026-06-19):** compliance reporting only *automatically
assesses* CIS — every plugin tags findings with CIS control IDs only, so STIG,
NIST, PCI-DSS, HIPAA and GDPR reports previously showed 100% compliance on any
system. Phase-1 fix landed (unassessed controls now report `ManualReview`, not
`Pass`); phase-2 (real multi-framework mappings) is the top open task below.

### Completed milestones:

- **All 13 audit bugs fixed** (BUG-01 through BUG-13) — see `docs/COMPREHENSIVE_AUDIT_REPORT.md`
- **All 7 infrastructure issues resolved** (INFRA-01 through INFRA-07)
- **Trait refactor complete** — `Config` unit struct deleted, `HardeningPlugin` trait now accepts `&PluginConfig`
- **Cross-distro validation** — 123-test suite passes on Arch, Debian, Fedora, Rocky Linux 9, openSUSE
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
- **514+ unit tests pass**, clippy clean, native + WASM builds clean

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

> Refreshed 2026-06-19 from a full state + online-currency audit. Items are open
> unless marked Done.

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
- **HIPAA/GDPR confidence** — those mappings are interpretive (GDPR Art.32 / project TM-* scheme; HIPAA §164); review for accuracy when convenient.
- **CIS catalogue hygiene** — 4 CIS ids the plugins emit (`1.6.1`, `5.2.14–16`) are not in the curated `cis.rs` catalogue, so they only appear when they fail. Add them to the catalogue (or fold CIS into the derive path) for full Option-B `Pass` visibility.

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

Single-host remote SSH scanning is complete; multi-host is sequential-only. Add
host profiles, parallel scanning, trend history and regression alerts (see the
limitations table in `docs/SSH_REMOTE_SCANNING.md`).

### P3 — Maintenance / currency

| Item | Detail | Status |
|------|--------|--------|
| Distro validation refresh | Re-validate on Debian 13, Fedora 44, RHEL 10, openSUSE Leap 16 (Leap 15 reached EOL April 2026) | ⬜ Pending |
| `tauri` 2.11.2 → 2.11.3 | Latest patch (2026-06-17); no CVE, routine bump | ⬜ Pending |
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
- **514+ Passing Tests**
- **Multi-Distribution Support**: Debian, Red Hat, Arch, SUSE families
- **Current Version**: 1.0.5 (Production Release)
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

**Last Updated**: 2026-06-19
