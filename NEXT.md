# Next Development Session — Linux System Hardener

---

## Current State (as of 2026-02-24)

All major audit items are resolved. Live testing session uncovered and fixed 6 additional issues.

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
- **418+ unit tests pass**, clippy clean, native + WASM builds clean

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

| Item | Source | Priority |
|------|--------|----------|
| ~~JSON output for `checkpoint rollback` command~~ | ~~ROADMAP.md v0.3.2 H~~ | Done (`5167e5a`) |
| Polkit policy file for nicer dialog text | ROADMAP.md v0.3.2 H | Low |
| AUR/deb/rpm package dependencies | ROADMAP.md v1.0.0 | Low |
| High Contrast theme (WCAG AAA) | ROADMAP.md v0.3.2 C | Low |
| Extract inline tests to `tests/` dirs | ROADMAP.md tech debt | Low |

### 4. v1.0.0 production readiness

| Item | Priority |
|------|----------|
| Security audit (third-party review) | Critical |
| Package distribution (deb, rpm, AUR) | High |
| Comprehensive user documentation | High |
| Performance optimisation | Medium |

---

## Project Summary

**Linux System Hardener** is a comprehensive Linux security automation tool written in Rust:

- **11 Crates** (10 core + 1 Tauri app)
- **8 Security Plugins**: Kernel, SSH, Firewall, PAM, Services, Audit, Permissions, MAC
- **418+ Passing Tests**
- **Multi-Distribution Support**: Debian, Red Hat, Arch, SUSE families
- **Current Version**: 0.3.3 (Development Release)
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

**Last Updated**: 2026-02-24
