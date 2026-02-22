# Next Development Session — Linux System Hardener

---

## Current State (as of 2026-02-22)

All major audit items are resolved. The codebase is clean and ready for feature work.

### Completed milestones:

- **All 13 audit bugs fixed** (BUG-01 through BUG-13) — see `docs/COMPREHENSIVE_AUDIT_REPORT.md`
- **All 7 infrastructure issues resolved** (INFRA-01 through INFRA-07)
- **Trait refactor complete** — `Config` unit struct deleted, `HardeningPlugin` trait now accepts `&PluginConfig`
- **Cross-distro validation** — 102-test suite passes on Arch, Debian, Fedora, openSUSE
- **381 unit tests pass**, clippy clean, native + WASM builds clean

### Trait refactor summary (commits `81c13ad`, `d029629`, `b87fb1c`):

- Core: deleted `Config`, trait methods accept `&PluginConfig`, `PluginManager` uses `&HardenerConfig`
- All 8 plugins updated to new trait signature
- SSH plugin is the **pilot**: fully consumes `config.directives` for overrides and `config.has_valid_exception()` for exemptions
- 35 test locations updated across 16 test files

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

### 1. Wire remaining 7 plugins to consume PluginConfig

The trait refactor is complete, but only the **SSH plugin** fully consumes `PluginConfig` directives and exceptions. The remaining 7 plugins accept `&PluginConfig` but ignore its contents. Each plugin should be wired one at a time to:

- Read `config.directives` for per-plugin setting overrides
- Check `config.has_valid_exception()` to skip rules with valid policy exceptions
- Respect `config.enabled` to short-circuit when disabled

**Plugins to wire** (recommended order, simplest first):

| Plugin | Key Directives | Complexity |
|--------|---------------|------------|
| Kernel | sysctl parameter overrides | Low |
| Permissions | custom file permission rules | Low |
| Services | service whitelist/blacklist | Low-Medium |
| Audit | custom auditd rules | Medium |
| PAM | module configuration overrides | Medium |
| Firewall | port/rule exceptions | Medium |
| MAC | SELinux/AppArmor policy overrides | Medium-High |

**Reference implementation**: `crates/hardener-plugins/src/ssh/mod.rs` — see how it reads directives and checks exceptions.

### 2. GUI/CLI Feature Parity (v0.4.0)

See `docs/GUI_CLI_PARITY_PLAN.md` — Phase 1 (dry-run preview) is complete.

| Phase | Feature | Priority | Status |
|-------|---------|----------|--------|
| Phase 2 | Scan filtering (severity dropdown, plugin selection) | P0 | Pending |
| Phase 3 | Checkpoint management (create/delete) | P1 | Pending |
| Phase 4 | Report export (format selection, file save) | P1 | Pending |
| Phase 5 | Scan history tab | P2 | Pending |
| Phase 6 | Audit/compliance mode toggles | P2 | Pending |

### 3. Remaining polish items

| Item | Source | Priority |
|------|--------|----------|
| JSON output for `checkpoint rollback` command | ROADMAP.md v0.3.2 H | Low |
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
- **381+ Passing Tests**
- **Multi-Distribution Support**: Debian, Red Hat, Arch, SUSE families
- **Current Version**: 0.3.3 (Development Release)
- **WASM Support**: GUI frontend compiles to `wasm32-unknown-unknown`

For version history and detailed feature tracking, see [ROADMAP.md](ROADMAP.md).
For coding standards, workflow, and conventions, see `.claude/CLAUDE.md`.

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

**Last Updated**: 2026-02-22
