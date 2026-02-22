# Next Development Session — Linux System Hardener

> **For the next assistant**: Read all markdown files and your memory carefully before starting. Here's the current state.

**Legend**: ⬜ Pending | 🔄 In Progress | ✅ Complete

---

## What happened last session (2026-02-22)

All 13 bugs from the comprehensive audit (`docs/COMPREHENSIVE_AUDIT_REPORT.md`) are now **fully fixed and committed**. The entire GUI→CLI apply pipeline is working. Build is clean.

### Key commits:
```
9d091cf docs: mark BUG-09, BUG-10, BUG-11 as fixed in audit report
2eb1b3c fix(cli): use system checkpoint path when running as root        ← BUG-11
64d9f74 fix(plugins): use executor abstraction for PAM file writes       ← BUG-10
037d0c4 fix(tauri): improve CLI binary discovery for development builds  ← BUG-09
8757db5 docs: update audit report with fix status markers
0d55037 fix(cli,tauri): fix sshd_config typo and timestamp formatting    ← BUG-12, BUG-13
b9ce945 fix(core,ui): repair GUI apply pipeline and add preview flow     ← BUG-01–07
```

### All 13 audit bugs fixed:

| Bug | Summary | Commit |
|-----|---------|--------|
| BUG-01 | JSON shape mismatch CLI↔Tauri (tuple vs flat array) | `b9ce945` |
| BUG-02 | camelCase→snake_case param names in Tauri bindings | `b9ce945` |
| BUG-03 | GUI errors invisible — added error banner component | `b9ce945` |
| BUG-04 | UFW matched `rule_description` instead of `rule_action` | `b9ce945` |
| BUG-05 | Firewall hardcoded `apply_success: true` | `b9ce945` |
| BUG-06 | CLI apply always exited 0 — now tracks failures | `b9ce945` |
| BUG-07 | Apply used empty `Config` — now loads `HardenerConfig` | `b9ce945` |
| BUG-08 | Nested tokio runtime panic in rollback | `bb124a5` |
| BUG-09 | Binary discovery — added `CARGO_MANIFEST_DIR` fallback | `037d0c4` |
| BUG-10 | PAM bypassed executor — now uses `ctx.executor().write_file()` | `64d9f74` |
| BUG-11 | Checkpoint path divergence — root uses `/var/lib`, GUI reads both | `2eb1b3c` |
| BUG-12 | `sshd.config` typo → `sshd_config` | `0d55037` |
| BUG-13 | Timestamp Debug format → chrono human-readable | `0d55037` |

**Build status**: `cargo check`, `cargo check -p hardener-ui --target wasm32-unknown-unknown`, `cargo test`, and `cargo clippy` all pass clean.

---

## What's next (priority order)

### 1. 🔄 Infrastructure issues (INFRA-01 through INFRA-07)

See `docs/COMPREHENSIVE_AUDIT_REPORT.md` § TIER 3 for full details.

| Issue | Description | Complexity | Status |
|-------|-------------|------------|--------|
| INFRA-01 | All uncommitted work committed | — | ✅ Done |
| INFRA-02 | SSH auth failing to GitHub/GitLab remotes | Config fix | ⬜ |
| INFRA-03 | Version mismatch (0.3.2 vs 0.3.3 across files) | Find & replace | ⬜ |
| INFRA-04 | GUI/Tauri crates excluded from CI | `.github/workflows/ci.yml` | ⬜ |
| INFRA-05 | Four overlapping planning docs consolidated | — | ✅ Done |
| INFRA-06 | Tauri CSP disabled, no capabilities file | `tauri.conf.json` | ⬜ |
| INFRA-07 | Workspace dependency inconsistencies | `Cargo.toml` files | ⬜ |

### 2. ⬜ Trait refactor: `Config` → `HardenerConfig`

`HardeningPlugin::apply()` and `validate()` accept an empty `Config` unit struct. Should accept `HardenerConfig` so plugins can read per-plugin directives (enabled/disabled, custom settings, policy exceptions). Requires updating:
- `crates/hardener-core/src/plugin.rs` — trait definition
- All 8 plugin implementations in `crates/hardener-plugins/src/*/mod.rs`
- `crates/hardener-cli/src/commands/apply.rs` — pass `HardenerConfig` instead of `Config`

### 3. ⬜ GUI/CLI Feature Parity (Phase 2+)

See `docs/GUI_CLI_PARITY_PLAN.md` — Phase 1 (preview & apply) is complete.
- Phase 2: Scan filtering (severity dropdown, plugin selection) ← **next GUI work**
- Phase 3: Checkpoint management (create/delete)
- Phase 4: Report export (format selection, file save)
- Phase 5: Scan history tab
- Phase 6: Audit/compliance mode toggles

---

## Project Summary

**Linux System Hardener** is a comprehensive Linux security automation tool written in Rust:

- **10 Core Crates + 1 Tauri App**
- **8 Security Plugins**: Kernel, SSH, Firewall, PAM, Services, Audit, Permissions, MAC
- **396+ Passing Tests**
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
