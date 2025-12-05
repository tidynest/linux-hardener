# Development Roadmap

## Overview

This document tracks the development progress and planned features for Linux System Hardener.

---

## Completed Features

### v0.1.0 - Core Infrastructure ✅
- [x] Plugin system with dependency-aware execution
- [x] Checkpoint system with Ed25519 signatures
- [x] Hash chain audit logging
- [x] Distribution detection (Debian, Red Hat, Arch, SUSE)
- [x] Desktop application (Tauri + Leptos)
- [x] Full plugin rollback integration with checkpoint system

### Security Plugins (8/8 Complete) ✅
- [x] Kernel Hardening (sysctl parameters)
- [x] SSH Hardening (OpenSSH configuration)
- [x] Firewall Hardening (nftables/firewalld/ufw)
- [x] PAM Hardening (authentication modules)
- [x] Services Minimisation (disable unnecessary services)
- [x] Audit Hardening (auditd rules)
- [x] Permissions Hardening (file permissions)
- [x] MAC Hardening (SELinux/AppArmor)

### Compliance Report Generation ✅
- [x] CLI `report` command with direct mode
- [x] CIS Benchmark framework
- [x] STIG framework (DISA)
- [x] NIST 800-53 framework
- [x] PCI-DSS v4.0 framework
- [x] HIPAA Security Rule framework
- [x] GDPR Article 32 framework
- [x] Text output formatter
- [x] JSON output formatter
- [x] CSV output formatter
- [x] HTML output formatter
- [x] All plugins with compliance mappings

### v0.2.0 - CLI & Reporting Enhancements ✅
- [x] Config file support (`~/.config/linux-hardener/`)
- [x] CLI flags: `--config`, `--audit`, `--compliance`, `--exit-code`
- [x] Policy exception system with audit trail
- [x] Interactive report wizard
- [x] CSV and HTML format support in CLI
- [x] PDF report formatter
- [x] GUI compliance report page

---

## In Progress

### v0.3.0 - Remote & Automation

| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| Remote scanning via SSH | Scan remote hosts without installing | High | ✅ Complete |
| Scheduled scanning | Cron-like scheduled security checks | Medium | ✅ Complete |
| CI/CD integration | Exit codes and machine-readable output | Medium | ✅ Complete |
| Ansible/Puppet modules | Integration with config management | Low | Pending |

**v0.3.0 Progress - SSH Remote Scanning:**
- [x] SystemExecutor trait for abstracting file/command operations
- [x] LocalExecutor implementation (wraps current behaviour)
- [x] SshExecutor implementation (remote operations via SSH)
- [x] Context integration with executor
- [x] CLI flags (`--ssh`, `--ssh-key`, `--ssh-port`, `--ssh-timeout`, `--ssh-no-verify`)
- [x] Async plugin trait (`HardeningPlugin` with `#[async_trait]`)
- [x] All 8 plugins converted to async
- [x] Plugin tests converted to async (`#[tokio::test]`)
- [x] CLI commands updated with `.await`
- [x] Tauri commands updated with `.await`
- [x] Error handling (`HardeningError::Executor` variant)
- [x] SshConnectionConfig helper for CLI argument parsing
- [x] Wire SshExecutor in CLI (create executor from `--ssh` flag)
- [x] Executor passed through scan, apply, report commands
- [x] Plugin refactoring to use `ctx.executor()` calls ✅ **DONE (2025-12-01)**
- [x] MockExecutor for unit testing ✅ **DONE (2025-12-01)**
- [x] MockExecutor unit tests (14 tests) ✅
- [x] Plugin mock tests for all 8 plugins (80 tests) ✅
- [x] SSH integration tests ✅ **DONE (2025-12-01)**
- [x] SSH remote scanning documentation (user guide) ✅ **DONE (2025-12-01)**

**v0.3.0 Progress - Scheduled Scanning:**
- [x] `hardener-scheduler` crate skeleton
- [x] `SchedulerConfig` structs with serde (5 tests)
- [x] `ScanHistoryManager` SQLite storage (5 tests)
- [x] `JsonStore` timestamped JSON output (4 tests)
- [x] `ScanRunner` orchestrates plugin scans (7 tests) ✅ **DONE (2025-12-03)**
  - `TriggerType` enum (Scheduled, Manual, Systemd)
  - `ScanSummary` for notification payloads
  - Severity filtering with configurable threshold
  - Integration with `PluginManager`, `ScanHistoryManager`, `JsonStore`
  - Reuses `SeverityCounts` (no code duplication)
- [x] `Daemon` with tokio-cron-scheduler (4 tests) ✅ **DONE (2025-12-04)**
  - Cron-scheduled scans via `tokio-cron-scheduler`
  - Signal handling (SIGTERM, SIGINT) for graceful shutdown
  - Atomic scan guard to prevent overlapping scans
  - `run_once()` for manual/testing triggers
- [x] CLI `daemon` command ✅ **DONE (2025-12-04)**
  - `hardener daemon start` - starts scheduling daemon
  - `hardener daemon run-once` - single scan without scheduler
  - `hardener daemon status` - shows config and scan history
- [x] `Notifier` trait and `NotificationDispatcher` ✅ **DONE (2025-12-04)**
- [x] `EmailNotifier` (lettre SMTP) ✅ **DONE (2025-12-04)**
- [x] `WebhookNotifier` (Slack/Discord/generic) ✅ **DONE (2025-12-04)**
- [x] `SystemdGenerator` (.service/.timer templates) ✅ **DONE (2025-12-05)**
  - Generates `.service` and `.timer` unit files
  - Cron-to-systemd calendar expression conversion
  - Security hardening directives in service unit
- [x] CLI `systemd` commands ✅ **DONE (2025-12-05)**
  - `hardener systemd generate` - output unit files to stdout or directory
  - `hardener systemd install` - install and enable timer (system or user)
  - `hardener systemd uninstall` - disable and remove units
  - `hardener systemd status` - show timer/service status
- [x] CLI `history` commands ✅ **DONE (2025-12-05)**
  - `hardener history list` - list recent scan sessions with filtering
  - `hardener history show <id>` - display session details and findings
  - `hardener history export <id>` - export session to JSON file

### v0.3.1 - GUI Polish & Testing

| Feature | Description | Priority |
|---------|-------------|----------|
| Fix "Loading..." text | Remove loading placeholder after app mounts | High |
| GUI styling/CSS | Improve visual design and user experience | High |
| GUI functional testing | Verify all GUI features work correctly | High |
| CLI functional testing | Verify all CLI commands work correctly | High |
| Safe testing environment | Test in VM/container to avoid system changes | Critical |

**Testing Requirements:**
- All testing MUST be done in a safe, isolated environment (VM or container)
- Tests must not modify the host system
- Both CLI and GUI (Desktop + Browser) need verification
- Arch Linux (LTS) specific: Ensure scan findings are relevant to Arch, not false positives from other distro-specific checks

### v0.3.2 - Distribution-Specific Validation

| Feature | Description | Priority |
|---------|-------------|----------|
| Arch Linux validation | Verify all plugins work correctly on Arch (LTS) | High |
| Debian/Ubuntu validation | Verify all plugins work correctly on Debian family | High |
| RHEL/Fedora validation | Verify all plugins work correctly on Red Hat family | High |
| openSUSE validation | Verify all plugins work correctly on SUSE family | Medium |

**Validation Requirements:**
- Each distro family requires dedicated testing sessions
- Scan findings must be accurate for the target distro
- No false positives from distro-specific files/settings that don't exist
- Package manager integration must work correctly per distro
- Service management must use correct init system commands

### v0.4.0 - Web Interface

| Feature | Description | Priority |
|---------|-------------|----------|
| Web dashboard | Browser-based management interface | Medium |
| Multi-host management | Manage multiple systems from one UI | Medium |
| Historical trends | Track security posture over time | Low |
| Alert notifications | Email/webhook on security regressions | Low |

### v1.0.0 - Production Release

| Feature | Description | Priority |
|---------|-------------|----------|
| Security audit | Third-party security review | Critical |
| Package distribution | deb, rpm, AUR packages | High |
| Comprehensive documentation | User guide, API docs | High |
| Performance optimisation | Scan speed improvements | Medium |
| Internationalisation | Multi-language support | Low |

---

## Technical Debt & Improvements

| Item | Description | Priority |
|------|-------------|----------|
| ~~Increase test coverage~~ | ~~Target 90%+ coverage~~ | ✅ Complete (338+ tests) |
| ~~Consolidate `create_plugin_registry()`~~ | ~~Duplicated in CLI, report, Tauri~~ | ✅ Complete |
| ~~Consolidate test mock plugins~~ | ~~Duplicated in registry.rs and plugin_manager_tests.rs~~ | ✅ Complete |
| ~~Config file utilities~~ | ~~Duplicated parsing/backup in SSH and PAM plugins~~ | ✅ Complete |
| ~~Refactor PAM plugin~~ | ~~Updated to use shared `file_utils` functions~~ | ✅ Complete |
| ~~Package manager code duplication~~ | ~~Validation/execution duplicated in apt, dnf, zypper, pacman~~ | ✅ Complete |
| ~~Remove duplicate registry in plugins.rs~~ | ~~Removed from plugins.rs and apply.rs~~ | ✅ Complete |
| Review field naming consistency | Some structs have mixed prefix usage (see HANDOFF.md) | Low |
| Gate or remove `testing` feature | Feature defined but not used in hardener-core | Low |
| Extract inline tests to `tests/` dirs | Follow `hardener-plugins/tests/` pattern across all crates | Low |
| Framework descriptions in reports | Add `description()` as subtitle in compliance reports | Low |
| SELinux/AppArmor policy management | Full policy editing, not just detection | Low |
| ISO 27001 framework | Add ISO 27001 compliance controls | Low |

### Code Deduplication Completed ✅

**1. Plugin Registry Creation** ✅
- Consolidated into `hardener_plugins::create_plugin_registry()`
- Removed duplicates from scan.rs, report.rs, and commands.rs

**2. Test Mock Plugins** ✅
- Created `hardener-core/src/testing.rs` with `MockPlugin` builder
- Features: `.name()`, `.depends_on()`, `.category()`, `.fail_scan()`, `.fail_apply()`
- Removed ~330 lines of duplicate mock struct definitions

**3. Config File Utilities** ✅
- Added to `hardener-common/src/file_utils.rs`:
  - `read_config_file()`, `read_config_file_optional()`
  - `parse_config_value()` with `ConfigFormat` enum
  - `set_config_directive()`
  - `create_timestamped_backup()`
- SSH and PAM plugins refactored to use these utilities

**4. Package Manager Helpers** ✅
- Added to `hardener-distro/src/package/mod.rs`:
  - `PackageNameRules` enum (Debian, Rpm, Arch)
  - `validate_package_name()` - shared validation with distro-specific rules
  - `validate_package_names()` - batch validation helper
  - `execute_command()` - generic command runner with error handling
  - `parse_rpm_package_list()` - shared RPM output parser for dnf/zypper
- All 4 package managers (apt, dnf, zypper, pacman) refactored to use shared helpers
- Reduced ~190 lines of duplicate code

### Test Restructure (Recommended - Low Priority)

Move inline tests from source files to dedicated `tests/` directories:

```
crates/hardener-core/
├── src/
│   ├── plugin.rs           # No inline tests
│   ├── registry.rs         # Has inline tests (could be moved)
│   ├── testing.rs          # NEW: MockPlugin builder
│   └── ...
└── tests/
    ├── plugin_manager_tests.rs  # Already using MockPlugin
    └── ...
```

Benefits: Clear separation, consistency, better IDE support, parallel test execution.

---

## Architecture Notes

### CLI/GUI Code Sharing

The compliance module (`hardener-compliance`) is designed for reuse:

```
┌─────────────────────────────────────────────────────────────┐
│                    User Interfaces                          │
├─────────────────────────┬───────────────────────────────────┤
│   hardener-cli          │   hardener-ui (Tauri/Leptos)      │
│   - Terminal prompts    │   - GUI dialogs                   │
│   - Argument parsing    │   - Visual components             │
└───────────┬─────────────┴───────────────┬───────────────────┘
            │                             │
            ▼                             ▼
┌─────────────────────────────────────────────────────────────┐
│              hardener-compliance (Shared Logic)             │
│   - ReportGenerator                                         │
│   - Framework definitions (CIS, STIG, NIST, etc.)          │
│   - Output formatters (Text, JSON, CSV, HTML, PDF)         │
└─────────────────────────────────────────────────────────────┘
```

### Supported Compliance Frameworks

| Framework | Controls | Description |
|-----------|----------|-------------|
| CIS | 35+ | Center for Internet Security Benchmarks |
| STIG | 20+ | DISA Security Technical Implementation Guides |
| NIST 800-53 | 20+ | US Federal security controls |
| PCI-DSS | 20+ | Payment Card Industry standards |
| HIPAA | 15+ | Healthcare security requirements |
| GDPR | 12+ | EU data protection (Article 32) |

---

## Contributing

When working on new features:

1. Create a feature branch from `master`
2. Update this PLAN.md with your progress
3. Ensure all tests pass (`cargo test`)
4. Run `cargo clippy` with no warnings
5. Submit PR for review

**Legend**: ⬜ Pending | 🔄 In Progress | ✅ Complete
