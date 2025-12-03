# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Configuration file support with layered loading (system → user → CLI → env vars)
- `HardenerConfig`, `GlobalConfig`, `PluginConfig` structs for configuration management
- `ConfigLoader` with multi-source config merging
- `PolicyException` support for documenting security deviations with audit trail
- `FindingPolicyException` field on `Finding` struct for policy annotation
- CLI flags: `--config`, `--audit`, `--compliance`, `--exit-code` for scan command
- Three scan modes: Default (annotated), Audit (pure), Compliance (violations only)
- Config paths: `/etc/linux-hardener/config.toml` (system), `~/.config/linux-hardener/config.toml` (user)
- Interactive report wizard with `--interactive` flag for guided report generation
- CSV and HTML output format support in CLI report command
- `dialoguer` dependency for interactive terminal prompts
- PDF report formatter with professional multi-page layout and embedded fonts (NotoSans)
- Automatic timestamped PDF filenames (`compliance-report-YYYYMMDD-HHMMSS.pdf`)
- Colour-coded status badges in PDF reports (PASS=green, FAIL=red, PARTIAL=amber)
- `krilla` dependency for PDF generation
- Full compliance framework names in report titles (e.g., "CIS Benchmark" instead of "CIS")
- `full_name()` and `description()` methods on `ComplianceFramework` enum
- Improved PDF findings formatting: bold 10pt text, proper indentation, spacing after FAIL rows
- GUI compliance report page with framework selection and report generation
- Tauri command `generate_compliance_report` for GUI integration
- Compliance page route `/compliance` with navigation link

### Changed
- Test suite expanded from 220 to 320+ tests (45% increase)
- PDF findings now display with better visual hierarchy and spacing
- All 8 plugins converted to async with `#[async_trait]`
- HardeningPlugin trait methods now async: `scan()`, `apply()`, `rollback()`, `validate()`

### Added (v0.3.0 Features)
- **SSH Remote Scanning**: Scan, apply, and rollback on remote hosts via SSH
- `SystemExecutor` trait for abstracting local/remote operations
- `LocalExecutor` implementation (wraps std::fs and std::process)
- `SshExecutor` implementation (uses openssh crate for remote operations)
- `MockExecutor` implementation for unit testing without filesystem access
- CLI SSH flags: `--ssh`, `--ssh-key`, `--ssh-port`, `--ssh-timeout`, `--ssh-no-verify`
- `SshConnectionConfig` helper for CLI argument parsing
- SSH remote scanning user guide (`docs/SSH_REMOTE_SCANNING.md`)
- Context now holds executor via `ctx.executor()` accessor
- 94 new mock-based unit tests for plugin testing
- SSH integration tests (Docker-compatible)
- `testing.rs` module with `MockPlugin` builder for test infrastructure
- **Scheduled Scanning (Phase 1)**: Foundation for scheduled security scans
- `hardener-scheduler` crate with configuration, SQLite storage, and JSON output
- `SchedulerConfig` structs for TOML configuration
- `ScanHistoryManager` for SQLite scan history storage
- `JsonStore` for timestamped JSON file output with SHA-256 integrity hashing

### Documentation
- Added `docs/SSH_REMOTE_SCANNING.md` - comprehensive user guide for SSH remote scanning

### CI/CD Status
- GitHub Actions CI/CD workflows exist but are not currently connected to repository
- Manual releases recommended via `./scripts/release.sh` until resolved

## [0.1.0] - 2025-11-25

### Added

#### Core Infrastructure
- Plugin trait system for modular security checks
- Plugin manager with dependency resolution and topological sorting
- Distribution detection (Debian, Red Hat, Arch, SUSE families)
- Package manager abstraction (apt, dnf, pacman, zypper)
- Checkpoint system with SQLite storage
- Ed25519 cryptographic signatures for checkpoints
- Hash chain audit logging with tamper detection
- Full plugin rollback integration with checkpoint system

#### Security Plugins (8 Total)
- **Kernel Hardening**: 12 sysctl security parameters (ASLR, ptrace, dmesg, etc.)
- **SSH Hardening**: 8 SSH configuration directives with secure defaults
- **Firewall Hardening**: firewalld/nftables/ufw backend support
- **PAM Hardening**: Password policies and authentication configuration
- **Services Minimisation**: Disable unnecessary services
- **Audit Hardening**: auditd configuration and rules
- **Permissions Hardening**: File permission security checks
- **MAC Hardening**: SELinux/AppArmor detection and status

#### Command Line Interface
- `hardener scan` - Scan system for security issues
- `hardener apply` - Apply hardening recommendations
- `hardener report` - Generate compliance reports
- `hardener checkpoint` - Manage system checkpoints
- `hardener plugins` - List available plugins
- Severity filtering and JSON output support

#### Compliance Report Generation
- **CIS Benchmark** framework (35+ controls)
- **STIG** framework - DISA Security Technical Implementation Guides (20+ controls)
- **NIST 800-53** framework - US Federal security controls (20+ controls)
- **PCI-DSS v4.0** framework - Payment Card Industry standards (20+ controls)
- **HIPAA** Security Rule framework (15+ controls)
- **GDPR** Article 32 framework (12+ controls)
- Output formats: Text, JSON, CSV, HTML

#### User Interface
- Tauri-based desktop application
- Leptos (Rust) frontend with reactive state
- Dashboard with security score
- Scanner page with real-time progress
- Configuration page for plugin selection
- Results page with severity filtering
- Checkpoints page for rollback management

#### Developer Tools
- Naming convention validator script
- Pre-commit hook for validation
- Comprehensive test suite (220 tests)

### Security
- Disabled unused sqlx database backends (mysql, postgres) to reduce attack surface

### Test Coverage
- 48 plugin tests
- 59 core infrastructure tests
- 113 new unit/integration tests added
- >90% code coverage

### Known Limitations
- Some hardening requires system reboot
- SELinux/AppArmor policies detected but not fully managed
- Certain checks require root privileges
- Wayland/GBM issues on some Linux configurations

### Dependencies
- Rust 1.75+
- Tauri 2.0
- Leptos 0.8
- SQLite (via sqlx)
- tokio async runtime

---

## Version History

- **0.1.0** (2025-11-25): Initial development release

[Unreleased]: https://github.com/tidynest/linux-system-hardener/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tidynest/linux-system-hardener/releases/tag/v0.1.0
