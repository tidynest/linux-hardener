# Linux System Hardener

**Author**: Eric Jingryd
**Version**: 0.3.2 (Development Release)
**License**: Apache-2.0

A comprehensive Linux security automation tool with multi-distribution support, built in Rust. Provides automated security scanning, hardening, and compliance reporting with full rollback capabilities.

---

## Overview

Linux System Hardener automates the process of securing Linux servers and workstations by:

- **Scanning** systems for security misconfigurations
- **Applying** hardening recommendations automatically
- **Rolling back** changes safely using checkpoint snapshots
- **Reporting** compliance status against security frameworks

The tool is designed for system administrators, DevOps engineers, and security professionals who need to maintain secure Linux infrastructure at scale.

---

## Features

### Security Plugins (8 Implemented)

| Plugin | Description | Status |
|--------|-------------|--------|
| **Kernel Hardening** | sysctl security parameters (ASLR, ptrace, etc.) | Complete |
| **SSH Hardening** | OpenSSH configuration security | Complete |
| **Firewall Hardening** | nftables/firewalld/ufw rule management | Complete |
| **PAM Authentication Hardening** | Pluggable Authentication Modules | Complete |
| **Service Minimisation** | Disable unnecessary services | Complete |
| **Audit Rules Hardening** | auditd rules and configuration | Complete |
| **File Permissions Hardening** | File permission security | Complete |
| **MAC System Hardening** | SELinux/AppArmor configuration | Complete |

### Core Infrastructure

- **Checkpoint System**: SQLite-backed state snapshots with Ed25519 cryptographic signatures
- **Full Rollback Support**: All plugins integrate with checkpoint system for safe rollback
- **Hash Chain Audit Logging**: Tamper-evident audit trail with cryptographic linking
- **Plugin Manager**: Dependency-aware plugin execution with topological sorting
- **Distribution Detection**: Automatic detection of Debian, Red Hat, Arch, and SUSE families

### Multi-Distribution Support

| Distribution | Package Manager | Init System | Status |
|--------------|-----------------|-------------|--------|
| Ubuntu 22.04+ | apt | systemd | Supported |
| Debian 12+ | apt | systemd | Supported |
| Fedora 39+ | dnf | systemd | Supported |
| RHEL 9+ | dnf | systemd | Supported |
| Arch Linux | pacman | systemd | Supported |
| openSUSE Leap 15.5+ | zypper | systemd | Supported |

### User Interface

- **Desktop Application**: Tauri-based native app with Leptos (Rust) frontend
- **Web Interface**: Runs in browser via Trunk (WASM)
- **Dark Terminal Theme**: Professional security-focused aesthetic with colour-coded severity states
- **Progressive Disclosure**: Simple overview with drill-down for details
- **Real-time Feedback**: Live scan progress and results

---

## Project Status

**Current Phase**: Development Release (v0.3.0)

### Test Coverage

```
Total Tests: 378+ passing
├── Plugin Tests: 48 + 80 mock tests
├── Core Tests: 59 + 14 mock executor tests
├── Compliance Tests: 46
├── State Tests: 31
├── Scheduler Tests: 57 (daemon, runner, notifications, systemd)
├── CLI Tests: 25
├── Distro Tests: 13
├── SSH Integration Tests: 24
└── Coverage: >90%
```

### Build Status

- Workspace compiles without warnings
- All clippy lints pass
- rustfmt applied consistently

---

## Architecture

```
linux-system-hardener/
├── crates/
│   ├── hardener-core/        # Plugin trait, context, checkpoint system
│   ├── hardener-common/      # Shared utilities and error types
│   ├── hardener-types/       # WASM-compatible shared type definitions
│   ├── hardener-distro/      # Distribution detection and adaptation
│   ├── hardener-plugins/     # Security plugin implementations
│   ├── hardener-state/       # Checkpoint manager, audit logging
│   ├── hardener-compliance/  # Compliance framework mapping
│   ├── hardener-scheduler/   # Scheduled scanning daemon
│   └── hardener-ui/          # Leptos WASM frontend components
├── src-tauri/                # Tauri backend (desktop app)
├── scripts/                  # Development utilities
└── docs/                     # Project documentation
```

### Key Design Principles

- **Security First**: Runs with minimum necessary privileges, comprehensive input validation
- **Safe by Default**: All changes are reversible via checkpoint system
- **Distribution Agnostic**: Abstracted package managers, init systems, and MAC frameworks
- **Modular Architecture**: Plugins are independent and can be developed/tested in isolation

---

## Getting Started

### Prerequisites

- Rust 1.75+ (with `wasm32-unknown-unknown` target for UI)
- Linux system (for full functionality)
- Root access (for applying hardening changes)

### Build from Source

```bash
# Clone repository
git clone https://github.com/tidynest/linux-system-hardener.git
cd linux-system-hardener

# Build all crates
cargo build --release

# Run tests
cargo test

# Build desktop application (requires Tauri CLI)
cargo install tauri-cli
cargo tauri build
```

### Development Setup

```bash
# Install development dependencies
rustup target add wasm32-unknown-unknown
cargo install trunk

# Run desktop app in development mode (requires polkit for privilege escalation)
cargo tauri dev

# On Wayland (Hyprland, Sway, etc.), use this workaround:
WEBKIT_DISABLE_COMPOSITING_MODE=1 cargo tauri dev

# Run web UI in development mode (browser - no Tauri required)
cd crates/hardener-ui && trunk serve --port 1420
# Open http://127.0.0.1:1420/ in your browser

# Browser automation via Playwright MCP (recommended for UI testing)
# Configure playwright-brave in .mcp.json, then use mcp__playwright-brave__browser_navigate
# See docs/browser-automation.md for complete setup instructions
```

### Development Workflow Commands

```bash
# Validate documentation is in sync with code
./scripts/validate_all.py           # Full validation
./scripts/validate_all.py --quick   # Fast check (skips slow validators)

# Auto-fix documentation (safe, idempotent)
./scripts/update_all_docs.py        # Preview changes
./scripts/update_all_docs.py --apply # Apply changes

# Check naming conventions
./scripts/validate_naming.py

# Release workflow
./scripts/release.sh --verify       # Check version consistency
./scripts/release.sh patch --dry-run # Preview release
./scripts/release.sh patch          # Actual release
```

See [scripts/README.md](scripts/README.md) for complete script documentation.

### Safe Root Testing

The hardener modifies critical system files. For safe testing with root privileges, use the provided container scripts:

```bash
# 1. Create isolated Arch Linux container (systemd-nspawn)
sudo ./scripts/create-test-container.sh

# 2. Enter container (project mounted at /project)
sudo ./scripts/create-test-container.sh enter

# 3. Inside container: build and run tests
cd /project
cargo build --release

# Run safe tests (read-only + dry-run)
sudo ./scripts/root-test-suite.sh

# Run full tests INCLUDING apply + rollback
sudo ./scripts/root-test-suite.sh --apply

# 4. Exit and clean up
poweroff                                       # Exit container
sudo ./scripts/create-test-container.sh clean  # Remove container
```

**Why two test modes?**

| Test | Without `--apply` | With `--apply` |
|------|-------------------|----------------|
| Scans, reports, daemon, history | ✅ Runs | ✅ Runs |
| Apply hardening + rollback | ⏭️ Skipped | ✅ Runs |

The `--apply` flag explicitly enables destructive tests. Without it, only read-only tests run. This prevents accidentally modifying configs. **Inside the container, both modes are completely safe** since it's isolated from your host system.

See [docs/CLI_V032_TEST_RESULTS.md](docs/CLI_V032_TEST_RESULTS.md) for full test documentation.

#### Web App vs Desktop App

The web app runs in any browser without needing Tauri installed:

| Feature | Web App (Browser) | Desktop App (Tauri) |
|---------|-------------------|---------------------|
| Run security scans | ❌ UI only | ✅ Full functionality |
| Apply hardening | ❌ UI only | ✅ With pkexec |
| Generate reports | ❌ UI only | ✅ Full functionality |
| Navigate pages | ✅ Works | ✅ Works |
| Dark terminal theme | ✅ Works | ✅ Works |

The web app is useful for UI development and testing. All pages render with proper empty states.

---

## Usage

### Command Line

```bash
# List available security plugins
hardener plugins

# Scan system for security issues
hardener scan

# Scan with severity filter (critical, high, medium, low, info)
hardener scan --severity high

# Scan specific plugins only (full ID or short name)
hardener scan --plugin kernel-hardening --plugin ssh-hardening
hardener scan --plugin kernel --plugin ssh  # Short names also work

# Output as JSON
hardener scan --format json

# Use custom config file
hardener scan --config /path/to/config.toml

# Audit mode - ignore all config, pure security assessment
hardener scan --audit

# Compliance mode - only show policy violations (no valid exception)
hardener scan --compliance

# CI/CD mode - exit with code 1 if findings exist
hardener scan --compliance --exit-code

# Interactive report wizard
hardener report --interactive

# Generate report in different formats
hardener report --framework cis --report-format html --output report.html
hardener report --framework cis --report-format csv --output report.csv

# Dry-run: see what would be changed without applying
sudo hardener apply --dry-run --all

# Apply all recommended hardening
sudo hardener apply --all

# Apply specific plugin
sudo hardener apply --plugin kernel-hardening

# Create a checkpoint before making changes
sudo hardener checkpoint create "before-hardening"

# List all checkpoints
hardener checkpoint list

# Show checkpoint details
hardener checkpoint show <checkpoint-id>

# Rollback to a previous checkpoint
sudo hardener rollback <checkpoint-id>

# View scan history (list recent sessions)
hardener history list

# View history with filters
hardener history list --limit 50 --status completed
hardener history list --host server1

# Show details of a specific scan session
hardener history show <session-id>

# Export scan session to JSON file
hardener history export <session-id>
hardener history export <session-id> --output /path/to/export.json

# Start the scheduled scanning daemon
hardener daemon start

# Run a single scan immediately (without scheduler)
hardener daemon run-once

# Show scheduler status and scan history
hardener daemon status

# Generate systemd unit files (outputs to stdout)
hardener systemd generate

# Generate with custom schedule (cron or systemd calendar format)
hardener systemd generate --schedule "0 2 * * *"

# Install systemd timer (requires root for system, or use --user)
sudo hardener systemd install
hardener systemd install --user

# Check systemd timer status
hardener systemd status

# Remove systemd timer
sudo hardener systemd uninstall
```

### SSH Remote Scanning

```bash
# Scan a remote host
hardener --ssh user@hostname scan

# Scan with specific SSH key
hardener --ssh admin@192.168.1.100 --ssh-key ~/.ssh/id_ed25519 scan

# Apply hardening remotely
sudo hardener --ssh root@server apply --all

# Generate compliance report from remote host
hardener --ssh root@server report --framework cis --format pdf
```

See [docs/SSH_REMOTE_SCANNING.md](docs/SSH_REMOTE_SCANNING.md) for complete SSH documentation.

### Desktop Application

1. Launch the application
2. Click "Run Security Scan" to analyse your system
3. Review findings by severity (Critical, High, Medium, Low, Info)
4. Select hardening recommendations to apply
5. Click "Apply Selected" (requires root password)
6. Use "Checkpoints" to rollback if needed

---

## Configuration

### Config File Locations

Configuration is loaded from multiple sources (later overrides earlier):

1. **System config**: `/etc/linux-hardener/config.toml`
2. **User config**: `~/.config/linux-hardener/config.toml`
3. **CLI config**: `--config /path/to/file.toml`
4. **Environment**: `HARDENER_*` variables

### Basic Configuration

```toml
# ~/.config/linux-hardener/config.toml

[global]
# Plugins to explicitly disable
disabled_plugins = ["mac"]

[ssh]
enabled = true

[kernel]
enabled = true
```

### Policy Exceptions

Document deviations from secure baseline with audit metadata:

```toml
[ssh.exceptions.PasswordAuthentication]
value = "yes"
allowed = true
reason = "Legacy LDAP integration until Q2 2025 migration"
approved_by = "security-team@company.com"
approved_date = "2024-11-01"
ticket = "SEC-1234"
expires = "2025-06-30"
```

### Scan Modes

- **Default** (`hardener scan`): Shows all findings with policy annotations
- **Audit** (`hardener scan --audit`): Ignores config, pure security assessment
- **Compliance** (`hardener scan --compliance`): Only shows policy violations

### Checkpoint Location

By default, checkpoints are stored in:
```
~/.local/share/linux-hardener/checkpoints.db
```

---

## Security Considerations

### Privilege Model

- **Scanning**: Runs as regular user where possible
- **Applying Changes**: Requires root privileges
- **Checkpoint Storage**: User-owned SQLite database with signed entries

### Threat Model

This tool is designed to harden systems against:
- Kernel-level exploits (via sysctl hardening)
- Network attacks (via firewall configuration)
- Privilege escalation (via PAM and permission hardening)
- Lateral movement (via service minimisation)
- Audit evasion (via comprehensive logging)

### Known Limitations

- Changes require system reboot to fully take effect in some cases
- Some hardening may break specific applications (test in staging first)
- SELinux/AppArmor policies are detected but not fully managed

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Standards

- Follow naming conventions in [docs/NAMING_CONVENTIONS.md](docs/NAMING_CONVENTIONS.md)
- All code must pass `cargo clippy` without warnings
- Maintain >90% test coverage for new code
- Use British English in documentation and user-facing text

---

## Roadmap

See [PLAN.md](PLAN.md) for detailed implementation plans for upcoming features.

### v0.2.0 (Complete)
- [x] Config file support (`~/.config/linux-hardener/`)
- [x] CLI flags: `--config`, `--audit`, `--compliance`, `--exit-code`
- [x] Policy exception system with audit trail
- [x] Interactive report wizard (`hardener report --interactive`)
- [x] CSV and HTML format support in CLI
- [x] PDF report formatter with automatic timestamped filenames and colour-coded badges
- [x] GUI compliance report page

### v0.3.0 (Complete)
- [x] SystemExecutor abstraction layer for local/remote operations
- [x] Remote scanning via SSH
- [x] SSH CLI flags: `--ssh`, `--ssh-key`, `--ssh-port`, `--ssh-timeout`, `--ssh-no-verify`
- [x] MockExecutor for unit testing
- [x] All plugins converted to async
- [x] SSH remote scanning documentation
- [x] Scheduled scanning daemon with tokio-cron-scheduler
- [x] CLI daemon commands: `start`, `run-once`, `status`
- [x] Notifications (email via SMTP, webhooks for Slack/Discord/generic)
- [x] Systemd timer generation (`hardener systemd generate/install/uninstall/status`)
- [x] History CLI commands (`hardener history list/show/export`)
- [x] WASM compilation fix (hardener-types crate for WASM-safe dependencies)
- [x] GUI dark terminal theme with CSS styling
- [x] Browser mode support (Web UI works without Tauri desktop wrapper)
- [x] CI/CD GitHub Actions integration
- [x] Ansible/Puppet modules

### v0.3.1 - GUI Polish & Testing (Complete)
- [x] Fix "Loading..." text persistence
- [x] GUI dark terminal theme with CSS Variables
- [x] Security score shows "--/100" before scan
- [x] Fix View Findings button styling
- [x] State persistence via SQLite storage
- [x] Browser mode fix (Tauri availability check)
- [x] Timestamp formatting on Checkpoints page
- [x] Background colour personalisation (5 security-focused themes)
- [x] Responsive layout for varying screen resolutions
- [x] Navigation restructure (3 pages: Dashboard, Analysis, Hardening)
- [x] GUI functional testing
- [x] CLI functional testing (30 tests, 100% pass rate)
- [x] Safe testing environment (systemd-nspawn container)

### v0.3.2 - GUI Major Redesign (Complete)
- [x] Page consolidation (6 pages → 3 logical sections: Dashboard, Analysis, Hardening)
- [x] Session 1: Overflow fixes, skip link, tab ARIA accessibility
- [x] Session 2: CSS utility classes (flex/grid/gap), responsive testing (320-1920px)
- [x] Session 2: Card component standardisation
- [x] Session 3: Colour contrast audit (WCAG AA), theme switching UI
- [x] Session 4: Empty states, CSS transitions, hover animations, E2E tests
- [x] Backend integration (Tauri commands connected)
- [x] Root privilege escalation via pkexec
- [x] Bug fixes: Security score calculation, false positives, validate() stubs, kernel rollback
- [ ] Test on GNOME, KDE, XFCE desktop environments

### v0.3.3 - Distribution Validation (Planned)
- [ ] Arch Linux validation
- [ ] Debian/Ubuntu validation
- [ ] RHEL/Fedora validation
- [ ] openSUSE validation

### v0.4.0 - Web Interface (Future)
- [ ] Web dashboard for browser-based management
- [ ] Multi-host management from single UI
- [ ] Historical security trends
- [ ] Alert notifications on security regressions

### v1.0.0 - Production Release (Future)
- [ ] Security audit completed
- [ ] Package distribution (deb, rpm, AUR)
- [ ] Comprehensive user documentation
- [ ] Performance optimisation

---

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

---

## Acknowledgements

This project draws inspiration from established security tools including:
- [Lynis](https://cisofy.com/lynis/) - Security auditing tool
- [OpenSCAP](https://www.open-scap.org/) - Security compliance toolkit
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) - Security configuration standards

---

**Author**: Eric Jingryd
**Contact**: tidynest@proton.me
**Repository**: https://github.com/tidynest/linux-system-hardener

**Last Updated**: 2025-12-10
