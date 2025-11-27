# Linux System Hardener

**Author**: Eric Jingryd
**Version**: 0.1.0 (Development Release)
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
| **PAM Hardening** | Pluggable Authentication Modules | Complete |
| **Services Minimisation** | Disable unnecessary services | Complete |
| **Audit Hardening** | auditd rules and configuration | Complete |
| **Permissions Hardening** | File permission security | Complete |
| **MAC Hardening** | SELinux/AppArmor configuration | Complete |

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
- **Progressive Disclosure**: Simple overview with drill-down for details
- **Real-time Feedback**: Live scan progress and results

---

## Project Status

**Current Phase**: Development Release (v0.1.0)

### Test Coverage

```
Total Tests: 220 passing
├── Plugin Tests: 48
├── Core Tests: 59
├── Compliance Tests: 46
├── State Tests: 31
├── CLI Tests: 21
├── Distro Tests: 15
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
│   ├── hardener-common/      # Shared types (Severity, Finding, etc.)
│   ├── hardener-distro/      # Distribution detection and adaptation
│   ├── hardener-plugins/     # Security plugin implementations
│   ├── hardener-state/       # Checkpoint manager, audit logging
│   ├── hardener-compliance/  # Compliance framework mapping
│   └── hardener-ui/          # Leptos frontend components
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

# Run desktop app in development mode
cargo tauri dev
```

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

# Scan specific plugins only
hardener scan --plugin kernel-hardening --plugin ssh-hardening

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
sudo hardener checkpoint rollback <checkpoint-id>
```

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

### v0.2.0 (In Progress)
- [x] Config file support (`~/.config/linux-hardener/`)
- [x] CLI flags: `--config`, `--audit`, `--compliance`, `--exit-code`
- [x] Policy exception system with audit trail
- [x] Interactive report wizard (`hardener report --interactive`)
- [x] CSV and HTML format support in CLI
- [x] PDF report formatter with automatic timestamped filenames and colour-coded badges
- [x] GUI compliance report page

### v0.3.0 (Planned)
- [ ] Remote scanning via SSH
- [ ] Scheduled scanning
- [ ] CI/CD integration

### v1.0.0 (Future)
- [ ] Production-ready release
- [ ] Security audit completed
- [ ] Package distribution (deb, rpm, AUR)

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
