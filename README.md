<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <img src="docs/assets/logo.svg" alt="Linux System Hardener" height="72">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/tidynest/linux-system-hardener/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/tidynest/linux-system-hardener/ci.yml?branch=main&style=flat-square&label=CI&labelColor=134e4a" alt="CI status"></a>
  <img src="https://img.shields.io/badge/version-1.2.2-0f766e?style=flat-square&labelColor=134e4a" alt="Version 1.2.2">
  <img src="https://img.shields.io/badge/license-Apache--2.0-0f766e?style=flat-square&labelColor=134e4a" alt="License Apache-2.0">
  <img src="https://img.shields.io/badge/rust-1.85%2B-0f766e?style=flat-square&labelColor=134e4a&logo=rust&logoColor=white" alt="Rust 1.85+">
  <img src="https://img.shields.io/aur/version/linux-system-hardener?style=flat-square&logo=archlinux&logoColor=white&label=AUR&color=0f766e&labelColor=134e4a" alt="AUR package">
  <img src="https://img.shields.io/badge/platform-Linux-0f766e?style=flat-square&labelColor=134e4a&logo=linux&logoColor=white" alt="Platform Linux">
  <img src="https://img.shields.io/badge/tests-750%2B%20passing-0d9488?style=flat-square&labelColor=134e4a" alt="750+ tests passing">
</p>

A comprehensive Linux security automation tool with multi-distribution support, built in Rust. Provides automated security scanning, hardening, and compliance reporting with full rollback capabilities.

> New here? Start with the [getting started guide](docs/guide/getting-started.md).
> The full documentation index lives at [docs/README.md](docs/README.md).

---

## Screenshots

<p align="center">
  <img src="docs/assets/screenshots/dashboard.png" alt="System Security Dashboard: security score and quick actions" width="820">
</p>
<p align="center">
  <img src="docs/assets/screenshots/analysis-findings.png" alt="Security Analysis: findings colour-coded by severity" width="49%">
  <img src="docs/assets/screenshots/hardening.png" alt="System Hardening: security profiles and per-plugin control" width="49%">
</p>

<p align="center"><sub>Desktop app (Tauri + Leptos) on the Midnight Teal theme: Dashboard, Security Analysis, and System Hardening from a live host scan.</sub></p>

---

## Contents

- [Overview](#overview)
- [Features](#features)
- [Project Status](#project-status)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Configuration](#configuration)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)

---

## Overview

Linux System Hardener automates the process of securing Linux servers and workstations by:

- **Scanning** systems for security misconfigurations
- **Applying** hardening recommendations automatically
- **Rolling back** changes safely using checkpoint snapshots
- **Reporting** compliance status against CIS, STIG, NIST 800-53, PCI-DSS,
  HIPAA, GDPR, ISO/IEC 27001:2022, SOC 2 (Trust Services Criteria),
  NIST SP 800-171 Revision 3 (Controlled Unclassified Information) and
  FedRAMP (Moderate Rev 5 baseline of 800-53 controls).
  Findings are mapped to each framework's
  controls (controls the engine cannot automatically assess are flagged for
  manual review rather than assumed compliant). RHEL-10-family hosts are
  assessed against DISA RHEL 10 STIG V1R1 and CIS RHEL 10 Benchmark v1.0.1
  identifiers automatically (`--profile` overrides)

The tool is designed for system administrators, DevOps engineers, and security professionals who need to maintain secure Linux infrastructure at scale.

---

## Features

### Security Plugins (8 Implemented)

| Plugin | Description | Status |
|--------|-------------|--------|
| **Kernel Hardening** | sysctl security parameters (ASLR, ptrace, etc.) | ✅ |
| **SSH Hardening** | OpenSSH configuration security | ✅ |
| **Firewall Hardening** | nftables/firewalld/ufw rule management | ✅ |
| **PAM Authentication Hardening** | Pluggable Authentication Modules | ✅ |
| **Service Minimisation** | Disable unnecessary services | ✅ |
| **Audit Rules Hardening** | auditd rules and configuration | ✅ |
| **File Permissions Hardening** | File permission security | ✅ |
| **MAC System Hardening** | SELinux/AppArmor configuration | ✅ |

<sub>✅ = complete</sub>

### Core Infrastructure

- **Checkpoint System**: SQLite-backed state snapshots with Ed25519 cryptographic signatures
- **Full Rollback Support**: All plugins integrate with checkpoint system for safe rollback
- **Hash Chain Audit Logging**: Tamper-evident audit trail with cryptographic linking
- **Plugin Manager**: Dependency-aware plugin execution with topological sorting
- **Distribution Detection**: Automatic detection of Debian, Red Hat, Arch, and SUSE families

### Multi-Distribution Support

| Distribution | Package Manager | Init System | Status |
|--------------|-----------------|-------------|--------|
| Ubuntu 22.04 LTS+ (incl. 26.04) | apt | systemd | ✅ |
| Debian 12+ (incl. 13 "Trixie") | apt | systemd | ✅ |
| Fedora 40+ (incl. 44) | dnf | systemd | ✅ |
| RHEL 9+ (incl. 10) | dnf | systemd | ✅ |
| Arch Linux (rolling) | pacman | systemd | ✅ |
| openSUSE Leap 15.6 / 16, Tumbleweed | zypper | systemd | ✅ |

<sub>✅ = supported</sub>

> Support is **family-based**: detection maps any release of the Debian, Red Hat,
> Arch or SUSE families to the same hardening behaviour, so current releases
> (Debian 13, Ubuntu 26.04, Fedora 44, RHEL 10, openSUSE Leap 16) are covered
> automatically. openSUSE Leap 15.x reached end-of-life in April 2026; use Leap
> 16. See [docs/reference/distribution-validation.md](docs/reference/distribution-validation.md) for
> the specific versions last validated end-to-end.

### User Interface

- **Desktop Application**: Tauri-based native app with Leptos (Rust) frontend
- **Web Interface**: Runs in browser via Trunk (WASM)
- **Dark Terminal Theme**: Professional security-focused aesthetic with colour-coded severity states (7 themes including WCAG AAA High Contrast)
- **Keyboard Navigation**: Full keyboard control: Ctrl+1-5 (pages), Alt+T (themes), Escape (close), F11 (fullscreen), Arrow keys (tabs and grids)
- **ARIA Accessibility**: WAI-ARIA tabs, skip link, `aria-selected`, `aria-live` regions, focus management
- **Progressive Disclosure**: Simple overview with drill-down for details
- **Real-time Feedback**: Live scan progress and results
- **Multi-host Fleet View** (desktop): A read-only **Fleet** page scans several
  saved inventory hosts concurrently and shows each host's severity posture
  (per-host critical/high/medium/low/info tallies and a colour-coded CIS
  compliance score) and expands to reveal that host's findings plus a
  per-framework compliance breakdown (pass/fail/manual/NA counts).

---

## Project Status

**Current Phase**: Production Release (v1.2.2)

### Test Coverage

```
Rust workspace:  750+ passed · 0 failed · 38 ignored   (>90% coverage)
GUI / desktop:   113 Playwright (Web UI, 5 distros) · 95 desktop (UX + functional) · 21 Node.js
```

### Build Status

- Workspace compiles without warnings
- All clippy lints pass
- rustfmt applied consistently

---

## Architecture

Workspace crate dependencies, grouped by layer. Every crate also depends on
`hardener-common` and `hardener-types`; those edges are omitted for clarity.
Dotted edges are an optional feature or WASM bundling rather than a Cargo
dependency.

```mermaid
graph TD
    subgraph binaries [Binaries]
        CLI["hardener-cli<br>(CLI binary)"]
        DESKTOP["linux-hardener-desktop<br>(Tauri backend)"]
        UI["hardener-ui<br>(Leptos/WASM frontend)"]
    end
    subgraph domain [Domain]
        PLUGINS["hardener-plugins<br>(8 security plugins)"]
        COMPLIANCE["hardener-compliance<br>(10 frameworks)"]
        SCHEDULER["hardener-scheduler<br>(scan daemon)"]
        CORE["hardener-core<br>(plugin trait, executors)"]
        STATE["hardener-state<br>(checkpoints, audit log)"]
        DISTRO["hardener-distro<br>(distribution detection)"]
    end
    subgraph foundation [Foundation]
        COMMON["hardener-common<br>(shared utilities)"]
        TYPES["hardener-types<br>(WASM-safe shared types)"]
    end

    CLI --> PLUGINS & COMPLIANCE & SCHEDULER & CORE & STATE & DISTRO
    DESKTOP --> PLUGINS & COMPLIANCE & SCHEDULER & CORE & STATE & DISTRO
    COMPLIANCE --> PLUGINS & CORE & DISTRO
    PLUGINS --> CORE & STATE
    SCHEDULER --> CORE
    CORE -. "optional (system feature)" .-> STATE
    DESKTOP -. "bundles prebuilt WASM dist" .-> UI
    COMMON --> TYPES
```

<details>
<summary>Directory layout</summary>

```
linux-system-hardener/
├── crates/
│   ├── hardener-types/       # WASM-compatible shared type definitions
│   ├── hardener-common/      # Shared utilities and error types
│   ├── hardener-core/        # Plugin trait, context, config system
│   ├── hardener-distro/      # Distribution detection and adaptation
│   ├── hardener-plugins/     # Security plugin implementations (8 plugins)
│   ├── hardener-state/       # Checkpoint manager, audit logging
│   ├── hardener-compliance/  # Compliance framework mapping (10 frameworks)
│   ├── hardener-scheduler/   # Scheduled scanning daemon
│   ├── hardener-cli/         # Command-line interface binary
│   └── hardener-ui/          # Leptos WASM frontend components
├── src-tauri/                # Tauri backend (desktop app)
├── scripts/                  # Development and testing utilities
└── docs/                     # Project documentation
```

</details>

### Key Design Principles

- **Security First**: Runs with minimum necessary privileges, comprehensive input validation
- **Safe by Default**: All changes are reversible via checkpoint system
- **Distribution Agnostic**: Abstracted package managers, init systems, and MAC frameworks
- **Modular Architecture**: Plugins are independent and can be developed/tested in isolation

---

## Getting Started

### Install from AUR (Arch Linux)

```bash
# Using an AUR helper (e.g. paru, yay)
paru -S linux-system-hardener

# Or manually
git clone https://aur.archlinux.org/linux-system-hardener.git
cd linux-system-hardener
makepkg -si
```

This installs both the `hardener` CLI and the `linux-hardener-desktop` GUI application.
For Fedora, RHEL, Debian, Ubuntu, and openSUSE packages, a static binary, or an
install from source, see the [installation guide](docs/guide/installation.md).

### Run with Docker (scan and report only)

A minimal `FROM scratch` image carrying only the static `hardener` binary can
audit the host read-only:

```bash
# Build from the repository root
docker build -f packaging/docker/Dockerfile -t linux-system-hardener .

# Read-only scan of the host's config surface
docker run --rm --pid=host \
  -v /etc:/etc:ro -v /var/log:/var/log:ro -v /usr/lib:/usr/lib:ro \
  linux-system-hardener scan --format json
```

Scan and report run read-only against the mounted host state.
`systemctl`/D-Bus-dependent checks (services, parts of audit/MAC/firewall)
degrade to tool-unavailable findings rather than lying, and `apply` is
unsupported in a container by design: it would need `--privileged` plus host
namespaces, defeating the isolation. Details in
[`packaging/docker/README.md`](packaging/docker/README.md).

### Building from Source

Requires Rust 1.85+ with the `wasm32-unknown-unknown` and
`x86_64-unknown-linux-musl` targets, plus a `musl` toolchain for the static CLI
binary. Quick build:

```bash
git clone https://github.com/tidynest/linux-system-hardener.git
cd linux-system-hardener
cargo build --release      # all crates (CLI plus libraries)
cargo test                 # workspace test suite
```

The complete build, cross-compilation, desktop/GUI, and development-mode
instructions live in [docs/contributing/building.md](docs/contributing/building.md).
Documentation-sync, validation, and release helpers are documented in
[scripts/README.md](scripts/README.md).

### Safe Root Testing

The hardener modifies critical system files. For safe testing with root privileges, use the provided container scripts:

```bash
# 1. Create isolated Arch Linux container (systemd-nspawn)
sudo ./scripts/containers/create-container.sh arch

# 2. Enter container (project mounted at /project)
sudo ./scripts/containers/create-container.sh arch enter

# 3. Inside container: build and run tests
cd /project
cargo build --release

# Run safe tests (read-only + dry-run)
sudo ./scripts/test/root-test-suite.sh

# Run full tests INCLUDING apply + rollback
sudo ./scripts/test/root-test-suite.sh --apply

# 4. Exit and clean up
poweroff                                       # Exit container
sudo ./scripts/containers/create-container.sh arch clean  # Remove container
```

**Why two test modes?**

| Test | Without `--apply` | With `--apply` |
|------|-------------------|----------------|
| Scans, reports, daemon, history | Runs | Runs |
| Apply hardening + rollback | Skipped | Runs |

The `--apply` flag explicitly enables destructive tests. Without it, only read-only tests run. This prevents accidentally modifying configs. **Inside the container, both modes are completely safe** since it's isolated from your host system.

**GUI tests** can be run separately or alongside CLI tests:

```bash
# Run 113 Playwright Web UI tests across all 5 distros
sudo ./scripts/test/gui/run-gui-tests.sh

# Or combine with CLI tests using the --gui flag
sudo ./scripts/test/run-cross-distro-tests.sh --apply --gui
```

See [docs/reference/distribution-validation.md](docs/reference/distribution-validation.md) for full test documentation.

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

The commands you will use most:

```bash
hardener plugins                        # List available security plugins
hardener scan                           # Scan the system for security issues
hardener scan --format json             # Machine-readable scan output
hardener report --framework cis         # Compliance report (10 frameworks)
sudo hardener apply --dry-run --all     # Preview hardening without changing anything
sudo hardener apply --all               # Apply all recommended hardening
hardener checkpoint list                # List rollback checkpoints
sudo hardener rollback <checkpoint-id>  # Roll back to a checkpoint
hardener history list                   # Recent scan sessions
```

The remaining surface at a glance (every command and flag is documented in
the [CLI reference](docs/reference/cli.md)):

```bash
# Checkpoints: create, inspect, prune
sudo hardener checkpoint create "before-hardening"
hardener checkpoint show <checkpoint-id>
hardener checkpoint delete <checkpoint-id>

# History: sessions, per-host trends, CI regression gate
hardener history show <session-id>
hardener history export <session-id> --output export.json
hardener history trends --host web-01
hardener history regressions            # Exit 1 when any host got worse
hardener --quiet history regressions    # Script-friendly quiet output

# Scheduled scanning: daemon and systemd timer
hardener daemon start                   # Blocks; run-once and status also available
hardener daemon run-once
hardener daemon status
hardener systemd generate               # Print unit files
sudo hardener systemd install           # Daily timer (or --user)
hardener systemd status
sudo hardener systemd uninstall

# Remote and fleet operations over SSH
hardener --ssh admin@server --ssh-key ~/.ssh/id_ed25519 scan
hardener --config /etc/linux-hardener/config.toml scan
hardener batch scan --all               # Every inventory host, concurrently
hardener batch report --all --framework cis
hardener batch apply --all              # Dry-run by default; add --execute
sudo hardener batch rollback --host web-01,web-02 --plugin ssh --execute
```

`batch apply` and `batch rollback` are **dry-run by default**: they validate
and preview without changing anything until `--execute` is given, and every
host is privilege-probed first so an unprivileged host fails in isolation.
Remote details: [SSH remote scanning](docs/guide/ssh-remote-scanning.md).
Fleet host inventory: `~/.config/linux-hardener/hosts.toml`
([configuration reference](docs/reference/configuration.md)).

### Desktop Application

1. Launch the application
2. Click "Run Security Scan" to analyse your system
3. Review findings by severity (Critical, High, Medium, Low, Info)
4. Select hardening recommendations to apply
5. Click "Apply Selected" (requires root password)
6. Use "Checkpoints" to rollback if needed

**Keyboard shortcuts:**

| Shortcut | Action |
|----------|--------|
| Ctrl+1-5 | Navigate to Dashboard/Analysis/Hardening/Remote/Scheduler |
| Alt+T | Cycle through themes |
| Escape | Close detail panels, exit fullscreen |
| F11 | Toggle fullscreen |
| Arrow keys | Navigate tab bars and findings grid |
| Enter/Space | Open finding detail |

The desktop app has seven pages. `Ctrl+1`-`5` cover the first five (Dashboard,
Analysis, Hardening, Remote, Scheduler); the two multi-host pages, **Fleet**
(read-only fleet scan) and **Fleet Apply** (apply/roll back across hosts), are
reached from the navigation bar and have no dedicated shortcut yet.

---

## Configuration

Configuration is loaded from multiple sources (later overrides earlier):

1. **System config**: `/etc/linux-hardener/config.toml`
2. **User config**: `~/.config/linux-hardener/config.toml`
3. **CLI config**: `--config /path/to/file.toml`
4. **Environment**: `HARDENER_*` variables

```toml
# ~/.config/linux-hardener/config.toml

[global]
disabled_plugins = ["mac-hardening"]

# Document accepted deviations with an audit trail
[ssh.exceptions.PasswordAuthentication]
value = "yes"
allowed = true
reason = "Legacy LDAP integration until Q2 2027 migration"
expires = "2027-06-30"
```

Three scan modes interact with the config: default (`hardener scan`,
findings with policy annotations), audit (`hardener scan --audit`, config
ignored), and compliance (`hardener scan --compliance`, only violations
without a valid exception).

Every section, key, default, and the scheduler/inventory files are
documented in the
[configuration reference](docs/reference/configuration.md).

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

- Follow naming conventions in [docs/reference/naming-conventions.md](docs/reference/naming-conventions.md)
- All code must pass `cargo clippy` without warnings
- Maintain >90% test coverage for new code
- Use British English in documentation and user-facing text

---

## Roadmap

Milestones, both completed (v0.2.0 through v1.2.0) and planned, live in
[docs/ROADMAP.md](docs/ROADMAP.md).

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

**Last Updated**: 2026-07-18
