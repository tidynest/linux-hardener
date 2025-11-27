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

---

## In Progress

### v0.2.0 - CLI & Reporting Enhancements

| Feature | Status | Priority |
|---------|--------|----------|
| Config file support (`~/.config/linux-hardener/`) | ✅ Complete | Medium |
| CLI flags: `--config`, `--audit`, `--compliance`, `--exit-code` | ✅ Complete | Medium |
| Policy exception system with audit trail | ✅ Complete | Medium |
| Interactive report wizard | ✅ Complete | Medium |
| CSV and HTML format support in CLI | ✅ Complete | Low |
| PDF report formatter | ✅ Complete | Low |
| GUI compliance report page | ✅ Complete | Medium |

---

## Planned Features

### v0.3.0 - Remote & Automation

| Feature | Description | Priority |
|---------|-------------|----------|
| Remote scanning via SSH | Scan remote hosts without installing | High |
| Scheduled scanning | Cron-like scheduled security checks | Medium |
| CI/CD integration | Exit codes and machine-readable output | Medium |
| Ansible/Puppet modules | Integration with config management | Low |

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
| ~~Increase test coverage~~ | ~~Target 90%+ coverage~~ | ✅ Complete (220 tests) |
| Framework descriptions in reports | Add `description()` as subtitle in compliance reports | Low |
| SELinux/AppArmor policy management | Full policy editing, not just detection | Low |
| ISO 27001 framework | Add ISO 27001 compliance controls | Low |

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
