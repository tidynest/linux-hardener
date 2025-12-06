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

### v0.3.0 - WASM Compilation Fix ✅

**Completed 2025-12-05**

- [x] Created `hardener-types` crate with WASM-safe dependencies (serde, chrono only)
- [x] Extracted shared types from hardener-common, hardener-core, hardener-compliance
- [x] Feature-gated krilla PDF library behind `pdf` feature in hardener-compliance
- [x] Updated hardener-ui to depend only on hardener-types
- [x] Added `.cargo/config.toml` for getrandom WASM backend configuration
- [x] Added `#[wasm_bindgen(start)]` entry point for Leptos app mounting
- [x] GUI compiles to `wasm32-unknown-unknown` and runs in Tauri

See [docs/WASM_FIX_PLAN.md](docs/WASM_FIX_PLAN.md) for implementation details.

### v0.3.1 - GUI Polish & Testing

| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| Fix "Loading..." text | Remove loading placeholder after app mounts | High | ✅ Complete |
| GUI styling/CSS | Improve visual design and user experience | High | ✅ Complete |
| Fix security score default | Show "--/100" before scan instead of "100/100" | High | ✅ Complete |
| Fix View Findings button | Use button instead of hyperlink styling | Medium | ✅ Complete |
| **State persistence bug** | Scan results now persist across navigation and app restarts via SQLite | Critical | ✅ Complete |
| **Browser mode fix** | Web UI now renders correctly without Tauri (added `tauri_available()` check) | Critical | ✅ Complete |
| Timestamp formatting | Format raw timestamp numbers on Checkpoints page | Medium | ✅ Complete |
| Background personalisation | Make background colour more personable/warm | Low | Pending |
| Responsive layout | Support varying screen/browser resolutions | Medium | Pending |
| Navigation restructure | Evaluate merging Configuration/Compliance into Scanner | Low | Pending |
| GUI functional testing | Verify all GUI features work correctly | High | In Progress |
| CLI functional testing | Verify all CLI commands work correctly | High | Pending |
| Safe testing environment | Test in VM/container to avoid system changes | Critical | Pending |

**v0.3.1 Completed Items (2025-12-05/06):**
- Fixed "Loading..." text persistence by mounting app to `#app` element
- Added dark terminal theme with CSS Variables, JetBrains Mono + Inter fonts
- Security score now shows "--/100" before scan with "Run a scan to see your score"
- "View Findings" now uses styled button with programmatic navigation
- All 6 pages styled: Dashboard, Scanner, Configuration, Compliance, Results, Checkpoints
- Timestamp formatting: Checkpoints page now shows human-readable dates
- **(2025-12-06)** Browser mode fix: Added `tauri_available()` check in `tauri_bindings.rs`
  - Web UI now renders all pages correctly without Tauri desktop wrapper
  - Commands return graceful errors in browser mode instead of crashing Leptos

**Completed (2025-12-05):**
- State persistence: Scan results now persist via `scan_sessions`, `scan_results`, `scan_findings` tables
- GUI loads latest scan results on mount via `get_latest_scan` Tauri command
- 4 unit tests for `ScanHistoryManager` all passing
- Full integration test passed (8/8 Web UI tests, database verification complete)

**Testing Requirements:**
- All testing MUST be done in a safe, isolated environment (VM or container)
- Tests must not modify the host system
- Both CLI and GUI (Desktop + Browser) need verification
- Arch Linux (LTS) specific: Ensure scan findings are relevant to Arch, not false positives from other distro-specific checks

### v0.3.2 - GUI Major Redesign & Comprehensive Testing

This version focuses on making the GUI fully functional, intuitive, and thoroughly tested.

#### A. Page Architecture Redesign

| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| Page consolidation | Reduce 6 pages to 3 logical sections | High | In Progress |
| Workflow-oriented design | Guide users through scan → configure → apply → verify flow | High | In Progress |
| State management overhaul | Ensure all changes persist across navigation | Critical | Pending |
| Backend integration | Connect GUI actions to actual Tauri commands | Critical | ✅ Complete |

**Final Page Structure (3 Pages):**

| Page | Route | Purpose | Contains |
|------|-------|---------|----------|
| **Dashboard** | `/` | Overview & quick start | SecurityScore, QuickActions, RecentActivity |
| **Analysis** | `/analysis` | Scan & compliance (tabbed) | [Findings] tab + [Compliance] tab with shared header |
| **Hardening** | `/hardening` | Configure & history (sectioned) | [Configure] + [History] sections with apply/rollback |

**Analysis Page Tabs:**
- **Findings Tab**: FindingsGrid + FindingDetail (from ScannerPage)
- **Compliance Tab**: Framework selection + ReportCard (from CompliancePage)
- Shared header with MiniSecurityScore and unified "Run Scan" button
- Animated tab transitions with gradient underline indicator

**Hardening Page Sections:**
- **Configure Section**: Profile presets, plugin toggles, apply button
- **History Section**: Apply results summary + checkpoint table with rollback

**Implementation Phases:**

| Phase | Components | Status |
|-------|------------|--------|
| Phase 1 | tabs.rs, mini_security_score.rs, recent_activity.rs | Pending |
| Phase 2 | findings_tab.rs, compliance_tab.rs, analysis_page.rs | Pending |
| Phase 3 | configure_section.rs, history_section.rs, hardening_page.rs | Pending |
| Phase 4 | Update router (lib.rs) and state (state/mod.rs) | Pending |
| Phase 5 | CSS additions for tabs/sections | ✅ Complete |
| Phase 6 | Delete old files (scanner_page, compliance_page, etc.) | Pending |

**State Updates Required:**
```rust
// Add to AppState
pub analysis_active_tab: RwSignal<usize>,      // 0=Findings, 1=Compliance
pub hardening_active_section: RwSignal<usize>, // 0=Configure, 1=History
pub checkpoints: RwSignal<Vec<CheckpointInfo>>,
pub is_loading_checkpoints: RwSignal<bool>,
```

#### B. User Guidance & UX

| Feature | Description | Priority |
|---------|-------------|----------|
| Contextual help text | Short, friendly explanations on every page section | High |
| Workflow indicators | Visual cues showing recommended order of actions | High |
| Tooltips & info icons | Hover explanations for technical terms and settings | Medium |
| Empty state guidance | Helpful prompts when no data exists (e.g., "Run your first scan") | Medium |
| Progress indicators | Clear feedback during scans, applies, and other operations | High |
| Error messages | User-friendly error text with suggested fixes | High |

**User Guidance Principles:**
- Every page section should have a brief, friendly heading explaining what it does
- Users should understand "what to do next" at a glance
- Technical jargon should be minimised or explained inline
- Recommended settings should be clearly indicated
- Dangerous actions should have clear warnings and confirmations

#### C. Comprehensive GUI Testing

| Test Category | Description | Priority |
|---------------|-------------|----------|
| **Unit tests** | Test individual components in isolation | High |
| **Integration tests** | Test component interactions and state flow | High |
| **E2E tests (Web)** | Puppeteer/Playwright tests for browser UI | Critical |
| **E2E tests (Desktop)** | Tauri test harness for desktop app | Critical |
| **State persistence tests** | Verify data survives navigation and refresh | Critical |
| **Backend communication tests** | Verify Tauri commands execute correctly | Critical |
| **Error handling tests** | Verify graceful degradation on failures | High |
| **Responsive layout tests** | Verify UI works at various resolutions | Medium |
| **Accessibility tests** | Keyboard navigation, screen reader compatibility | Medium |

**Testing Infrastructure Needs:**
- Leptos component testing framework setup
- Puppeteer/Playwright test suite for Web UI
- Tauri test mode for Desktop app
- Mock backend for isolated frontend testing
- CI/CD integration for automated test runs
- Test coverage reporting

#### D. Backend Integration

| Feature | Description | Priority |
|---------|-------------|----------|
| Scan execution | Connect "Run Scan" to actual Tauri scan command | Critical |
| Apply hardening | Connect "Apply" buttons to Tauri apply command | Critical |
| Checkpoint creation | Create checkpoints before applying changes | Critical |
| Rollback functionality | Connect rollback to Tauri rollback command | Critical |
| Real-time progress | WebSocket or polling for scan/apply progress | High |
| Error propagation | Surface backend errors to UI properly | High |

#### E. Root Privilege Escalation for GUI

Security scans and hardening operations require root privileges to access system files and configurations. The GUI apps (both Web and Desktop) need a mechanism to execute privileged operations safely.

**Privilege Requirements by Operation:**

| Operation | Requires Root | Reason |
|-----------|---------------|--------|
| Scanning | Partial | Most scans work without root; some checks (e.g., `/etc/shadow`) need elevated access |
| Apply hardening | Yes | Modifies system config files (`/etc/sysctl.conf`, `/etc/ssh/sshd_config`, etc.) |
| Rollback | Yes | Restores system config files from checkpoints |
| Delete checkpoint | No | Checkpoints stored in user-local database |

**Approach Comparison:**

| Approach | Description | Pros | Cons |
|----------|-------------|------|------|
| **Polkit integration** | Use `pkexec` to prompt for password and run privileged operations | Standard Linux privilege escalation, user-friendly prompts | Requires polkit agent running, may not work in all DEs |
| **Privileged daemon** | Separate systemd service running as root, GUI communicates via Unix socket | Most secure, persistent connection, can enforce authorization policies | More complex architecture, needs IPC implementation |
| **Sudo wrapper** | Call `sudo` or `pkexec` for individual operations | Simple implementation | Prompts for each operation, may time out |
| **Capabilities-based** | Grant specific Linux capabilities (e.g., `CAP_DAC_READ_SEARCH`) to binary | Fine-grained permissions, no password prompts | Complex capability management, not all operations supported |

**Chosen Approach**: pkexec with graceful error handling

##### Implementation Architecture

```
User clicks "Apply"
        │
        ▼
┌───────────────────────┐
│ Tauri command         │
│ run_apply_privileged  │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│ Spawn pkexec process: │
│ pkexec /path/hardener │
│   apply --plugin X    │
│   --output json       │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────────────────────┐
│ Polkit auth agent shows password      │
│ dialog (polkit-gnome, kde-agent, etc) │
└───────────┬───────────────────────────┘
            │
     ┌──────┴──────┬────────────┐
     │             │            │
     ▼             ▼            ▼
  Success      Cancelled    No Agent
     │             │            │
     ▼             ▼            ▼
  Parse JSON    Show msg    Show install
  results       "Cancelled"  instructions
     │
     ▼
  Update GUI
```

##### Error Handling & User Guidance

**If polkitd not running:**
```
Polkit is required for privilege escalation but isn't running.

Install with:
  Arch:   sudo pacman -S polkit
  Debian: sudo apt install policykit-1
  Fedora: sudo dnf install polkit

Then restart your session.
```

**If no auth agent running:**
```
A Polkit authentication agent is required to show the password prompt.

Install one with:
  Arch:   sudo pacman -S polkit-gnome
  Debian: sudo apt install policykit-1-gnome
  Fedora: sudo dnf install polkit-gnome

Then add to your window manager startup:
  exec /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1
```

**If user cancels password dialog:**
```
Authentication cancelled. Root privileges are required to apply hardening changes.
```

##### Dependency Handling

**Development/Manual Installs:**
- Detect missing polkit components at runtime
- Show clear installation instructions per distro
- Optionally offer to open terminal with install command

**Package Distribution (AUR, deb, rpm):**
- Declare `polkit` as package dependency
- Recommend `polkit-gnome` or equivalent as optional dependency
- Package manager handles installation automatically

##### Implementation Tasks

- [x] Add `check_polkit_availability()` function in Tauri commands ✅ **DONE (2025-12-06)**
- [x] Create `run_privileged_command()` helper that wraps pkexec ✅ **DONE (2025-12-06)**
- [x] Modify `run_apply` to use pkexec + CLI instead of in-process execution ✅ **DONE (2025-12-06)**
- [x] Modify `run_rollback` to use pkexec + CLI ✅ **DONE (2025-12-06)**
- [x] Add JSON output mode to CLI `apply` command (for machine-readable results) ✅ (already existed)
- [ ] Add JSON output mode to CLI `checkpoint rollback` command
- [x] Create user-friendly error messages for polkit failures ✅ **DONE (2025-12-06)**
- [x] Test on Hyprland (with polkit-gnome) ✅ **DONE (2025-12-06)**
- [ ] Test on GNOME, KDE, XFCE desktop environments
- [ ] (Optional) Create polkit policy file for nicer dialog text
- [ ] (Future) Add to AUR/deb/rpm package dependencies

**Tauri 2.x Critical Note:** Frontend argument keys MUST use camelCase (e.g., `pluginIds` not `plugin_ids`) to match Tauri 2.x's default serde configuration. The `wasm-bindgen` extern binding must include the `catch` attribute for proper Promise rejection handling.

### v0.3.3 - Distribution-Specific Validation

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

**Last Updated**: 2025-12-06
