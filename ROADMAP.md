# Development Roadmap

## Overview

This document tracks the development progress and planned features for Linux System Hardener.

**Legend**: ⬜ Pending | 🔄 In Progress | ✅ Complete

---

## Completed Features

### v0.1.0 — Core Infrastructure ✅

- [x] Plugin system with dependency-aware execution
- [x] Checkpoint system with Ed25519 signatures
- [x] Hash chain audit logging
- [x] Distribution detection (Debian, Red Hat, Arch, SUSE)
- [x] Desktop application (Tauri + Leptos)
- [x] Full plugin rollback integration with checkpoint system

### v0.1.x — Security Plugins (8/8) ✅

- [x] Kernel Hardening (sysctl parameters)
- [x] SSH Hardening (OpenSSH configuration)
- [x] Firewall Hardening (nftables/firewalld/ufw)
- [x] PAM Hardening (authentication modules)
- [x] Services Minimisation (disable unnecessary services)
- [x] Audit Hardening (auditd rules)
- [x] Permissions Hardening (file permissions)
- [x] MAC Hardening (SELinux/AppArmor)

### v0.1.x — Compliance Report Generation ✅

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

### v0.2.0 — CLI & Reporting Enhancements ✅

- [x] Config file support (`~/.config/linux-hardener/`)
- [x] CLI flags: `--config`, `--audit`, `--compliance`, `--exit-code`
- [x] Policy exception system with audit trail
- [x] Interactive report wizard
- [x] CSV and HTML format support in CLI
- [x] PDF report formatter
- [x] GUI compliance report page

---

## In Progress

### v0.3.0 — Remote & Automation ✅

| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| Remote scanning via SSH | Scan remote hosts without installing | High | ✅ Complete |
| Scheduled scanning | Cron-like scheduled security checks | Medium | ✅ Complete |
| CI/CD integration | Exit codes and machine-readable output | Medium | ✅ Complete |

#### A. SSH Remote Scanning ✅

- [x] SystemExecutor trait for abstracting file/command operations
- [x] LocalExecutor implementation (wraps current behaviour)
- [x] SshExecutor implementation (remote operations via SSH)
- [x] Context integration with executor
- [x] CLI flags (`--ssh`, `--ssh-key`, `--port`, `--ssh-timeout`, `--ssh-no-verify`)
- [x] Async plugin trait (`HardeningPlugin` with `#[async_trait]`)
- [x] All 8 plugins converted to async
- [x] Plugin tests converted to async (`#[tokio::test]`)
- [x] CLI commands updated with `.await`
- [x] Tauri commands updated with `.await`
- [x] Error handling (`HardeningError::Executor` variant)
- [x] SshConnectionConfig helper for CLI argument parsing
- [x] Wire SshExecutor in CLI (create executor from `--ssh` flag)
- [x] Executor passed through scan, apply, report commands
- [x] Plugin refactoring to use `ctx.executor()` calls
- [x] MockExecutor for unit testing
- [x] MockExecutor unit tests (14 tests)
- [x] Plugin mock tests for all 8 plugins (80 tests)
- [x] SSH integration tests
- [x] SSH remote scanning documentation (user guide)

#### B. Scheduled Scanning ✅

- [x] `hardener-scheduler` crate skeleton
- [x] `SchedulerConfig` structs with serde (5 tests)
- [x] `ScanHistoryManager` SQLite storage (5 tests)
- [x] `JsonStore` timestamped JSON output (4 tests)
- [x] `ScanRunner` orchestrates plugin scans (7 tests)
  - `TriggerType` enum (Scheduled, Manual, Systemd)
  - `ScanSummary` for notification payloads
  - Severity filtering with configurable threshold
  - Integration with `PluginManager`, `ScanHistoryManager`, `JsonStore`
  - Reuses `SeverityCounts` (no code duplication)
- [x] `Daemon` with tokio-cron-scheduler (4 tests)
  - Cron-scheduled scans via `tokio-cron-scheduler`
  - Signal handling (SIGTERM, SIGINT) for graceful shutdown
  - Atomic scan guard to prevent overlapping scans
  - `run_once()` for manual/testing triggers
- [x] CLI `daemon` command
  - `hardener daemon start` — starts scheduling daemon
  - `hardener daemon run-once` — single scan without scheduler
  - `hardener daemon status` — shows config and scan history
- [x] `Notifier` trait and `NotificationDispatcher`
- [x] `EmailNotifier` (lettre SMTP)
- [x] `WebhookNotifier` (Slack/Discord/generic)
- [x] `SystemdGenerator` (.service/.timer templates)
  - Generates `.service` and `.timer` unit files
  - Cron-to-systemd calendar expression conversion
  - Security hardening directives in service unit
- [x] CLI `systemd` commands
  - `hardener systemd generate` — output unit files to stdout or directory
  - `hardener systemd install` — install and enable timer (system or user)
  - `hardener systemd uninstall` — disable and remove units
  - `hardener systemd status` — show timer/service status
- [x] CLI `history` commands
  - `hardener history list` — list recent scan sessions with filtering
  - `hardener history show <id>` — display session details and findings
  - `hardener history export <id>` — export session to JSON file

#### C. WASM Compilation Fix ✅

> Completed 2025-12-05

- [x] Created `hardener-types` crate with WASM-safe dependencies (serde, chrono only)
- [x] Extracted shared types from hardener-common, hardener-core, hardener-compliance
- [x] Feature-gated krilla PDF library behind `pdf` feature in hardener-compliance
- [x] Updated hardener-ui to depend only on hardener-types
- [x] Added `.cargo/config.toml` for getrandom WASM backend configuration
- [x] Added `#[wasm_bindgen(start)]` entry point for Leptos app mounting
- [x] GUI compiles to `wasm32-unknown-unknown` and runs in Tauri

> **Implementation Details**: WASM compilation fix completed (see git history)

---

### v0.3.1 — GUI Polish & Testing ✅

| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| Fix "Loading..." text | Remove loading placeholder after app mounts | High | ✅ Complete |
| GUI styling/CSS | Improve visual design and user experience | High | ✅ Complete |
| Fix security score default | Show "--/100" before scan instead of "100/100" | High | ✅ Complete |
| Fix View Findings button | Use button instead of hyperlink styling | Medium | ✅ Complete |
| State persistence bug | Scan results persist across navigation via SQLite | Critical | ✅ Complete |
| Browser mode fix | Web UI renders correctly without Tauri | Critical | ✅ Complete |
| Timestamp formatting | Format raw timestamp numbers on Checkpoints page | Medium | ✅ Complete |
| Background personalisation | 5 security-focused themes (Fortress, Sentinel, Command, Guardian, Daywatch) | Low | ✅ Complete |
| Responsive layout | Mobile-first responsive design | Medium | ✅ Complete |
| Navigation restructure | 5 pages (Dashboard, Analysis, Hardening, Remote, Scheduler) | Low | ✅ Complete |
| GUI functional testing | Verify all GUI features work correctly | High | ✅ Complete |
| CLI functional testing | Verify all CLI commands work (97 tests: 31 unit + 66 functional) | High | ✅ Complete |
| Safe testing environment | systemd-nspawn container with test scripts | Critical | ✅ Complete |

#### A. GUI Fixes (2025-12-05/06)

- [x] Fixed "Loading..." text persistence by mounting app to `#app` element
- [x] Added dark terminal theme with CSS Variables, JetBrains Mono + Inter fonts
- [x] Security score now shows "--/100" before scan with "Run a scan to see your score"
- [x] "View Findings" now uses styled button with programmatic navigation
- [x] All 3 pages styled: Dashboard, Analysis (tabbed), Hardening (sectioned)
- [x] Timestamp formatting: Checkpoints page now shows human-readable dates
- [x] Browser mode fix: Added `tauri_available()` check in `tauri_bindings.rs`
  - Web UI renders all pages correctly without Tauri desktop wrapper
  - Commands return graceful errors in browser mode instead of crashing Leptos

#### B. State Persistence (2025-12-05)

- [x] Scan results persist via `scan_sessions`, `scan_results`, `scan_findings` tables
- [x] GUI loads latest scan results on mount via `get_latest_scan` Tauri command
- [x] 4 unit tests for `ScanHistoryManager` all passing
- [x] Full integration test passed (8/8 Web UI tests, database verification complete)

#### C. Testing Infrastructure (2025-12-10)

- [x] Safe testing environment implemented using systemd-nspawn container
- [x] CLI functional test results: 27/27 tests pass
- [x] Root functional test results: 35/36 tests pass (1 skip is test script pattern matching)
- [x] Bug M fixed: Scheduler database now uses user path for non-root users

> **Test Results**: See [docs/DISTRIBUTION_VALIDATION.md](docs/DISTRIBUTION_VALIDATION.md)

**Root Test Highlights**:
- 47 findings as root (vs 11 as non-root) — plugins now have full access
- 26 audit findings visible with root access
- Kernel apply: changes applied, `kptr_restrict=2` verified
- All 6 compliance frameworks: reports generated
- PDF generation: 30KB PDF created

**Testing Scripts**:

| Script | Purpose |
|--------|---------|
| `scripts/create-test-container.sh` | Create/manage Arch Linux container |
| `scripts/root-test-suite.sh` | Comprehensive root test suite |
| `scripts/run-gui-tests.sh` | Web UI Playwright test orchestrator (5 distros) |
| `scripts/gui-test-inner.sh` | Container inner script (Xvfb + HTTP + Playwright; dynamically generates index.html from dist/) |
| `scripts/run-tauri-gui-tests.sh` | Tauri desktop test orchestrator |
| `scripts/tauri-gui-test-inner.sh` | Container inner script for Tauri desktop tests |

**Usage**:

```bash
sudo ./scripts/create-test-container.sh        # Create container
sudo ./scripts/create-test-container.sh enter  # Enter container
# Inside container (binary built on host is bind-mounted):
cd /project
sudo ./scripts/root-test-suite.sh              # Safe tests (read-only)
sudo ./scripts/root-test-suite.sh --apply      # Full tests (apply + rollback)
```

> **Note**: Destructive tests (apply hardening, rollback) require explicit `--apply` flag. Inside the container, both modes are completely safe since it's isolated from the host system.

---

### v0.3.2 — Frontend Layout & Accessibility ✅

> **Implementation Guide**: See [docs/FRONTEND_LAYOUT_PLAN.md](docs/FRONTEND_LAYOUT_PLAN.md)

| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| Layout fixes | Flex/grid overflow, text truncation | Critical | ✅ Complete |
| Responsive layout | CSS spacing scale, utility classes, Card component | High | ✅ Complete |
| Theme & accessibility | Colour contrast, ARIA, focus states, theme toggle | High | ✅ Complete |
| Polish & testing | Animations, error states, E2E tests | Medium | ✅ Complete |
| Backend integration | Scan, apply, checkpoint, rollback, errors | High | ✅ Complete |
| Root privilege escalation | pkexec integration for privileged operations | High | ✅ Complete |

#### A. Layout Fixes (Session 1) ✅

- [x] Added `min-width: 0` to `.navigation`, `.nav-links`, `.header-content`, `.activity-content`
- [x] Updated grid templates: `.dashboard-grid`, `.scanner-layout`, `.detail-values dl`, `.report-summary`
- [x] Added utility classes: `.truncate`, `.line-clamp-2`, `.line-clamp-3`, `.sr-only`, `.min-w-0`, `.skip-link`
- [x] Skip link as first focusable element with `<main id="main-content" tabindex="-1">`
- [x] Tab components: `aria-controls`, `aria-labelledby`, `tabindex` management, unique IDs

#### B. Responsive Layout (Session 2) ✅

- [x] Spacing scale: `--space-xs` to `--space-2xl` in `:root`
- [x] Utility classes in `styles.css`: `.flex`, `.flex-col`, `.grid`, `.gap-*`, `.items-*`, `.justify-*`
- [x] Viewport testing complete: 320px, 640px, 1920px
- [x] Touch targets: 44px minimum via `@media (pointer: coarse)`
- [x] Card component in `card.rs` with `Card`, `CardVariant`, `HeadingLevel`
- [x] All section components refactored to use Card component

#### C. Theme & Accessibility (Session 3) ✅

- [x] Colour contrast audit: Brightened `--text-secondary` and `--text-muted` to meet WCAG AA 4.5:1 ratio
- [x] CSS `[data-theme="..."]` selectors for Fortress, Sentinel, Command, Guardian, Daywatch themes
- [x] ThemeToggle component in `theme_toggle.rs` with dropdown UI
- [x] Theme persistence via localStorage, applies on page load
- [x] Added "Storage" feature to web-sys in Cargo.toml for localStorage access
- [x] Visual testing completed for all themes via Playwright MCP

| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| Colour contrast audit | Adjusted `--text-secondary` (#a1aebe) and `--text-muted` (#7a8a9e) for WCAG AA | High | ✅ Complete |
| `data-theme` attribute | CSS-only theme switching via `[data-theme="..."]` for all 5 themes | Medium | ✅ Complete |
| Focus state improvements | Consistent 0.125rem outline ring for accessibility | Medium | ✅ Complete |
| Theme toggle component | ThemeToggle dropdown with localStorage persistence | Low | ✅ Complete |
| High Contrast theme | WCAG AAA accessibility theme (7:1+ contrast ratios) | Low | ✅ Complete |

#### D. Polish & Testing (Session 4) ✅

- [x] Empty state styling with icons: 📋 (activity), 🔍 (findings), 📊 (compliance), ⚡ (apply), 💾 (checkpoints)
- [x] CSS transition variables: `--transition-fast` (150ms), `--transition-normal` (250ms), `--transition-slow` (350ms)
- [x] Button hover effects: `translateY(-1px)` lift with `box-shadow`
- [x] Card hover: border colour transition
- [x] Table row hover: smooth background transition
- [x] Severity badge hover: subtle `scale(1.05)`
- [x] Score display: slow transition for state changes
- [x] Filter select: focus ring with accent colour
- [x] E2E tests: TC-11 to TC-14 all passed

> **Test Plan**: See `docs/GUI_V031_TEST_PLAN.md`

#### E. Final Polish (Session 5) ✅

- [x] Tab animation reduced from 250ms to 120ms for snappier switching
- [x] Tab transform reduced from 8px to 4px for subtler motion
- [x] Navigation title now uses `--color-accent` (adapts to each theme's identity colour)
- [x] Created `docs/THEME_DESIGN_GUIDE.md` with comprehensive theme creation documentation

#### F. GUI Bug Fixes (Session 6) ✅

- [x] **Issue H**: Score mismatch Dashboard vs Analysis — unified `calculate_all_scores()` function
- [x] **Issue J**: Generate Reports no feedback — added status message display with success/error styling
- [x] **Issue K**: Checkpoints not visible after Apply — `get_checkpoints()` now reads both user + system databases
- [x] **Issue L**: Theme selector unreadable — CSS `appearance: none` reset with custom SVG dropdown arrow
- [x] Added Refresh button to checkpoint section for manual reload
- [x] MiniSecurityScore now shares compliance-based scoring algorithm with SecurityScore

#### G. Backend Integration ✅

- [x] Scan execution
- [x] Apply hardening (via pkexec)
- [x] Checkpoint creation
- [x] Rollback functionality (parses `RollbackResult` JSON, displays per-file restore status)
- [x] Error propagation

#### H. Root Privilege Escalation ✅

> **Chosen Approach**: pkexec with graceful error handling

**Privilege Requirements by Operation**:

| Operation | Requires Root | Reason |
|-----------|---------------|--------|
| Scanning | Partial | Most scans work without root; some checks (e.g., `/etc/shadow`) need elevated access |
| Apply hardening | Yes | Modifies system config files (`/etc/sysctl.conf`, `/etc/ssh/sshd_config`, etc.) |
| Rollback | Yes | Restores system config files from checkpoints |
| Delete checkpoint | No | Checkpoints stored in user-local database |

**Implementation Architecture**:

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

**Implementation Tasks**:

- [x] Add `check_polkit_availability()` function in Tauri commands
- [x] Create `run_privileged_command()` helper that wraps pkexec
- [x] Modify `run_apply` to use pkexec + CLI instead of in-process execution
- [x] Modify `run_rollback` to use pkexec + CLI
- [x] Add JSON output mode to CLI `apply` command (for machine-readable results)
- [x] Add JSON output mode to CLI `checkpoint rollback` command
- [x] Create user-friendly error messages for polkit failures
- [x] Test on Hyprland (with polkit-gnome)
- [x] Create polkit policy file for nicer dialog text
- [ ] Add to AUR/deb/rpm package dependencies

> **Tauri 2.x Note**: Frontend argument keys MUST use camelCase (e.g., `pluginIds` not `plugin_ids`) to match Tauri 2.x's default serde configuration.

---

### v0.3.3 — Distribution Validation ✅

| Distribution | Family | Version | Tests | Pass | Fail | Skip | Status |
|--------------|--------|---------|-------|------|------|------|--------|
| Arch Linux | Arch | Rolling (LTS 6.12) | 123 | 123 | 0 | 6 | ✅ Complete |
| Debian | Debian | 12 (Bookworm) | 123 | 123 | 0 | 6 | ✅ Complete |
| Fedora | Red Hat | 41 | 123 | 123 | 0 | 6 | ✅ Complete |
| Rocky Linux | Red Hat | 9 | 123 | 123 | 0 | 6 | ✅ Complete |
| openSUSE | SUSE | Leap 15.6 | 123 | 123 | 0 | 6 | ✅ Complete |

> **Note on family coverage**: Each validated distribution covers its entire family. Debian covers Ubuntu/Mint/Pop!_OS/elementary; Fedora covers RHEL/CentOS/Rocky/Alma/Oracle Linux; openSUSE covers SLES; Arch covers Manjaro/EndeavourOS/Garuda. All distributions in a family use identical hardener code paths.

**Validation Requirements**:

- [x] Each distro family requires dedicated testing sessions
- [x] Scan findings must be accurate for the target distro
- [x] No false positives from distro-specific files/settings that don't exist
- [x] Package manager integration must work correctly per distro
- [x] Service management must use correct init system commands

**Test Environment**: systemd-nspawn containers with bind-mounted project directory. Container scripts in `scripts/create-*-container.sh`.

**GUI Test Validation**: 84 Playwright Web UI tests pass on all 5 distros (Arch, Debian, Fedora, Rocky 9, openSUSE). Covers dashboard, findings, compliance, configure, history, themes, and error handling. Run via `sudo ./scripts/run-gui-tests.sh` or `run-cross-distro-tests.sh --gui`.

> **Test Results**: See [docs/DISTRIBUTION_VALIDATION.md](docs/DISTRIBUTION_VALIDATION.md)

---

### v0.4.0 — GUI/CLI Feature Parity & Web Interface

> **Implementation Guide**: See [docs/GUI_CLI_PARITY_PLAN.md](docs/GUI_CLI_PARITY_PLAN.md)

#### A. GUI/CLI Parity — P0-P1 Features

| Feature | CLI Equivalent | Priority | Status |
|---------|----------------|----------|--------|
| Dry-run preview | `apply --dry-run` | P0 | ✅ Complete |
| Severity filter | `scan --severity` | P0 | ✅ Complete |
| Plugin selection on scan | `scan --plugin` | P1 | ✅ Complete |
| Manual checkpoint create | `checkpoint create` | P1 | ✅ Complete |
| Checkpoint delete | `checkpoint delete` | P1 | ✅ Complete |
| Report export to file | `report --output` | P1 | ✅ Complete |
| Report format selection | `report --report-format` | P1 | ✅ Complete |

#### B. GUI/CLI Parity — P2-P3 Features

| Feature | CLI Equivalent | Priority | Status |
|---------|----------------|----------|--------|
| Scan history | `history list/show` | P2 | ✅ Complete |
| Audit mode toggle | `scan --audit` | P2 | ✅ Complete |
| Compliance mode toggle | `scan --compliance` | P2 | ✅ Complete |
| Plugin listing | `plugins` command | P2 | ✅ Complete |
| Checkpoint details | `checkpoint show` | P2 | ✅ Complete |
| Remote scanning UI | `--ssh` flags | P3 | ✅ Complete |
| Scheduler UI | `daemon` commands | P3 | ✅ Complete |
| Config file picker | `--config FILE` | P3 | ✅ Complete |

#### C. UI Polish Pass ✅

| Fix | Pages | Status |
|-----|-------|--------|
| Shared `.two-col-row` CSS class with `align-self: start` | All | ✅ Complete |
| RecentActivity card no longer stretches to fill page | Dashboard | ✅ Complete |
| Quick-start guide replaces empty right panel | Remote | ✅ Complete |
| Profile + Plugin Control side-by-side layout | Hardening (Configure) | ✅ Complete |
| Apply + Rollback results side-by-side layout | Hardening (History) | ✅ Complete |
| Cards size independently (no height-matching stretch) | Scheduler | ✅ Complete |
| Directional empty-state guidance text | Dashboard, Hardening | ✅ Complete |

#### D. Web Interface Enhancements

| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| Multi-host management | Manage multiple systems from one UI | Medium | ⬜ Pending |
| Historical trends | Track security posture over time | Low | ⬜ Pending |
| Alert notifications | Email/webhook on security regressions | Low | ⬜ Pending |
| DE testing | Test pkexec/polkit on GNOME, KDE, XFCE | Low | ⬜ Pending |

---

### v1.0.0 — Production Release

| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| Security audit | Third-party security review | Critical | ⬜ Pending |
| Package distribution | deb, rpm, AUR packages | High | 🔄 Specs ready |
| Comprehensive documentation | User guide, API docs, man page | High | 🔄 Man page done |
| Performance optimisation | Scan speed improvements | Medium | ⬜ Pending |
| Internationalisation | Multi-language support | Low | ⬜ Pending |

---

## Future Enhancements

Features planned for post-v1.0.0 releases.

### Configuration Management Integration

| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| Ansible modules | Ansible playbook integration for hardening | Low | ⬜ Pending |
| Puppet modules | Puppet manifest integration for hardening | Low | ⬜ Pending |
| Salt states | SaltStack state integration | Low | ⬜ Pending |
| Chef recipes | Chef cookbook integration | Low | ⬜ Pending |

### Additional Compliance Frameworks

| Framework | Description | Priority | Status |
|-----------|-------------|----------|--------|
| ISO 27001 | Information security management | Low | ⬜ Pending |
| SOC 2 | Service organisation controls | Low | ⬜ Pending |
| FedRAMP | Federal Risk and Authorization | Low | ⬜ Pending |

### Advanced Features

| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| SELinux policy management | Full policy editing, not just detection | Low | ⬜ Pending |
| AppArmor profile editor | Create and manage AppArmor profiles | Low | ⬜ Pending |
| High Contrast theme | WCAG AAA accessibility theme | Low | ✅ Complete |

---

## Technical Debt & Improvements

| Item | Description | Priority | Status |
|------|-------------|----------|--------|
| Increase test coverage | Target 90%+ coverage | Low | ✅ Complete (428+ tests) |
| Consolidate `create_plugin_registry()` | Duplicated in CLI, report, Tauri | Low | ✅ Complete |
| Consolidate test mock plugins | Duplicated in registry.rs and plugin_manager_tests.rs | Low | ✅ Complete |
| Config file utilities | Duplicated parsing/backup in SSH and PAM plugins | Low | ✅ Complete |
| Refactor PAM plugin | Updated to use shared `file_utils` functions | Low | ✅ Complete |
| Package manager code duplication | Validation/execution duplicated in apt, dnf, zypper, pacman | Low | ✅ Complete |
| Remove duplicate registry in plugins.rs | Removed from plugins.rs and apply.rs | Low | ✅ Complete |
| Review field naming consistency | Audit complete: 2 violations fixed | Low | ✅ Complete |
| Gate or remove `testing` feature | Removed unused feature from hardener-core | Low | ✅ Complete |
| Extract inline tests to `tests/` dirs | Follow `hardener-plugins/tests/` pattern | Low | ✅ Complete |
| Framework descriptions in reports | Added `description()` as subtitle | Low | ✅ Complete |

### Code Deduplication Summary ✅

**1. Plugin Registry Creation**
- Consolidated into `hardener_plugins::create_plugin_registry()`
- Removed duplicates from scan.rs, report.rs, and commands.rs

**2. Test Mock Plugins**
- Created `hardener-core/src/testing.rs` with `MockPlugin` builder
- Features: `.name()`, `.depends_on()`, `.category()`, `.fail_scan()`, `.fail_apply()`
- Removed ~330 lines of duplicate mock struct definitions

**3. Config File Utilities**
- Added to `hardener-common/src/file_utils.rs`:
  - `read_config_file()`, `read_config_file_optional()`
  - `parse_config_value()` with `ConfigFormat` enum
  - `set_config_directive()`
  - `create_timestamped_backup()`
- SSH and PAM plugins refactored to use these utilities

**4. Package Manager Helpers**
- Added to `hardener-distro/src/package/mod.rs`:
  - `PackageNameRules` enum (Debian, Rpm, Arch)
  - `validate_package_name()` — shared validation with distro-specific rules
  - `validate_package_names()` — batch validation helper
  - `execute_command()` — generic command runner with error handling
  - `parse_rpm_package_list()` — shared RPM output parser for dnf/zypper
- All 4 package managers (apt, dnf, zypper, pacman) refactored to use shared helpers
- Reduced ~190 lines of duplicate code

### Field Naming Audit ✅

> Completed 2025-12-11

**Summary**: Audit complete. 2 true violations fixed, remaining items found to be acceptable patterns.

**Fixed Issues**:

| Struct | Location | Fix Applied |
|--------|----------|-------------|
| MockPlugin | `hardener-core/src/testing.rs:29` | `dependencies` → `plugin_dependencies`, `fail_scan` → `plugin_fail_scan`, `fail_apply` → `plugin_fail_apply` |
| ServiceDirective | `hardener-plugins/src/services/mod.rs:67` | `service_issue_severity` → `service_severity` |

**Reviewed & Accepted** (consistent patterns, no change needed):

| Category | Structs | Reasoning |
|----------|---------|-----------|
| Suffix pattern `_count` | ScanSession, ScanSummary | Consistent naming with `critical_count`, `high_count`, etc. |
| Database DTOs | ScanFinding, ScanFindingRow | Fields match database columns — acceptable for DTO boundary |
| Named aggregation | SeverityCounts | Struct name provides context |
| Framework conventions | Cli, SshConnectionConfig | Clap/SSH standard conventions |
| UI definitions | FrameworkScore, TabDef, PluginDef | Simple internal types with clear context |

### Test Restructure (Recommended)

Move inline tests from source files to dedicated `tests/` directories:

```
crates/hardener-core/
├── src/
│   ├── plugin.rs           # No inline tests
│   ├── registry.rs         # Has inline tests (could be moved)
│   ├── testing.rs          # MockPlugin builder
│   └── ...
└── tests/
    ├── plugin_manager_tests.rs  # Already using MockPlugin
    └── ...
```

**Benefits**: Clear separation, consistency, better IDE support, parallel test execution.

---

## Architecture Notes

### CLI/GUI Code Sharing

The compliance module (`hardener-compliance`) is designed for reuse:

```
┌──────────────────────────────────────────────────────────┐
│                     User Interfaces                      │
├─────────────────────────┬────────────────────────────────┤
│   hardener-cli          │   hardener-ui (Tauri/Leptos)   │
│   - Terminal prompts    │   - GUI dialogs                │
│   - Argument parsing    │   - Visual components          │
└───────────┬─────────────┴───────────────┬────────────────┘
            │                             │
            ▼                             ▼
┌──────────────────────────────────────────────────────────┐
│              hardener-compliance (Shared Logic)          │
│   - ReportGenerator                                      │
│   - Framework definitions (CIS, STIG, NIST, etc.)        │
│   - Output formatters (Text, JSON, CSV, HTML, PDF)       │
└──────────────────────────────────────────────────────────┘
```

### Supported Compliance Frameworks

| Framework | Controls | Description |
|-----------|----------|-------------|
| CIS | 38 | Center for Internet Security Benchmarks |
| STIG | 20 | DISA Security Technical Implementation Guides |
| NIST 800-53 | 20 | US Federal security controls |
| PCI-DSS | 22 | Payment Card Industry standards |
| HIPAA | 14 | Healthcare security requirements |
| GDPR | 12 | EU data protection (Article 32) |

---

## Contributing

When working on new features:

1. Create a feature branch from `main`
2. Update ROADMAP.md with your progress
3. Ensure all tests pass (`cargo test`)
4. Run `cargo clippy` with no warnings
5. Submit PR for review

---

**Last Updated**: 2026-02-25
