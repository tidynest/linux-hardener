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
| Background personalisation | 5 security-focused themes created (Fortress, Sentinel, Command, Guardian, Daywatch) | Low | ✅ Complete |
| Responsive layout | See [FRONTEND_LAYOUT_PLAN.md](docs/FRONTEND_LAYOUT_PLAN.md) Session 2 | Medium | ✅ Complete |
| Navigation restructure | Consolidated to 3 pages (Dashboard, Analysis, Hardening) | Low | ✅ Complete |
| GUI functional testing | Verify all GUI features work correctly | High | ✅ Complete |
| CLI functional testing | Verify all CLI commands work correctly (31 unit tests + 66 functional tests) | High | ✅ Complete |
| Safe testing environment | systemd-nspawn container with test scripts | Critical | ✅ Complete |

**v0.3.1 Completed Items (2025-12-05/06):**
- Fixed "Loading..." text persistence by mounting app to `#app` element
- Added dark terminal theme with CSS Variables, JetBrains Mono + Inter fonts
- Security score now shows "--/100" before scan with "Run a scan to see your score"
- "View Findings" now uses styled button with programmatic navigation
- All 3 pages styled: Dashboard, Analysis (tabbed), Hardening (sectioned)
- Timestamp formatting: Checkpoints page now shows human-readable dates
- **(2025-12-06)** Browser mode fix: Added `tauri_available()` check in `tauri_bindings.rs`
  - Web UI now renders all pages correctly without Tauri desktop wrapper
  - Commands return graceful errors in browser mode instead of crashing Leptos

**Completed (2025-12-05):**
- State persistence: Scan results now persist via `scan_sessions`, `scan_results`, `scan_findings` tables
- GUI loads latest scan results on mount via `get_latest_scan` Tauri command
- 4 unit tests for `ScanHistoryManager` all passing
- Full integration test passed (8/8 Web UI tests, database verification complete)

**Testing Infrastructure (2025-12-10):**
- ✅ Safe testing environment implemented using systemd-nspawn container
- ✅ CLI functional test results: 27/27 tests pass ([docs/CLI_V032_TEST_RESULTS.md](docs/CLI_V032_TEST_RESULTS.md))
- ✅ Root functional test results: 35/36 tests pass (1 skip is test script pattern matching)
- ✅ Bug M fixed: Scheduler database now uses user path for non-root users

**Root Test Highlights:**
- **47 findings** as root (vs 11 as non-root) - plugins now have full access
- **26 audit findings** visible with root access
- Kernel apply: ✅ Changes applied, `kptr_restrict=2` verified
- All 6 compliance frameworks: ✅ Reports generated
- PDF generation: ✅ 30KB PDF created

**Testing Scripts:**
| Script | Purpose |
|--------|---------|
| `scripts/create-test-container.sh` | Create/manage Arch Linux container |
| `scripts/root-test-suite.sh` | Comprehensive root test suite |

**Usage:**
```bash
sudo ./scripts/create-test-container.sh        # Create container
sudo ./scripts/create-test-container.sh enter  # Enter container
# Inside container (binary built on host is bind-mounted):
cd /project
sudo ./scripts/root-test-suite.sh              # Safe tests (read-only)
sudo ./scripts/root-test-suite.sh --apply      # Full tests (apply + rollback)
```

**Note on `--apply` flag:** Destructive tests (apply hardening, rollback) require explicit `--apply` flag. This is a safety feature to prevent accidentally running tests that modify configs. Inside the container, both modes are completely safe since it's isolated from the host system.

### v0.3.2 - Frontend Layout & Accessibility

This version focuses on fixing layout issues, improving accessibility, and enhancing the theme system.

> **Implementation Guide**: See [docs/FRONTEND_LAYOUT_PLAN.md](docs/FRONTEND_LAYOUT_PLAN.md) for detailed session-by-session breakdown.

#### A. Layout Fixes (Session 1 - Critical) ✅

| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| Flex overflow fix | Add `min-width: 0` to all flex children | Critical | ✅ Complete |
| Grid overflow fix | Use `minmax(0, 1fr)` in grid templates | Critical | ✅ Complete |
| Text truncation | Add `.truncate` class to long text elements | High | ✅ Complete |
| Skip link | Implement skip link in `lib.rs` for accessibility | High | ✅ Complete |
| Tab ARIA | Add ARIA attributes to tab components | High | ✅ Complete |

**Session 1 Completed (2025-12-07):**
- Added `min-width: 0` to `.navigation`, `.nav-links`, `.header-content`, `.activity-content`
- Updated grid templates: `.dashboard-grid`, `.scanner-layout`, `.detail-values dl`, `.report-summary`
- Added utility classes: `.truncate`, `.line-clamp-2`, `.line-clamp-3`, `.sr-only`, `.min-w-0`, `.skip-link`
- Skip link as first focusable element with `<main id="main-content" tabindex="-1">`
- Tab components: `aria-controls`, `aria-labelledby`, `tabindex` management, unique IDs

#### B. Responsive Layout (Session 2) ✅ COMPLETE

| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| CSS spacing scale | Add `--space-xs` through `--space-2xl` variables | High | ✅ Complete |
| Utility classes | Add `.flex`, `.grid`, `.gap-*`, `.items-*`, `.justify-*` utilities | High | ✅ Complete |
| Card standardisation | Reusable `Card` component with consistent styling | Medium | ✅ Complete |
| Mobile-first breakpoints | Test at 320px, 640px, 1024px, 1440px | Medium | ✅ Complete |
| Touch targets | Minimum 44px touch targets for interactive elements | Medium | ✅ Complete |

**Session 2 Completed (2025-12-08):**
- Spacing scale: `--space-xs` to `--space-2xl` in `:root`
- Utility classes in `styles.css`: `.flex`, `.flex-col`, `.grid`, `.gap-*`, `.items-*`, `.justify-*`
- Viewport testing complete: 320px, 640px, 1920px
- Touch targets: 44px minimum via `@media (pointer: coarse)`
- Card component in `card.rs` with `Card`, `CardVariant`, `HeadingLevel`
- All section components refactored to use Card component

#### C. Theme & Accessibility (Session 3) ✅ COMPLETE

| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| Colour contrast audit | Adjusted `--text-secondary` (#a1aebe) and `--text-muted` (#7a8a9e) for WCAG AA | High | ✅ Complete |
| `data-theme` attribute | CSS-only theme switching via `[data-theme="..."]` for all 5 themes | Medium | ✅ Complete |
| Focus state improvements | Consistent 0.125rem outline ring for accessibility | Medium | ✅ Complete |
| Theme toggle component | ThemeToggle dropdown with localStorage persistence | Low | ✅ Complete |
| High Contrast theme | WCAG AAA accessibility theme option | Low | Pending |

**Session 3 Completed (2025-12-08):**
- Colour contrast audit: Brightened `--text-secondary` and `--text-muted` to meet WCAG AA 4.5:1 ratio
- CSS `[data-theme="..."]` selectors for Fortress, Sentinel, Command, Guardian, Daywatch themes
- ThemeToggle component in `theme_toggle.rs` with dropdown UI
- Theme persistence via localStorage, applies on page load
- Added "Storage" feature to web-sys in Cargo.toml for localStorage access
- Visual testing completed for all themes via Playwright MCP

#### D. Polish & Testing (Session 4)

| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| Animations | Subtle hover effects, page transitions, loading states | Low | ✅ Complete |
| Error states | Empty state designs, error message styling | Medium | ✅ Complete |
| Responsive typography | Fluid font sizes with `clamp()` | Low | ✅ Complete (Session 2) |
| E2E tests (Web) | Playwright tests for browser UI | High | ✅ Complete |
| E2E tests (Desktop) | Tauri test harness for desktop app | Medium | Deferred to v0.4.0 |

**Session 4 Completed (2025-12-08):**
- Empty state styling with icons: 📋 (activity), 🔍 (findings), 📊 (compliance), ⚡ (apply), 💾 (checkpoints)
- CSS transition variables: `--transition-fast` (150ms), `--transition-normal` (250ms), `--transition-slow` (350ms)
- Button hover effects: `translateY(-1px)` lift with `box-shadow`
- Card hover: border colour transition
- Table row hover: smooth background transition
- Severity badge hover: subtle `scale(1.05)`
- Score display: slow transition for state changes
- Filter select: focus ring with accent colour
- E2E tests: TC-11 to TC-14 all passed (see `docs/GUI_V031_TEST_PLAN.md`)

**Session 5 Completed (2025-12-09) - Final Polish:**
- Tab animation reduced from 250ms to 120ms for snappier switching
- Tab transform reduced from 8px to 4px for subtler motion
- Navigation title now uses `--color-accent` (adapts to each theme's identity colour)
- Created `docs/THEME_DESIGN_GUIDE.md` with comprehensive theme creation documentation

**Session 6 Completed (2025-12-09) - GUI Bug Fixes:**
- ✅ **Issue H**: Score mismatch Dashboard vs Analysis - unified `calculate_all_scores()` function
- ✅ **Issue J**: Generate Reports no feedback - added status message display with success/error styling
- ✅ **Issue K**: Checkpoints not visible after Apply - `get_checkpoints()` now reads both user + system databases
- ✅ **Issue L**: Theme selector unreadable - CSS `appearance: none` reset with custom SVG dropdown arrow
- Added Refresh button to checkpoint section for manual reload
- MiniSecurityScore now shares compliance-based scoring algorithm with SecurityScore

#### E. Backend Integration (Complete)

| Feature | Status |
|---------|--------|
| Scan execution | ✅ Complete |
| Apply hardening | ✅ Complete (via pkexec) |
| Checkpoint creation | ✅ Complete |
| Rollback functionality | ✅ Complete |
| Error propagation | ✅ Complete |

#### F. Root Privilege Escalation (Reference - Complete)

> **Status**: ✅ Implementation complete. This section retained for reference.

Security scans and hardening operations require root privileges. The GUI uses pkexec for privilege escalation.

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
- [ ] (Optional) Create polkit policy file for nicer dialog text
- [ ] (Future) Add to AUR/deb/rpm package dependencies

**Tauri 2.x Critical Note:** Frontend argument keys MUST use camelCase (e.g., `pluginIds` not `plugin_ids`) to match Tauri 2.x's default serde configuration. The `wasm-bindgen` extern binding must include the `catch` attribute for proper Promise rejection handling.

### v0.3.3 - Distribution-Specific Validation (Complete)

| Distribution | Family | Version | Tests | Pass | Fail | Skip | Status |
|--------------|--------|---------|-------|------|------|------|--------|
| Arch Linux | Arch | Rolling (LTS 6.12) | 102 | 102 | 0 | 1 | ✅ VALIDATED |
| Debian | Debian | 12 (Bookworm) | 102 | 102 | 0 | 1 | ✅ VALIDATED |
| Fedora | Red Hat | 41 | 102 | 102 | 0 | 1 | ✅ VALIDATED |
| openSUSE | SUSE | Leap 15.6 | 102 | 102 | 0 | 1 | ✅ VALIDATED |

> **Note on family coverage:** Each validated distribution covers its entire family. Debian covers Ubuntu/Mint/Pop!_OS/elementary; Fedora covers RHEL/CentOS/Rocky/Alma/Oracle Linux; openSUSE covers SLES; Arch covers Manjaro/EndeavourOS/Garuda. All distributions in a family use identical hardener code paths.

**Validation Requirements:**
- Each distro family requires dedicated testing sessions
- Scan findings must be accurate for the target distro
- No false positives from distro-specific files/settings that don't exist
- Package manager integration must work correctly per distro
- Service management must use correct init system commands

**Test Environment:** systemd-nspawn containers with bind-mounted project directory. Container scripts in `scripts/create-*-container.sh`.

See [docs/DISTRIBUTION_VALIDATION.md](docs/DISTRIBUTION_VALIDATION.md) for detailed test results per distribution.

### v0.4.0 - GUI/CLI Feature Parity & Web Interface

> **Implementation Guide**: See [docs/GUI_CLI_PARITY_PLAN.md](docs/GUI_CLI_PARITY_PLAN.md) for detailed phase-by-phase breakdown.

#### GUI/CLI Parity (P0-P1 Features)

| Feature | CLI Equivalent | Priority | Status |
|---------|----------------|----------|--------|
| Dry-run preview | `apply --dry-run` | P0 | Pending |
| Severity filter | `scan --severity` | P0 | Pending |
| Plugin selection on scan | `scan --plugin` | P1 | Pending |
| Manual checkpoint create | `checkpoint create` | P1 | Pending |
| Checkpoint delete | `checkpoint delete` | P1 | Pending |
| Report export to file | `report --output` | P1 | Pending |
| Report format selection | `report --report-format` | P1 | Pending |

#### GUI/CLI Parity (P2-P3 Features)

| Feature | CLI Equivalent | Priority | Status |
|---------|----------------|----------|--------|
| Scan history | `history list/show` | P2 | Pending |
| Audit mode toggle | `scan --audit` | P2 | Pending |
| Compliance mode toggle | `scan --compliance` | P2 | Pending |
| Plugin listing | `plugins` command | P2 | Pending |
| Checkpoint details | `checkpoint show` | P2 | Pending |
| Remote scanning UI | `--ssh` flags | P3 | Pending |
| Scheduler UI | `daemon` commands | P3 | Pending |
| Config file picker | `--config FILE` | P3 | Pending |

#### Web Interface Enhancements

| Feature | Description | Priority |
|---------|-------------|----------|
| Multi-host management | Manage multiple systems from one UI | Medium |
| Historical trends | Track security posture over time | Low |
| Alert notifications | Email/webhook on security regressions | Low |
| DE testing | Test pkexec/polkit on GNOME, KDE, XFCE | Low |

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
| ~~Increase test coverage~~ | ~~Target 90%+ coverage~~ | ✅ Complete (396+ tests) |
| ~~Consolidate `create_plugin_registry()`~~ | ~~Duplicated in CLI, report, Tauri~~ | ✅ Complete |
| ~~Consolidate test mock plugins~~ | ~~Duplicated in registry.rs and plugin_manager_tests.rs~~ | ✅ Complete |
| ~~Config file utilities~~ | ~~Duplicated parsing/backup in SSH and PAM plugins~~ | ✅ Complete |
| ~~Refactor PAM plugin~~ | ~~Updated to use shared `file_utils` functions~~ | ✅ Complete |
| ~~Package manager code duplication~~ | ~~Validation/execution duplicated in apt, dnf, zypper, pacman~~ | ✅ Complete |
| ~~Remove duplicate registry in plugins.rs~~ | ~~Removed from plugins.rs and apply.rs~~ | ✅ Complete |
| ~~Review field naming consistency~~ | ~~Audit complete: 2 violations fixed, rest acceptable~~ | ✅ Complete |
| ~~Gate or remove `testing` feature~~ | ~~Removed unused feature from hardener-core~~ | ✅ Complete |
| Extract inline tests to `tests/` dirs | Follow `hardener-plugins/tests/` pattern across all crates | Low |
| ~~Framework descriptions in reports~~ | ~~Added `description()` as subtitle in all report formats~~ | ✅ Complete |
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

### Field Naming Audit (2025-12-11) ✅

Comprehensive audit of all struct field naming conventions across the codebase.

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
| Database DTOs | ScanFinding, ScanFindingRow | Fields match database columns - acceptable for DTO boundary |
| Named aggregation | SeverityCounts | Struct name provides context |
| Framework conventions | Cli, SshConnectionConfig | Clap/SSH standard conventions |
| UI definitions | FrameworkScore, TabDef, PluginDef | Simple internal types with clear context |

**Additional cleanup**: Removed stale `#[cfg(feature = "testing")]` reference from `hardener-core/src/lib.rs`

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
| CIS | 38 | Center for Internet Security Benchmarks |
| STIG | 20 | DISA Security Technical Implementation Guides |
| NIST 800-53 | 20 | US Federal security controls |
| PCI-DSS | 22 | Payment Card Industry standards |
| HIPAA | 14 | Healthcare security requirements |
| GDPR | 12 | EU data protection (Article 32) |

---

## Contributing

When working on new features:

1. Create a feature branch from `master`
2. Update this PLAN.md with your progress
3. Ensure all tests pass (`cargo test`)
4. Run `cargo clippy` with no warnings
5. Submit PR for review

**Legend**: ⬜ Pending | 🔄 In Progress | ✅ Complete

**Last Updated**: 2025-12-11
