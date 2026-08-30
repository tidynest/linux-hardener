# Development Roadmap

## Overview

This document tracks the development progress and planned features for Linux Hardener.

**Legend**: ⬜ Pending | 🔄 In Progress | ✅ Complete

> **Where open work actually lives.** Since 2026-08-01 every known open item has
> a GitHub issue, and the
> [issue tracker](https://github.com/tidynest/linux-hardener/issues) is
> the authoritative list. This roadmap records the milestone shape and names the
> issue for anything still open, rather than restating the plan beside it. For
> what each release changed, and for merged work that is not yet released, read
> [CHANGELOG.md](../CHANGELOG.md).

---

## Completed Features

### v0.1.0: Core Infrastructure ✅

- [x] Plugin system with dependency-aware execution
- [x] Checkpoint system with Ed25519 signatures
- [x] Hash chain audit logging
- [x] Distribution detection (Debian, Red Hat, Arch, SUSE)
- [x] Desktop application (Tauri + Leptos)
- [x] Full plugin rollback integration with checkpoint system

### v0.1.x: Security Plugins (8/8) ✅

- [x] Kernel Hardening (sysctl parameters)
- [x] SSH Hardening (OpenSSH configuration)
- [x] Firewall Hardening (nftables/firewalld/ufw)
- [x] PAM Hardening (authentication modules)
- [x] Services Minimisation (disable unnecessary services)
- [x] Audit Hardening (auditd rules)
- [x] Permissions Hardening (file permissions)
- [x] MAC Hardening (SELinux/AppArmor)

### v0.1.x: Compliance Report Generation ✅

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

### v0.2.0: CLI & Reporting Enhancements ✅

- [x] Config file support (`~/.config/linux-hardener/`)
- [x] CLI flags: `--config`, `--audit`, `--exit-code`
- [x] Policy exception system with audit trail
- [x] Interactive report wizard
- [x] CSV and HTML format support in CLI
- [x] PDF report formatter
- [x] GUI compliance report page

---

## Milestone history

Every milestone in this section is delivered. The one row still marked partial,
DE testing under v0.4.0 §D, names its issue.

### v0.3.0: Remote & Automation ✅

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
  - `hardener daemon start`: starts scheduling daemon
  - `hardener daemon run-once`: single scan without scheduler
  - `hardener daemon status`: shows config and scan history
- [x] `Notifier` trait and `NotificationDispatcher`
- [x] `EmailNotifier` (lettre SMTP)
- [x] `WebhookNotifier` (Slack/Discord/generic)
- [x] `SystemdGenerator` (.service/.timer templates)
  - Generates `.service` and `.timer` unit files
  - Cron-to-systemd calendar expression conversion
  - Security hardening directives in service unit
- [x] CLI `systemd` commands
  - `hardener systemd generate`: output unit files to stdout or directory
  - `hardener systemd install`: install and enable timer (system or user)
  - `hardener systemd uninstall`: disable and remove units
  - `hardener systemd status`: show timer/service status
- [x] CLI `history` commands
  - `hardener history list`: list recent scan sessions with filtering
  - `hardener history show <id>`: display session details and findings
  - `hardener history export <id>`: export session to JSON file

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

### v0.3.1: GUI Polish & Testing ✅

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
| Responsive layout | Desktop-first responsive design | Medium | ✅ Complete |
| Navigation restructure | 5 pages (Dashboard, Analysis, Hardening, Remote, Scheduler) - superseded by the GUI/UX redesign below (7 pages behind a grouped sidebar) | Low | ✅ Complete |
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

> **Test Results**: See [docs/reference/distribution-validation.md](reference/distribution-validation.md)

**Root Test Highlights**:
- 47 findings as root (vs 11 as non-root): plugins now have full access
- 26 audit findings visible with root access
- Kernel apply: changes applied, `kptr_restrict=2` verified
- All 6 compliance frameworks: reports generated
- PDF generation: 30KB PDF created

**Testing Scripts**:

| Script | Purpose |
|--------|---------|
| `scripts/containers/create-container.sh` | Create/manage test containers (arch/debian/ubuntu/fedora/rhel/opensuse/arch-nftables) |
| `scripts/test/root-test-suite.sh` | Comprehensive root test suite |
| `scripts/test/gui/run-gui-tests.sh` | Web UI Playwright test orchestrator (5 distros) |
| `scripts/test/gui/gui-test-inner.sh` | Container inner script (HTTP + headless Playwright; dynamically generates index.html from dist/) |
| `scripts/test/gui/run-tauri-gui-tests.sh` | Tauri desktop test orchestrator |
| `scripts/test/gui/tauri-gui-test-inner.sh` | Container inner script for Tauri desktop tests |

**Usage**:

```bash
sudo ./scripts/containers/create-container.sh arch        # Create container
sudo ./scripts/containers/create-container.sh arch enter  # Enter container
# Inside container (binary built on host is bind-mounted):
cd /project
sudo ./scripts/test/root-test-suite.sh              # Safe tests (read-only)
sudo ./scripts/test/root-test-suite.sh --apply      # Full tests (apply + rollback)
```

> **Note**: Destructive tests (apply hardening, rollback) require explicit `--apply` flag. Inside the container, both modes are completely safe since it's isolated from the host system.

---

### v0.3.2: Frontend Layout & Accessibility ✅

> **Implementation Guide**: `docs/archive/FRONTEND_LAYOUT_PLAN.md`, an internal
> working document that is not published in this repository.

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
- [x] Card component in `card.rs` with `Card`, `HeadingLevel` (a `CardVariant` enum shipped alongside them and was removed on 2026-08-17: its two non-default variants emitted CSS classes `styles.css` never defined, and no caller ever passed the prop)
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

> **Test Plan**: `docs/archive/GUI_V031_TEST_PLAN.md`, an internal working
> document that is not published in this repository.

#### E. Final Polish (Session 5) ✅

- [x] Tab animation reduced from 250ms to 120ms for snappier switching
- [x] Tab transform reduced from 8px to 4px for subtler motion
- [x] Navigation title now uses `--color-accent` (adapts to each theme's identity colour)
- [x] Created `docs/design/theming.md` with comprehensive theme creation documentation

#### F. GUI Bug Fixes (Session 6) ✅

- [x] **Issue H**: Score mismatch Dashboard vs Analysis, unified `calculate_all_scores()` function
- [x] **Issue J**: Generate Reports no feedback, added status message display with success/error styling
- [x] **Issue K**: Checkpoints not visible after Apply, `get_checkpoints()` now reads both user + system databases
- [x] **Issue L**: Theme selector unreadable, CSS `appearance: none` reset with custom SVG dropdown arrow
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
- [x] Add to AUR/deb/rpm package dependencies

> **Tauri 2.x Note**: Frontend argument keys MUST use camelCase (e.g., `pluginIds` not `plugin_ids`) to match Tauri 2.x's default serde configuration.

---

### v0.3.3: Distribution Validation ✅

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

**Test Environment**: systemd-nspawn containers with bind-mounted project directory. Container creation via `scripts/containers/create-container.sh <distro>`.

**GUI Test Validation**: 84 Playwright Web UI tests pass on all 5 distros (Arch, Debian, Fedora, Rocky 9, openSUSE). Covers dashboard, findings, compliance, configure, history, themes, and error handling. Run via `sudo ./scripts/test/gui/run-gui-tests.sh` or `run-cross-distro-tests.sh --gui`.

> **Test Results**: See [docs/reference/distribution-validation.md](reference/distribution-validation.md)

---

### v0.4.0: GUI/CLI Feature Parity & Web Interface

> **Implementation Guide**: See [docs/plans/archive/2026-02-24-gui-cli-parity.md](plans/archive/2026-02-24-gui-cli-parity.md)

#### A. GUI/CLI Parity: P0-P1 Features

| Feature | CLI Equivalent | Priority | Status |
|---------|----------------|----------|--------|
| Dry-run preview | `apply --dry-run` | P0 | ✅ Complete |
| Severity filter | `scan --severity` | P0 | ✅ Complete |
| Plugin selection on scan | `scan --plugin` | P1 | ✅ Complete |
| Manual checkpoint create | `checkpoint create` | P1 | ✅ Complete |
| Checkpoint delete | `checkpoint delete` | P1 | ✅ Complete |
| Report export to file | `report --output` | P1 | ✅ Complete |
| Report format selection | `report --report-format` | P1 | ✅ Complete |

#### B. GUI/CLI Parity: P2-P3 Features

| Feature | CLI Equivalent | Priority | Status |
|---------|----------------|----------|--------|
| Scan history | `history list/show` | P2 | ✅ Complete |
| Audit mode toggle | `scan --audit` | P2 | ✅ Complete |
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
| Multi-host management | Manage multiple systems from one UI | Medium | ✅ Complete (Fleet scan + compliance scores + apply/rollback GUI + ad-hoc SSH targets + live per-host progress + per-host history all shipped). One follow-up open: drilling into a host's compliance count needs an IPC command that does not exist yet, issue #50 |
| Historical trends | Track security posture over time | Low | ✅ Complete (CLI `history trends`; desktop renders a per-host scan-history timeline with a better/worse/same direction label, `commands::get_host_history` into `components::host_panel`) |
| Alert notifications | Email/webhook on security regressions | Low | ✅ Complete (scheduler `notify_mode` regression alerts) |
| DE testing | Test pkexec/polkit on GNOME, KDE, XFCE | Low | 🔄 Tooling shipped (`scripts/test/polkit/detect-polkit-agent.sh`, `test-polkit-matrix.sh`, the parametrised `test-polkit.sh <desktop>`, `docs/guide/desktop-environment-compatibility.md`); real GNOME/KDE/XFCE runs need live DE sessions, issue #18 |

---

### v1.0.0: Production Release ✅

| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| Security audit (internal) | Internal security review (53/53 findings) | Critical | ✅ Complete |
| Package distribution | AUR PKGBUILD, RPM spec, Debian packaging | High | ✅ Complete |
| Comprehensive documentation | Man page, docs/guide/installation.md, SECURITY.md | High | ✅ Complete |
| Cross-distro validation | 5 distros, 123/123 tests each | High | ✅ Complete |
| Package install validation | Simulated installs on all 5 distros | High | ✅ Complete |

---

### v1.0.2: CLI Fixes & Desktop UX ✅

| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| CLI crash fixes | daemon status, checkpoint list, wizard crashes | Critical | ✅ Complete |
| Stderr routing | Progress to stderr for clean piping | High | ✅ Complete |
| Idempotent dirs | State init no longer fails if dirs exist | High | ✅ Complete |
| User-mode systemd | Correct user-scoped unit paths | Medium | ✅ Complete |
| Keyboard navigation | Ctrl+1-5, Alt+T, Escape, F11, Arrow keys | High | ✅ Complete |
| ARIA accessibility | WAI-ARIA tabs, skip link, aria-selected/live | High | ✅ Complete |
| Shared TabBar | Reusable TabBar with keyboard nav + ARIA | High | ✅ Complete |
| CopyButton | Async Clipboard API for compliance reports | Medium | ✅ Complete |
| ConfirmDelete | Inline delete confirmation | Medium | ✅ Complete |
| Findings grid keyboard | Arrow/Enter/Space navigation for findings | Medium | ✅ Complete |
| Desktop test suites | 89 tests (43 UX + 46 functional) + 29 Node.js | High | ✅ Complete |

---

### v1.2.0: Multi-host & Compliance Depth ✅ (Released)

- [x] Multi-host batch CLI: `batch scan` / `report` / `apply` / `rollback` (concurrent, per-host isolated, tiered exit codes)
- [x] Per-host scan history, trends, and regression detection (`history trends/regressions --host`)
- [x] Scheduler regression alerts (`notify_mode`: findings / regression / both)
- [x] Remote-correct checkpoints (capture/restore through the executor; host-keyed; cross-host restore refused)
- [x] ISO/IEC 27001:2022 framework + multi-framework finding mappings (STIG/NIST/PCI-DSS/HIPAA/GDPR)
- [x] CIS coverage completion: 11 CIS controls now genuinely assessed (Pass/Fail); `report --framework cis` shows 6 ManualReview, down from 17
- [x] PAM/permissions assessment improvements: faillock/pwhistory use threshold comparison; shadow/gshadow use allowed-bits mask (never loosens stricter settings)
- [x] Desktop **Fleet** view: read-only multi-host scan posture with CIS compliance scores and per-framework breakdown
- [x] Fleet apply/rollback in the GUI: shells out to the audited `batch apply/rollback`; mandatory dry-run + confirm modal before any change
- [x] Polkit desktop-environment test tooling (`scripts/test/polkit/detect-polkit-agent.sh`, `test-polkit-matrix.sh`, DE-specific wrappers, `docs/guide/desktop-environment-compatibility.md`)

---

### v1.3.0 to v1.5.1: released, recorded in the changelog ✅

Five releases landed between v1.2.0 and today and are deliberately not restated
here, because [CHANGELOG.md](../CHANGELOG.md) is their single source:
**v1.3.0** (RHEL 10 profiles, the SOC 2 / 800-171 / FedRAMP frameworks,
per-command Tauri ACLs, build identity in `--version`, and the
docs/scripts/packaging restructure), **v1.3.1** (build-identity and PKGBUILD
target-dir packaging fixes), **v1.3.2** (the first defects surfaced by real
local apply runs), **v1.4.0** (honest apply counts, idempotent state-aware apply
across all eight plugins, honest unchecked reporting, remote privilege probing),
**v1.5.0** (the GUI/UX redesign below, reversible rollback, and three security
fixes), and **v1.5.1** (`scan --exit-code` fails on an incomplete scan,
`scan --compliance` removed, and the openSUSE vendor-configuration fix).

**v1.8.1 is the current release.** No count is given here on purpose: it
changes with every commit, and the two figures that used to stand in this
sentence were both stale within days. Read whatever has accumulated since
the tag with `git rev-list --count v1.8.1..main`.
`CHANGELOG.md` `[Unreleased]` describes unreleased work.

### GUI/UX Redesign (Desktop) ✅ (shipped in v1.5.0)

> Frontend-only: markup, CSS and presentational Leptos components only; no backend, IPC or type changes.

- [x] Flat top navigation bar replaced by a grouped left sidebar (Local: Dashboard, Analysis, Hardening; Fleet: Hosts, Fleet Apply, Scheduler) with a collapsible icon rail and a pinned Settings area
- [x] Remote and Fleet screens merged into a single Hosts page (bulk scan plus a single-host connect session, both behind one expandable row); old `/remote` links redirect there automatically
- [x] New Settings page: a visual theme swatch grid across all seven themes (Midnight Teal, Fortress, Sentinel, Command, Guardian, Daywatch, High Contrast) plus an About block
- [x] Fleet Apply restyled as a staged Preview/Execute flow with a segmented Apply/Roll back control and a sticky summary bar
- [x] Scheduler moves to a single Save action over schedule presets, with custom cron behind an Advanced disclosure
- [x] Dashboard, Analysis and Hardening restyled to match (security score shown as a bar everywhere, Title Case labels throughout)
- [x] Keyboard shortcuts updated: Ctrl+1-5 reach Dashboard, Analysis, Hardening, Hosts and Scheduler (Ctrl+4 lands on Hosts via the retained `/remote` redirect); Fleet Apply and Settings have no dedicated shortcut yet

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

### Compliance Assessment Coverage

All 10 frameworks now emit genuine Pass/Fail results via plugin-declared per-control
coverage (`coverage()` per plugin, aggregated by `hardener_plugins::compliance_coverage()`
and injected into `ReportGenerator`). CIS and ISO 27001:2022 keep curated catalogues
(full standard; unassessed controls → `ManualReview`). Non-CIS catalogues are derived
from coverage so each report uses a single id scheme with no placeholder noise.
`report --framework cis` shows 6 `ManualReview` (down from 17); all other frameworks
report zero `ManualReview` for covered controls.

| Task | Description | Priority | Status |
|------|-------------|----------|--------|
| Honest manual-review status | Stop reporting unassessed controls as `Pass` | High | ✅ Complete |
| Per-control multi-framework mappings | Plugins emit STIG/NIST/PCI-DSS/HIPAA/GDPR/ISO 27001 control IDs alongside CIS | High | ✅ Complete |
| Catalogue id reconciliation | Unify catalogue vs SSG-scheme ids for clean reports | Low | ✅ Complete (`frameworks::curated_controls` returns a hand-curated catalogue for CIS and ISO 27001 only; every other framework's catalogue is derived from live plugin coverage, so catalogue and findings share one identifier scheme) |
| Option B: `Pass` for checked-passing controls | Per-control coverage set; every non-CIS framework reports zero `ManualReview` | Low | ✅ Complete |
| CIS curated-catalogue coverage | 11 CIS controls now genuinely assessed; `report --framework cis` shows 6 `ManualReview` (from 17), the remainder genuinely out of scope | Medium | ✅ Complete |

### Additional Compliance Frameworks

| Framework | Description | Priority | Status |
|-----------|-------------|----------|--------|
| ISO/IEC 27001:2022 | 93 Annex A controls across 4 themes; catalogue implemented and findings mapped to the Technological theme | Medium | ✅ Complete |
| SOC 2 | Service organisation controls (AICPA Trust Services Criteria) | Low | ✅ Complete |
| FedRAMP | Federal Risk and Authorization Management Program | Low | ✅ Complete |
| NIST SP 800-171 | Rev 3 CUI requirements, crosswalked from the plugins' 800-53 controls | Low | ✅ Complete |

### Advanced Features

| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| SSH crypto-algorithm hardening | Harden `KexAlgorithms`/`Ciphers`/`MACs`, incl. post-quantum kex (`mlkem768x25519-sha256`, default in OpenSSH 10). Must detect supported algorithms (`ssh -Q kex`) and run `sshd -t` before restart to avoid lockout | High | ✅ Done |
| RHEL 10 compliance profiles | Report-time ID translation to DISA RHEL 10 STIG V1R1 and CIS RHEL 10 v1.0.1, auto-detected on RHEL-family 10 (`hardener-compliance/src/profiles.rs`) | Medium | ✅ Complete |
| Multi-host SSH management | Manage/monitor multiple hosts from one UI: host profiles, parallel scanning, trend history, regression alerts | Medium | ✅ Complete: CLI `batch scan/report/apply/rollback` + `history trends/regressions` + scheduler regression alerts; GUI Fleet scan/compliance/apply/rollback + ad-hoc SSH targets + live per-host progress + per-host history. Compliance-count drill-down remains open, issue #50 |
| nftables ruleset persistence | The nftables backend probes which file `nftables.service` actually loads on this host, rather than assuming one, and persists its ruleset through that path: `/etc/nftables.conf` on Arch and Debian, `/etc/sysconfig/nftables.conf` on Fedora and RHEL, `/etc/nftables/rules/main.nft` on openSUSE | High | ✅ Complete, issue #52 closed |
| Security audit (external) | Third-party security review; scope in [security/external-audit-scope.md](security/external-audit-scope.md) | Medium | ⬜ Open, issue #19 |
| Performance optimisation | Scan speed improvements; `scan --timings` shipped | Medium | ✅ Done, issue #20 closed 2026-07-17 |
| Internationalisation | Multi-language support | Low | ⬜ Pending |
| SELinux policy management | Full policy editing, not just detection | Low | ⬜ Pending |
| AppArmor profile editor | Create and manage AppArmor profiles | Low | ⬜ Pending |
| High Contrast theme | WCAG AAA accessibility theme | Low | ✅ Complete |

---

## Technical Debt & Improvements

| Item | Description | Priority | Status |
|------|-------------|----------|--------|
| Increase test coverage | Target 90%+ coverage | Low | Partial. The 90 per cent target is not met: `docs/reference/coverage-baseline.md` lists every file under 60 per cent and records `src-tauri/src/commands.rs` at 26.60 per cent. **No suite size is quoted here on purpose** - it moves with every commit, and the figure that stood in this sentence read 1991 from 2026-08-12, correct that day and two days later superseded by the 2054 the ledger measured. [evidence-ledger.md](reference/evidence-ledger.md) carries the current baseline and is the only place a count belongs |
| Consolidate `create_plugin_registry()` | Duplicated in CLI, report, Tauri | Low | ✅ Complete |
| Consolidate test mock plugins | Duplicated in registry.rs and plugin_manager_tests.rs | Low | ✅ Complete |
| Config file utilities | Duplicated parsing/backup in SSH and PAM plugins | Low | ✅ Complete |
| Refactor PAM plugin | Updated to use shared `file_utils` functions | Low | ✅ Complete |
| Package manager code duplication | Validation/execution duplicated in apt, dnf, zypper, pacman | Low | ✅ Complete |
| Remove duplicate registry in plugins.rs | Removed from plugins.rs and apply.rs | Low | ✅ Complete |
| Review field naming consistency | Audit complete: 2 violations fixed | Low | ✅ Complete |
| Gate or remove `testing` feature | Removed unused feature from hardener-core | Low | ✅ Complete |
| Extract inline tests out of their source files | Child module in its own file, not `tests/` | Low | ✅ Complete, issue #49, 2026-08-01 |
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
  - `validate_package_name()`: shared validation with distro-specific rules
  - `validate_package_names()`: batch validation helper
  - `execute_command()`: generic command runner with error handling
  - `parse_rpm_package_list()`: shared RPM output parser for dnf/zypper
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
| Database DTOs | ScanFinding, ScanFindingRow | Fields match database columns, acceptable for DTO boundary |
| Named aggregation | SeverityCounts | Struct name provides context |
| Framework conventions | Cli, SshConnectionConfig | Clap/SSH standard conventions |
| UI definitions | FrameworkScore, TabDef, PluginDef | Simple internal types with clear context |

### Test Restructure: issue #49

Complete as of 2026-08-01. Every source file in `crates/` and `src-tauri/src`
that held an inline `#[cfg(test)]` block now declares it instead, and the block
lives in its own file beside the code it exercises.

The destination was a decision rather than a style question. Most of these tests
read **private** items, so moving them under `tests/` would have meant widening
visibility to make them compile, and in a hardening tool a `pub` added to satisfy
a test is an API change in the wrong direction. Every one of them is therefore a
child module in its own file. `hardener-cli` had no choice at all: it is a binary
crate, so nothing can depend on it and an integration test was never available.

Three things settled along the way and are worth not re-deriving. A non-root
`foo.rs` takes `foo/tests.rs` beside it, which the 2018 path rules resolve with
no `mod.rs` and no `#[path]`, so `super` is unchanged and no moved line needs
editing. A `foo/mod.rs` **is** the module `foo`, so its tests go in the directory
it already owns. And a module that is not called `tests` keeps its own name in a
file of that name, following `src-tauri/src/acl_tests.rs`, which had been sitting
beside `main.rs` since 2026-07-18 and was the repository's own precedent.

Every split file opens with `#![cfg(test)]`. The declaration that pulls it in is
already gated, so this changes nothing about what is compiled; it is there
because three validators decide test context by looking for `cfg(test)` in the
file they are reading, and a moved test module without it is judged as
production code by all three.

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

The "Controls" column is the size of each framework's control **catalogue**.
For CIS and ISO 27001 that is the curated file's own size. For the other eight
it is the coverage-derived catalogue, so the number is the count of distinct
control ids `hardener_plugins::compliance_coverage()` supplies for that
framework and moves whenever a plugin gains or loses a mapping. **Five of these
rows carried the sizes of catalogue files that no longer exist** until
2026-08-18: `stig.rs`, `nist.rs`, `pci.rs`, `hipaa.rs` and `gdpr.rs` were
deleted when coverage-derived catalogues landed, and the figures written here on
2026-06-20 outlived them. Re-read them from the tool rather than from a file:
`hardener report --framework <id> --format json | jq '.[0].report_controls | length'`.
The CIS row stays the curated file's 41 by the definition above; that same
command renders **44** for CIS, because the generator folds plugin coverage into
the curated catalogue, and the two numbers answer different questions.
"Assessed" indicates whether plugin findings are mapped to the framework so
controls genuinely pass/fail. All 10 frameworks are finding-mapped and use
plugin-declared per-control coverage (Option B): an assessed control reports
`Pass` or `Fail`; an unassessed one reports `ManualReview`.

| Framework | Controls | Assessed | Description |
|-----------|----------|----------|-------------|
| CIS | 41 | ✅ Yes | Center for Internet Security Benchmarks |
| STIG | 22 | ✅ Yes | DISA Security Technical Implementation Guides |
| NIST 800-53 | 19 | ✅ Yes | US Federal security controls (Rev 5) |
| PCI-DSS | 8 | ✅ Yes | Payment Card Industry standards (v4.0) |
| HIPAA | 8 | ✅ Yes | Healthcare security requirements |
| GDPR | 6 | ✅ Yes | EU data protection (Article 32) |
| ISO/IEC 27001:2022 | 93 | ✅ Yes | Information security management (Annex A, 4 themes) |
| SOC 2 | 5 | ✅ Yes | AICPA Trust Services Criteria (2017, CC-series; coverage-derived) |
| NIST SP 800-171 | 14 | ✅ Yes | Revision 3 CUI requirements, crosswalked from 800-53 (coverage-derived) |
| FedRAMP | 19 | ✅ Yes | Moderate (Rev 5) baseline members among the 800-53 controls (coverage-derived) |

---

## Contributing

When working on new features:

1. Create a feature branch from `main`
2. Update ROADMAP.md with your progress
3. Ensure all tests pass (`cargo test`)
4. Run `cargo clippy` with no warnings
5. Submit PR for review

---

**Last Updated**: 2026-08-30
