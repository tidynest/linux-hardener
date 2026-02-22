# Next Development Session — Linux System Hardener

> **For the next assistant**: Read all markdown files and your memory carefully before starting. Here's the current state.

**Legend**: ⬜ Pending | 🔄 In Progress | ✅ Complete

---

## What happened this session (2026-02-22)

All 13 bugs from the comprehensive audit (`docs/COMPREHENSIVE_AUDIT_REPORT.md`) are now **fully fixed and committed**. The entire GUI→CLI apply pipeline is working. Build is clean.

### Commits this session:
```
2eb1b3c fix(cli): use system checkpoint path when running as root        ← BUG-11
64d9f74 fix(plugins): use executor abstraction for PAM file writes       ← BUG-10
037d0c4 fix(tauri): improve CLI binary discovery for development builds  ← BUG-09
8757db5 docs: update audit report with fix status markers
0d55037 fix(cli,tauri): fix sshd_config typo and timestamp formatting    ← BUG-12, BUG-13
b9ce945 fix(core,ui): repair GUI apply pipeline and add preview flow     ← BUG-01–07
```

### All 13 bugs fixed:
| Bug | Summary | Commit |
|-----|---------|--------|
| BUG-01 | JSON shape mismatch CLI↔Tauri (tuple vs flat array) | `b9ce945` |
| BUG-02 | camelCase→snake_case param names in Tauri bindings | `b9ce945` |
| BUG-03 | GUI errors invisible — added error banner component | `b9ce945` |
| BUG-04 | UFW matched `rule_description` instead of `rule_action` | `b9ce945` |
| BUG-05 | Firewall hardcoded `apply_success: true` | `b9ce945` |
| BUG-06 | CLI apply always exited 0 — now tracks failures | `b9ce945` |
| BUG-07 | Apply used empty `Config` — now loads `HardenerConfig` | `b9ce945` |
| BUG-08 | Nested tokio runtime panic in rollback | `bb124a5` (prior) |
| BUG-09 | Binary discovery — added `CARGO_MANIFEST_DIR` fallback | `037d0c4` |
| BUG-10 | PAM bypassed executor — now uses `ctx.executor().write_file()` | `64d9f74` |
| BUG-11 | Checkpoint path divergence — root uses `/var/lib`, GUI reads both | `2eb1b3c` |
| BUG-12 | `sshd.config` typo → `sshd_config` | `0d55037` |
| BUG-13 | Timestamp Debug format → chrono human-readable | `0d55037` |

### Working tree state:
- `docs/COMPREHENSIVE_AUDIT_REPORT.md` — modified (BUG-09, BUG-10, BUG-11 status markers need committing)
- `docs/FULL_AUDIT_REPORT.md` — untracked (redundant draft, can be deleted)
- `docs/audit-agent-outputs/` — untracked (raw agent output, skip)

**Build status**: `cargo check`, `cargo check -p hardener-ui --target wasm32-unknown-unknown`, `cargo test`, and `cargo clippy` all pass clean.

---

## What's next (priority order)

### 1. ⬜ Commit remaining doc update
`docs/COMPREHENSIVE_AUDIT_REPORT.md` has updated status markers for BUG-09/10/11 — needs a quick `git add && git commit`.

### 2. ⬜ Infrastructure issues (INFRA-01 through INFRA-07)
See `docs/COMPREHENSIVE_AUDIT_REPORT.md` § TIER 3 for full details.

| Issue | Description | Complexity |
|-------|-------------|------------|
| INFRA-01 | ✅ All uncommitted work now committed | Done |
| INFRA-02 | SSH auth failing to GitHub/GitLab remotes | Config fix |
| INFRA-03 | Version mismatch (0.3.2 vs 0.3.3 across files) | Find & replace |
| INFRA-04 | GUI/Tauri crates excluded from CI | `.github/workflows/ci.yml` |
| INFRA-05 | Four overlapping planning docs (NEXT/NEXT2/PLAN/PLAN2) | Consolidation |
| INFRA-06 | Tauri CSP disabled, no capabilities file | `tauri.conf.json` |
| INFRA-07 | Workspace dependency inconsistencies | `Cargo.toml` files |

### 3. ⬜ Trait refactor: `Config` → `HardenerConfig`
`HardeningPlugin::apply()` and `validate()` accept an empty `Config` unit struct. Should accept `HardenerConfig` so plugins can read per-plugin directives (enabled/disabled, custom settings, policy exceptions). Requires updating:
- `crates/hardener-core/src/plugin.rs` — trait definition
- All 8 plugin implementations in `crates/hardener-plugins/src/*/mod.rs`
- `crates/hardener-cli/src/commands/apply.rs` — pass `HardenerConfig` instead of `Config`

### 4. ⬜ GUI/CLI Feature Parity (Phase 2+)
See `docs/GUI_CLI_PARITY_PLAN.md` — Phase 1 (preview & apply) is complete.
- Phase 2: Scan filtering (severity dropdown, plugin selection) ← **next GUI work**
- Phase 3: Checkpoint management (create/delete)
- Phase 4: Report export (format selection, file save)
- Phase 5: Scan history tab
- Phase 6: Audit/compliance mode toggles

---

## Project Summary

**Linux System Hardener** is a comprehensive Linux security automation tool written in Rust. It's a mature workspace-based project with:

- **10 Core Crates + 1 Tauri App**
- **8 Security Plugins**: Kernel, SSH, Firewall, PAM, Services, Audit, Permissions, MAC
- **396+ Passing Tests**
- **Multi-Distribution Support**: Debian family (Ubuntu, Mint), Red Hat family (Fedora, RHEL, Rocky), Arch family, SUSE family
- **Current Version**: 0.3.3 (Development Release)
- **WASM Support**: GUI frontend compiles to `wasm32-unknown-unknown`

---

## Codebase Architecture

### Workspace Structure

```
/home/bakri/RustroverProjects/linux-system-hardener/
├── Cargo.toml (workspace root)
├── .cargo/config.toml       # WASM rustflags for getrandom
├── crates/
│   ├── hardener-types/      # WASM-compatible shared type definitions
│   ├── hardener-cli/        # CLI interface (entry point)
│   ├── hardener-core/       # Core scanning/execution engine
│   ├── hardener-plugins/    # 8 security hardening plugins
│   ├── hardener-scheduler/  # Daemon for scheduled scanning
│   ├── hardener-state/      # Checkpoint/audit trail (Ed25519 signed)
│   ├── hardener-compliance/ # PDF report generation (pdf feature)
│   ├── hardener-common/     # Shared utilities/errors
│   ├── hardener-distro/     # Distribution abstraction
│   └── hardener-ui/         # Leptos WASM frontend
├── src-tauri/               # Desktop application
├── docs/                    # Comprehensive documentation
└── scripts/                 # Utility scripts
```

### Crate Dependency Graph

```
hardener-cli (entry point)
  ├── hardener-core (engine)
  ├── hardener-plugins (scanners/appliers)
  ├── hardener-compliance (reporting)
  ├── hardener-scheduler (daemon)
  ├── hardener-state (audit trail)
  └── hardener-common (shared)

hardener-types (WASM-safe, no system deps)
  └── serde, chrono only

hardener-core
  ├── hardener-types
  ├── hardener-common
  └── hardener-state (optional)

hardener-plugins
  └── hardener-core

hardener-compliance
  ├── hardener-types
  ├── hardener-core (default-features = false)
  └── krilla (optional, pdf feature)

hardener-ui (WASM frontend)
  └── hardener-types (only!)

hardener-scheduler
  ├── hardener-core
  ├── hardener-plugins
  └── hardener-common
```

---

## Completed Development Phases

### Phase 1 — Scheduled Scanning Infrastructure ✅

The `hardener-scheduler` crate has fully implemented scheduled scanning.

| File | Purpose | Tests |
|------|---------|-------|
| `src/config.rs` | `SchedulerConfig`, `StorageConfig`, `NotificationConfig` structs | 5 |
| `src/db.rs` | `ScanHistoryManager` with SQLite (sqlx) | 5 |
| `src/json_store.rs` | Timestamped JSON exports with SHA-256 integrity | 4 |
| `src/runner.rs` | `ScanRunner` orchestrates plugin execution | 7 |
| `src/daemon.rs` | `Daemon` with cron scheduling, signal handling | 4 |

**CLI Commands**:

```bash
hardener daemon start     # Start scheduler daemon (blocks until Ctrl-C)
hardener daemon run-once  # Single immediate scan
hardener daemon status    # Show config and recent sessions
```

**Database Schema** (SQLite in `scheduler.db`):
- `scan_sessions` — Session metadata (ID, timestamps, status, trigger type, counts)
- `scan_findings` — Individual findings per session with compliance mappings
- `notification_log` — Notification delivery tracking

---

### Phase 2 — Notification System ✅

> Completed 2025-12-04

| File | Purpose | Tests |
|------|---------|-------|
| `src/notification/mod.rs` | `Notifier` trait, `NotificationResult`, severity helpers | 10 |
| `src/notification/email.rs` | `EmailNotifier` — SMTP via lettre with TLS | — |
| `src/notification/webhook.rs` | `WebhookNotifier` — Slack/Discord/Generic payloads | 13 |
| `src/notification/dispatcher.rs` | `NotificationDispatcher` — coordinates all channels | — |

**Key Features**:

- [x] `Notifier` trait: Async trait for notification channels with `send()` and `channel()` methods
- [x] `NotificationResult`: Captures success/failure with error messages for database logging
- [x] `EmailNotifier`: SMTP with STARTTLS, password via `HARDENER_SMTP_PASSWORD` env var
- [x] `WebhookNotifier`: Three payload formats (Slack attachments, Discord embeds, Generic JSON)
- [x] Header env var expansion: `${API_KEY}` syntax for secure header injection
- [x] Severity filtering: `meets_severity_threshold()` checks findings against `notify_min_severity`
- [x] Database logging: All attempts logged to `notification_log` table
- [x] Integration: `ScanRunner::run()` dispatches notifications after scan completion

**Configuration**:

```toml
[scheduler.notifications]
notify_min_severity = "critical"

[scheduler.notifications.email]
enabled = true
smtp_host = "mail.example.com"
smtp_port = 587
smtp_tls = true
smtp_username = "admin@example.com"
from_address = "hardener@example.com"
recipients = ["security-team@example.com"]

[scheduler.notifications.webhooks]
enabled = true

[[scheduler.notifications.webhooks.endpoints]]
name = "slack"
url = "https://hooks.slack.com/services/..."
format = "slack"
```

---

### Phase 3 — Systemd Integration ✅

> Completed 2025-12-05

| File | Purpose |
|------|---------|
| `crates/hardener-scheduler/src/systemd.rs` | `SystemdGenerator` for unit file generation |
| `crates/hardener-cli/src/commands/systemd.rs` | CLI commands for systemd management |

**Key Features**:

- [x] `SystemdGenerator`: Generates `.service` and `.timer` unit files
- [x] `cron_to_calendar()`: Converts 5-field cron expressions to systemd OnCalendar format
- [x] Security hardening: Service unit includes `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`
- [x] User/system modes: Install to user (`~/.config/systemd/user/`) or system (`/etc/systemd/system/`)

**CLI Commands**:

```bash
hardener systemd generate              # Output unit files to stdout
hardener systemd generate -o /path/    # Write to directory
hardener systemd install               # Install system service (requires root)
hardener systemd install --user        # Install user service
hardener systemd uninstall             # Remove system service
hardener systemd uninstall --user      # Remove user service
hardener systemd status                # Show timer/service status
```

---

### Phase 4 — History CLI Commands ✅

> Completed 2025-12-05

| File | Purpose |
|------|---------|
| `crates/hardener-cli/src/commands/history.rs` | History command implementations |
| `crates/hardener-cli/src/cli.rs` | Added `HistoryAction` enum and `History` command |

**CLI Commands**:

```bash
hardener history list                        # List recent scan sessions
hardener history list --limit 50             # Show more sessions
hardener history list --host srv1            # Filter by host
hardener history list --status completed     # Filter by status
hardener history show <session-id>           # Show session details and findings
hardener history export <id>                 # Export session to JSON file
hardener history export <id> -o /path/file   # Custom output path
```

---

### Phase 5 — WASM Compilation Fix ✅

> Completed 2025-12-05

- [x] Created `hardener-types` crate with WASM-safe dependencies (serde, chrono only)
- [x] Extracted shared types from hardener-common, hardener-core, hardener-compliance
- [x] Feature-gated krilla PDF library behind `pdf` feature in hardener-compliance
- [x] Updated hardener-ui to depend only on hardener-types
- [x] Added `.cargo/config.toml` for getrandom WASM backend configuration
- [x] Added `#[wasm_bindgen(start)]` entry point for Leptos app mounting
- [x] GUI compiles to `wasm32-unknown-unknown` and runs in browser/Tauri

> **Implementation Details**: See [docs/WASM_FIX_PLAN.md](docs/WASM_FIX_PLAN.md)

---

### Phase 6 — Browser Mode Fix ✅

> Completed 2025-12-06

**Problem**: Web UI (browser mode) failed to render page content.

**Root Cause**: `tauri_bindings.rs` called `window.__TAURI__.core.invoke` without checking if Tauri was available, causing JavaScript errors that crashed Leptos reactivity.

**Solution**: Added `is_tauri_available()` inline JS function and `tauri_available()` Rust wrapper. All Tauri commands now return early with error if running in browser mode.

**Result**: Web UI fully functional — Dashboard, Analysis (Findings/Compliance tabs), Hardening (Configure/History tabs) all render correctly.

---

## v0.3.1 — GUI Polish & Testing ✅

> Completed 2025-12-06

### A. GUI Fixes

- [x] Fixed "Loading..." text persistence by mounting app to `#app` element
- [x] Added dark terminal theme with CSS Variables, JetBrains Mono + Inter fonts
- [x] Security score now shows "--/100" before scan with "Run a scan to see your score"
- [x] "View Findings" now uses styled button with programmatic navigation
- [x] All 3 pages styled: Dashboard, Analysis (tabbed), Hardening (sectioned)
- [x] Timestamp formatting: Checkpoints page now shows human-readable dates
- [x] Browser mode fix: Added `tauri_available()` check in `tauri_bindings.rs`
  - Web UI renders all pages correctly without Tauri desktop wrapper
  - Commands return graceful errors in browser mode instead of crashing Leptos

### B. State Persistence

- [x] Scan results persist via `scan_sessions`, `scan_results`, `scan_findings` tables
- [x] GUI loads latest scan results on mount via `get_latest_scan` Tauri command
- [x] 4 unit tests for `ScanHistoryManager` all passing
- [x] Full integration test passed (8/8 Web UI tests, database verification complete)

### C. Testing Infrastructure

- [x] Safe testing environment implemented using systemd-nspawn container
- [x] CLI functional test results: 27/27 tests pass
- [x] Root functional test results: 35/36 tests pass (1 skip is test script pattern matching)
- [x] Bug M fixed: Scheduler database now uses user path for non-root users

> **Test Results**: See [docs/CLI_V032_TEST_RESULTS.md](docs/CLI_V032_TEST_RESULTS.md)

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

## v0.3.2 — Frontend Layout & Accessibility ✅

> Completed 2025-12-08

> **Implementation Guide**: See [docs/FRONTEND_LAYOUT_PLAN.md](docs/FRONTEND_LAYOUT_PLAN.md)

### A. Layout Fixes (Session 1)

- [x] Added `min-width: 0` to `.navigation`, `.nav-links`, `.header-content`, `.activity-content`
- [x] Updated grid templates: `.dashboard-grid`, `.scanner-layout`, `.detail-values dl`, `.report-summary`
- [x] Added utility classes: `.truncate`, `.line-clamp-2`, `.line-clamp-3`, `.sr-only`, `.min-w-0`, `.skip-link`
- [x] Skip link as first focusable element with `<main id="main-content" tabindex="-1">`
- [x] Tab components: `aria-controls`, `aria-labelledby`, `tabindex` management, unique IDs

### B. Responsive Layout (Session 2)

- [x] Spacing scale: `--space-xs` to `--space-2xl` in `:root`
- [x] Utility classes in `styles.css`: `.flex`, `.flex-col`, `.grid`, `.gap-*`, `.items-*`, `.justify-*`
- [x] Viewport testing complete: 320px, 640px, 1920px
- [x] Touch targets: 44px minimum via `@media (pointer: coarse)`
- [x] Card component in `card.rs` with `Card`, `CardVariant`, `HeadingLevel`
- [x] All section components refactored to use Card component

### C. Theme & Accessibility (Session 3)

- [x] Colour contrast audit: Brightened `--text-secondary` and `--text-muted` to meet WCAG AA 4.5:1 ratio
- [x] CSS `[data-theme="..."]` selectors for Fortress, Sentinel, Command, Guardian, Daywatch themes
- [x] ThemeToggle component in `theme_toggle.rs` with dropdown UI
- [x] Theme persistence via localStorage, applies on page load
- [x] Added "Storage" feature to web-sys in Cargo.toml for localStorage access
- [x] Visual testing completed for all themes via Playwright MCP

### D. Polish & Testing (Session 4)

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

### E. Final Polish (Session 5)

- [x] Tab animation reduced from 250ms to 120ms for snappier switching
- [x] Tab transform reduced from 8px to 4px for subtler motion
- [x] Navigation title now uses `--color-accent` (adapts to each theme's identity colour)
- [x] Created `docs/THEME_DESIGN_GUIDE.md` with comprehensive theme creation documentation

### F. GUI Bug Fixes (Session 6)

| Issue | Description | Status |
|-------|-------------|--------|
| H | Score mismatch Dashboard vs Analysis pages | ✅ Complete |
| I | 11 findings — PAM false positives (pwquality.conf missing on Arch) | ⬜ Deferred |
| J | "Generate Reports" button gives no visual feedback | ✅ Complete |
| K | Checkpoints not visible in UI after Apply Hardening | ✅ Complete |
| L | Theme selector text unreadable (same color as background) | ✅ Complete |

**Issue H Fix**: Unified `calculate_all_scores()` function shared between `SecurityScore` and `MiniSecurityScore` components.

**Issue J Fix**: Added `status_message` reactive signal with success/error display styling.

**Issue K Fix**: `get_checkpoints()` in `commands.rs` now reads from both user (`~/.local/share/linux-hardener/checkpoints.db`) and system (`/var/lib/linux-hardener/checkpoints.db`) databases and merges results.

**Issue L Fix**: Added `appearance: none` CSS reset with custom SVG dropdown arrow for WebKit compatibility.

**Issue I Details**: PAM findings are valid on Ubuntu/Debian but not actionable on Arch Linux where `pwquality.conf` doesn't exist by default. Not a bug — Arch uses `pam_unix` not `pam_pwquality`. May add distribution-specific handling in future.

**Files Changed**:
- `src-tauri/src/commands.rs` — Dual database reading for checkpoints
- `crates/hardener-ui/src/components/mini_security_score.rs` — Use shared scoring
- `crates/hardener-ui/src/components/security_score.rs` — Export `calculate_all_scores()`
- `crates/hardener-ui/src/components/compliance_tab.rs` — Status message feedback
- `crates/hardener-ui/src/components/history_section.rs` — Refresh button
- `crates/hardener-ui/styles.css` — Theme selector CSS, status messages

---

## v0.3.3 — Distribution Validation ✅

> Completed 2025-12-11

| Distribution | Family | Version | Tests | Pass | Fail | Skip | Status |
|--------------|--------|---------|-------|------|------|------|--------|
| Arch Linux | Arch | Rolling (LTS 6.12) | 102 | 102 | 0 | 1 | ✅ Complete |
| Debian | Debian | 12 (Bookworm) | 102 | 102 | 0 | 1 | ✅ Complete |
| Fedora | Red Hat | 41 | 102 | 102 | 0 | 1 | ✅ Complete |
| openSUSE | SUSE | Leap 15.6 | 102 | 102 | 0 | 1 | ✅ Complete |

> **Note on family coverage**: Each validated distribution covers its entire family. Debian covers Ubuntu/Mint/Pop!_OS/elementary; Fedora covers RHEL/CentOS/Rocky/Alma/Oracle Linux; openSUSE covers SLES; Arch covers Manjaro/EndeavourOS/Garuda.

> **Test Results**: See [docs/DISTRIBUTION_VALIDATION.md](docs/DISTRIBUTION_VALIDATION.md)

---

## Bug Fixes Summary

### Fixed Bugs

| Bug | Description | Severity | Fix Applied |
|-----|-------------|----------|-------------|
| D | UFW false positive when not root | Medium | Uses `systemctl is-active ufw` first (doesn't need root) |
| E | Audit rules false positives | Medium | Detects permission denied from `auditctl -l`, skips rule findings |
| F | Stub `validate()` methods | Medium | All three now properly report estimated changes |
| G | Kernel rollback gap | High | `apply()` creates `/etc/sysctl.d/99-hardener.conf`, rollback removes it |
| M | Scheduler database hardcoded path | Medium | Added `default_data_dir()` helper for user path fallback |
| O | Checkpoint not created during apply | Critical | Fixed context creation to include checkpoint manager |
| P | Nested tokio runtime panic | Critical | Made `create_checkpoint_for_apply()` async |
| Q | Invalid plugin name accepted silently | Medium | Added `validate_plugin_filter()` in `scan.rs` |
| R | Test script showed 105% pass rate | Low | Added `log_check()` for verification steps |

### Bug-Exposing Tests Added

- `firewall_mock_tests.rs`: `test_firewall_scan_permission_denied_should_not_report_disabled` — ✅ Passing
- `audit_mock_tests.rs`: `test_audit_scan_permission_denied_should_not_report_missing_rules` — ✅ Passing

---

## Theme System

> Updated 2025-12-09

Five security-focused themes in `crates/hardener-ui/themes/`:

| Theme | Description | Colour Scheme |
|-------|-------------|---------------|
| **Fortress** | Deep slate-blue with gold accents | Vault-like, enterprise feel |
| **Sentinel** | Warm charcoal with amber | Vigilant, cozy |
| **Command** | Deep navy with ice-blue | Military precision, high-tech |
| **Guardian** | Forest black with emerald | Natural protection, calming |
| **Daywatch** | Warm off-white with teal | Light mode for daytime |

**Features**:
- [x] All themes tested via Playwright MCP in browser mode
- [x] Theme selection UI implemented (ThemeToggle dropdown in navigation)
- [x] Title colour now uses `--color-accent` (adapts to each theme's identity colour)
- [x] Tab animation reduced from 250ms to 120ms for snappier feel
- [x] Theme Design Guide created: `docs/THEME_DESIGN_GUIDE.md`
- [ ] High Contrast theme for WCAG AAA accessibility

---

## Security Score Algorithm

> Updated 2025-12-09

**New Algorithm** (Issues A-C fixed):
- Based on compliance framework control pass/fail with severity weighting
- Pass = 100pts, Critical fail = 0pts, High = 25pts, Medium = 50pts, Low = 75pts, Info = 90pts
- Overall score = average of all framework weighted scores

**Files Changed**:
- `security_score.rs` — New `calculate_framework_score()` and `calculate_all_scores()` functions
- `quick_actions.rs` — Now generates compliance reports after scan for all 6 frameworks
- `styles.css` — Added `.score-breakdown` styles for framework detail display

**New UI Features**:
- Expandable "Framework Breakdown" showing per-framework scores (CIS, STIG, NIST, etc.)
- Each framework shows weighted score + pass/total count
- Colour-coded by score level (green/yellow/red)

---

## CLI Verification Summary

| Category | Count | Accuracy |
|----------|-------|----------|
| Kernel | 4 | ✅ All correct |
| FileSystem | 2 | ✅ All correct |
| Authentication | 8 | ✅ All correct |
| Network | 0-1 | ✅ Fixed — no false positive when permission denied |
| Audit | 0-25 | ✅ Fixed — no false positives when permission denied |

**Non-Root Tests (Host)**:

| Category | Pass | Fail | Notes |
|----------|------|------|-------|
| Basic commands | 5/5 | 0 | All working |
| Scan operations | 6/6 | 0 | Severity filter, exit code work |
| Report generation | 10/10 | 0 | All 6 frameworks, all formats |
| Apply/dry-run | 5/5 | 0 | Estimated changes shown (Bug F fixed) |
| Checkpoint | 1/1 | 0 | List works |
| Daemon/History | 2/2 | 0 | ✅ Fixed — user dir fallback |
| Systemd | 2/2 | 0 | Generate/status work |
| SSH remote | 1/1 | 0 | Error handling works |
| **Total** | **27/27** | **0** | 100% pass rate |

> Full results in `docs/CLI_V032_TEST_RESULTS.md`

---

## Current Session Progress (2025-12-11)

### Completed This Session

- [x] Removed unused `testing` feature from `hardener-core/Cargo.toml`
- [x] Field Naming Convention Audit — Comprehensive audit of all 11 crates + src-tauri
- [x] Fixed critical field naming issues:
  - `MockPlugin`: `dependencies` → `plugin_dependencies`, `fail_scan` → `plugin_fail_scan`, `fail_apply` → `plugin_fail_apply`
  - `ServiceDirective`: `service_issue_severity` → `service_severity`
- [x] Removed stale `#[cfg(feature = "testing")]` in `hardener-core/src/lib.rs`
- [x] Added framework descriptions to compliance reports (Text, HTML, JSON, PDF, CSV)
- [x] Phase 1: Preview & Apply Flow (GUI/CLI Parity):
  - Added `run_apply_dry_run` Tauri command
  - Added `invoke_apply_dry_run` frontend binding
  - Preview panel shows estimated changes grouped by plugin
  - Fixed plugin ID mismatch in `apply.rs`
  - Fixed CLI output.rs inverted match arms

---

## Next Steps

### v0.4.0 — GUI/CLI Feature Parity

> **Implementation Guide**: See [docs/GUI_CLI_PARITY_PLAN.md](docs/GUI_CLI_PARITY_PLAN.md)

| Phase | Feature | Priority | Status |
|-------|---------|----------|--------|
| 1 | Dry-run preview | P0 | ✅ Complete |
| 2 | Scan filtering (severity, plugin) | P0 | ⬜ Next |
| 3 | Checkpoint management (create, delete) | P1 | ⬜ Pending |
| 4 | Report export (file, format selection) | P1 | ⬜ Pending |
| 5 | Scan history (list, show) | P2 | ⬜ Pending |
| 6 | Mode toggles (audit, compliance) | P2 | ⬜ Pending |

### Low Priority

- [ ] Extract inline tests to `tests/` directories
- [ ] Add High Contrast theme for WCAG AAA accessibility

---

## Key Naming Conventions

From `docs/NAMING_CONVENTIONS.md`:

| Category | Convention | Example |
|----------|------------|---------|
| Crates | kebab-case | `hardener-scheduler` |
| Modules | snake_case | `notification` |
| Structs/Traits | PascalCase | `EmailNotifier`, `Notifier` |
| Functions/Variables | snake_case | `send_notification` |
| Constants | SCREAMING_SNAKE_CASE | `DEFAULT_SMTP_PORT` |
| Field names | Prefixed | `smtp_host`, `webhook_url` |
| Plugin structs | `<Domain>HardeningPlugin` | `KernelHardeningPlugin` |

### Scheduler/Daemon Domain

| Pattern | Example |
|---------|---------|
| Config structs | `SchedulerConfig`, `StorageConfig`, `NotificationConfig` |
| Database managers | `ScanHistoryManager`, `JsonStore` |
| Daemon components | `Daemon`, `ScanRunner` |
| CLI commands | `daemon start`, `daemon run-once`, `daemon status` |

---

## Code Quality Standards

### Must Follow

- **Secure-by-default design** — all input validated
- **No code duplication** — even for short sections
- **Short, readable, efficient code**
- **British English throughout** (colour, authorise, minimisation)
- **>90% test coverage** for new code
- **Pass `cargo clippy`** without warnings
- **NO AI attributions** anywhere in project

### Commit Format (Conventional Commits)

```
<type>(<scope>): <description>
```

**Types**: feat, fix, docs, style, refactor, perf, test, build, ci, chore, security

**Scopes**: cli, core, plugins, config, state, compliance, ui, deps, scheduler

---

## Documentation Files to Update

After making changes, update these files:

| File | Content to Update |
|------|-------------------|
| `README.md` | Feature descriptions, version |
| `PLAN.md` | Progress tracking (mark items complete) |
| `CHANGELOG.md` | Version history entries |
| `docs/ARCHITECTURE.md` | System design diagrams |
| `docs/DATA_FLOW.md` | Data flow descriptions |
| `docs/FILE_MAP.md` | New files and exports |
| `docs/NAMING_CONVENTIONS.md` | New types/patterns |

---

## Critical Files Reference

### Scheduler Crate Entry Points

| File | Key Types/Functions |
|------|---------------------|
| `crates/hardener-scheduler/src/lib.rs` | Module exports |
| `crates/hardener-scheduler/src/config.rs` | `SchedulerConfig`, `EmailConfig`, `WebhookConfig` |
| `crates/hardener-scheduler/src/daemon.rs` | `Daemon::new()`, `start()`, `run_once()` |
| `crates/hardener-scheduler/src/runner.rs` | `ScanRunner::run()`, `ScanSummary` |
| `crates/hardener-scheduler/src/db.rs` | `ScanHistoryManager`, `log_notification()` |

### CLI Daemon Commands

| File | Content |
|------|---------|
| `crates/hardener-cli/src/commands/daemon.rs` | `start`, `run_once`, `status` subcommands |
| `crates/hardener-cli/src/cli.rs` | Clap argument definitions |

### Existing Error Types

Location: `crates/hardener-common/src/error.rs` — `HardeningError` enum

Add new variants if needed:

```rust
// Example additions for notification errors
NotificationFailed { channel: String, reason: String },
SmtpConnectionFailed { host: String, error: String },
WebhookRequestFailed { url: String, status: u16 },
```

---

## Testing Patterns

### Mock-Based Testing

The project uses `MockExecutor` for isolated testing. See:
- `crates/hardener-plugins/tests/` — 80+ plugin mock tests
- `crates/hardener-scheduler/src/*.rs` — Each module has inline tests

### Test Conventions

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_descriptive_name() {
        // Arrange
        // Act
        // Assert
    }
}
```

---

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `HARDENER_SMTP_PASSWORD` | SMTP password for email notifications |
| `${VAR}` in webhook headers | Substituted at runtime |

---

## Database Paths

| Path | Purpose |
|------|---------|
| `~/.local/share/linux-hardener/checkpoints.db` | Checkpoint storage |
| `/var/lib/linux-hardener/scheduler.db` | Scan history (root) |
| `~/.local/share/linux-hardener/scheduler.db` | Scan history (user) |
| `/var/lib/linux-hardener/scans/` | JSON exports (root) |

---

## Quick Start Commands

```bash
# Build and test
cargo build
cargo test
cargo clippy

# Run specific crate tests
cargo test -p hardener-scheduler

# Run the CLI
./target/debug/hardener --help
./target/debug/hardener daemon status

# Run desktop app (Wayland workaround)
WEBKIT_DISABLE_COMPOSITING_MODE=1 cargo tauri dev

# Run web app in browser (no Tauri required)
cd crates/hardener-ui && trunk serve --port 1420
# Open http://127.0.0.1:1420/ in browser

# Build WASM frontend only
cd crates/hardener-ui && trunk build

# Verify WASM compilation
cargo check -p hardener-ui --target wasm32-unknown-unknown
```

### Web App vs Desktop App

| Feature | Web App (Browser) | Desktop App (Tauri) |
|---------|-------------------|---------------------|
| Run scans | ❌ No backend | ✅ Full functionality |
| Apply hardening | ❌ No backend | ✅ With pkexec |
| View compliance | ❌ No backend | ✅ Full functionality |
| Navigate pages | ✅ Works | ✅ Works |
| Dark terminal theme | ✅ Works | ✅ Works |

The web app is useful for UI development and testing without needing Tauri. All pages render correctly, but Tauri commands (scan, apply, etc.) return errors gracefully with "Tauri not available" messages.

---

## Development Workflow

### Pre-Flight Checks Protocol

Before starting any development operation, verify the system state to prevent duplicate processes and port conflicts.

#### Before Starting Development Server

```bash
# Step 1: Check if Trunk/dev server already running
lsof -i :1420 2>/dev/null && echo "STOP: Port 1420 in use" || echo "Port 1420 available"

# Step 2: Check for existing Tauri processes
pgrep -f "tauri" && echo "STOP: Tauri already running" || echo "No Tauri process"

# Step 3: Kill existing processes if needed
lsof -ti:1420 | xargs kill -9 2>/dev/null
pkill -f "linux-system-hardener" 2>/dev/null
```

**Rule**: IF port 1420 in use → MUST kill existing process before proceeding.

#### Before Opening Browser Windows

1. Check if browser window already exists for this URL
2. IF window exists → reuse existing window, DO NOT open new one
3. IF no window → proceed with opening single instance

```bash
# Check for existing debug browser
curl -s http://localhost:9222/json/version >/dev/null 2>&1 && echo "Browser debug port active" || echo "No debug browser"
```

#### Before Taking Screenshots

1. Verify viewport is exactly 1920x1080
2. Wait for page to reach network idle state
3. Confirm no loading spinners or skeleton states visible
4. IF viewport wrong → reset to 1920x1080 before capture

### Development Server Launch

**Always use the launch script** for reliable Tauri development:

```bash
# Recommended: Use the bulletproof launch script
./scripts/tauri-dev.sh

# Or with verbose output
./scripts/tauri-dev.sh -v
```

The script automatically:
- Detects Wayland/Hyprland session
- Sets `WEBKIT_DISABLE_DMABUF_RENDERER=1` for NVIDIA GPUs
- Sets `WEBKIT_DISABLE_COMPOSITING_MODE=1` for Hyprland
- Verifies required packages are installed
- Checks for wasm32 target

**Manual launch** (if script unavailable):

```bash
WEBKIT_DISABLE_COMPOSITING_MODE=1 cargo tauri dev
```

### What NOT To Do

- DO NOT run `trunk serve` separately (Tauri runs it via `beforeDevCommand`)
- DO NOT run `cargo tauri dev` without Wayland environment variables
- DO NOT start multiple instances without killing previous
- DO NOT change viewport size during screenshot sessions

### Error Handling Guidelines

#### When Commands Fail

1. Read full error message, identify root cause
2. Check if error is recoverable (port conflict, missing dep)
3. IF recoverable → attempt single automatic fix
4. IF fix fails OR error unclear → STOP and explain to user

**Rule 0**: When anything fails unexpectedly, STOP. Explain what happened. Wait for user guidance.

#### Automatic Retry Scenarios

| Error | Recovery Action |
|-------|-----------------|
| Port conflict | Kill existing process, retry once |
| Missing wasm32 target | Run `rustup target add wasm32-unknown-unknown`, retry |
| Trunk not found | Run `cargo install trunk`, retry |
| Network timeout | Wait 5 seconds, retry once |

#### DO NOT Auto-Retry

- Compilation errors (require code changes)
- Permission denied errors (require user intervention)
- Configuration errors (require manual review)
- Any error that occurred twice already

### Session Cleanup

When ending a session or before switching contexts:

```bash
# Kill development processes
pkill -f "trunk serve" 2>/dev/null
pkill -f "tauri" 2>/dev/null
pkill -f "linux-system-hardener" 2>/dev/null

# Kill debug browsers
pkill -f "remote-debugging-port=9222" 2>/dev/null

# Verify ports released
lsof -i :1420 2>/dev/null || echo "Port 1420 released"
lsof -i :9222 2>/dev/null || echo "Port 9222 released"
```

---

## User Interaction Style

The user prefers:
- **Code in portions** (100-150 lines max)
- **Full explanations** of what code does
- **Placement instructions** with line numbers
- **Interactive discussion** before adding code
- To **add code themselves** unless they say otherwise

Treat the user as a trainee you're guiding through the project. Explain connections between scripts and functionalities.

---

## Always Remember

- Update documentation after changes
- Follow naming conventions strictly
- No AI attributions
- British English
- Code must pass clippy

---

*This document was prepared for continuity between development sessions.*

**Last Updated**: 2025-12-12
