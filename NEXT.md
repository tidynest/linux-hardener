# Next Development Session - Linux System Hardener

> **For the next assistant**: This document contains comprehensive findings and development plans for continuing work on this project. Read this thoroughly before starting.

---

## Project Summary

**Linux System Hardener** is a comprehensive Linux security automation tool written in Rust. It's a mature workspace-based project with:

- **10 Core Crates + 1 Tauri App**
- **8 Security Plugins**: Kernel, SSH, Firewall, PAM, Services, Audit, Permissions, MAC
- **378+ Passing Tests**
- **Multi-Distribution Support**: Ubuntu, Debian, Fedora, RHEL, Arch, openSUSE
- **Current Version**: 0.3.2 (Development Release)
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

## Current Development State

### Phase 1: COMPLETE - Scheduled Scanning Infrastructure

The `hardener-scheduler` crate has fully implemented Phase 1:

#### Completed Components

| File | Purpose | Tests |
|------|---------|-------|
| `src/config.rs` | `SchedulerConfig`, `StorageConfig`, `NotificationConfig` structs | 5 tests |
| `src/db.rs` | `ScanHistoryManager` with SQLite (sqlx) | 5 tests |
| `src/json_store.rs` | Timestamped JSON exports with SHA-256 integrity | 4 tests |
| `src/runner.rs` | `ScanRunner` orchestrates plugin execution | 7 tests |
| `src/daemon.rs` | `Daemon` with cron scheduling, signal handling | 4 tests |

#### CLI Commands (Implemented)

```bash
hardener daemon start     # Start scheduler daemon (blocks until Ctrl-C)
hardener daemon run-once  # Single immediate scan
hardener daemon status    # Show config and recent sessions
```

#### Database Schema (SQLite)

Three tables in `scheduler.db`:
- `scan_sessions`: Session metadata (ID, timestamps, status, trigger type, counts)
- `scan_findings`: Individual findings per session with compliance mappings
- `notification_log`: Notification delivery tracking

---

### Phase 2: COMPLETE - Notification System ✅

**Completed 2025-12-04**

#### Implemented Files

| File | Purpose | Tests |
|------|---------|-------|
| `src/notification/mod.rs` | `Notifier` trait, `NotificationResult`, severity helpers | 10 |
| `src/notification/email.rs` | `EmailNotifier` - SMTP via lettre with TLS | - |
| `src/notification/webhook.rs` | `WebhookNotifier` - Slack/Discord/Generic payloads | 13 |
| `src/notification/dispatcher.rs` | `NotificationDispatcher` - coordinates all channels | - |

#### Key Features

- **`Notifier` trait**: Async trait for notification channels with `send()` and `channel()` methods
- **`NotificationResult`**: Captures success/failure with error messages for database logging
- **`EmailNotifier`**: SMTP with STARTTLS, password via `HARDENER_SMTP_PASSWORD` env var
- **`WebhookNotifier`**: Three payload formats (Slack attachments, Discord embeds, Generic JSON)
- **Header env var expansion**: `${API_KEY}` syntax for secure header injection
- **Severity filtering**: `meets_severity_threshold()` checks findings against `notify_min_severity`
- **Database logging**: All attempts logged to `notification_log` table
- **Integration**: `ScanRunner::run()` dispatches notifications after scan completion

#### Configuration (unchanged from design)

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

### Phase 3: COMPLETE - Systemd Integration ✅

**Completed 2025-12-05**

#### Implemented Files

| File | Purpose |
|------|---------|
| `crates/hardener-scheduler/src/systemd.rs` | `SystemdGenerator` for unit file generation |
| `crates/hardener-cli/src/commands/systemd.rs` | CLI commands for systemd management |

#### Key Features

- **`SystemdGenerator`**: Generates `.service` and `.timer` unit files
- **`cron_to_calendar()`**: Converts 5-field cron expressions to systemd OnCalendar format
- **Security hardening**: Service unit includes `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`
- **User/system modes**: Install to user (`~/.config/systemd/user/`) or system (`/etc/systemd/system/`)

#### CLI Commands

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

### Phase 4: COMPLETE - History CLI Commands ✅

**Completed 2025-12-05**

#### Implemented Files

| File | Purpose |
|------|---------|
| `crates/hardener-cli/src/commands/history.rs` | History command implementations |
| `crates/hardener-cli/src/cli.rs` | Added `HistoryAction` enum and `History` command |

#### CLI Commands

```bash
hardener history list              # List recent scan sessions
hardener history list --limit 50   # Show more sessions
hardener history list --host srv1  # Filter by host
hardener history list --status completed  # Filter by status
hardener history show <session-id> # Show session details and findings
hardener history export <id>       # Export session to JSON file
hardener history export <id> -o /path/to/file.json  # Custom output path
```

---

## Key Naming Conventions

From `docs/NAMING_CONVENTIONS.md` (1600 lines):

| Category | Convention | Example |
|----------|------------|---------|
| Crates | kebab-case | `hardener-scheduler` |
| Modules | snake_case | `notification` |
| Structs/Traits | PascalCase | `EmailNotifier`, `Notifier` |
| Functions/Variables | snake_case | `send_notification` |
| Constants | SCREAMING_SNAKE_CASE | `DEFAULT_SMTP_PORT` |
| Field names | Prefixed | `smtp_host`, `webhook_url` |
| Plugin structs | `<Domain>HardeningPlugin` | `KernelHardeningPlugin` |

### Scheduler/Daemon Domain (Recently Added)

| Pattern | Example |
|---------|---------|
| Config structs | `SchedulerConfig`, `StorageConfig`, `NotificationConfig` |
| Database managers | `ScanHistoryManager`, `JsonStore` |
| Daemon components | `Daemon`, `ScanRunner` |
| CLI commands | `daemon start`, `daemon run-once`, `daemon status` |

---

## Code Quality Standards

### Must Follow
- **Secure-by-default design** - all input validated
- **No code duplication** - even for short sections
- **Short, readable, efficient code**
- **British English throughout** (colour, authorise, minimisation)
- **>90% test coverage** for new code
- **Pass `cargo clippy`** without warnings
- **NO AI attributions** anywhere in project

### Commit Format (Conventional Commits)
```
<type>(<scope>): <description>
```

**Types:** feat, fix, docs, style, refactor, perf, test, build, ci, chore, security

**Scopes:** cli, core, plugins, config, state, compliance, ui, deps, scheduler

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

| Location | Error Type |
|----------|------------|
| `crates/hardener-common/src/error.rs` | `HardeningError` enum |

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
- `crates/hardener-plugins/tests/` - 80+ plugin mock tests
- `crates/hardener-scheduler/src/*.rs` - Each module has inline tests

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

# Browser automation via Playwright MCP (recommended for UI testing)
# Configure playwright-brave in .mcp.json, then use mcp__playwright-brave__browser_navigate
# IMPORTANT: Close any existing dev browser windows before starting automation
# See docs/browser-automation.md for complete setup instructions

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

## Summary of Next Steps

1. **Completed**: Notification system (Phase 2) ✅
   - `Notifier` trait with `NotificationResult`
   - `EmailNotifier` (SMTP via lettre)
   - `WebhookNotifier` (Slack/Discord/Generic)
   - `NotificationDispatcher` integration with `ScanRunner`
   - 23 new tests (48 total in scheduler crate)

2. **Completed**: Systemd integration (Phase 3) ✅
   - `SystemdGenerator` for `.service` and `.timer` unit files
   - `cron_to_calendar()` for cron expression conversion
   - CLI commands: `generate`, `install`, `uninstall`, `status`
   - 9 new tests (57 total in scheduler crate)

3. **Completed**: History CLI commands (Phase 4) ✅
   - `history list` with `--limit`, `--host`, `--status` filters
   - `history show <session-id>` with detailed findings
   - `history export <session-id>` to JSON file
   - 6 new CLI tests (31 total in hardener-cli)

4. **Completed**: WASM Compilation Fix ✅
   - Created `hardener-types` crate with WASM-safe dependencies
   - Extracted shared types from hardener-common, hardener-core, hardener-compliance
   - Feature-gated krilla PDF library behind `pdf` feature
   - Updated hardener-ui to depend only on hardener-types
   - Added `.cargo/config.toml` for getrandom WASM backend
   - Added `#[wasm_bindgen(start)]` entry point for Leptos app
   - GUI now compiles to `wasm32-unknown-unknown` and runs in browser/Tauri

5. **Completed**: Browser Mode Fix ✅
   - **Problem**: Web UI (browser mode) failed to render page content
   - **Root cause**: `tauri_bindings.rs` called `window.__TAURI__.core.invoke` without checking if Tauri was available, causing JavaScript errors that crashed Leptos reactivity
   - **Solution**: Added `is_tauri_available()` inline JS function and `tauri_available()` Rust wrapper
   - All Tauri commands now return early with error if running in browser mode
   - Web UI fully functional: Dashboard, Analysis (Findings/Compliance tabs), Hardening (Configure/History tabs)

6. **Next Tasks**:
   - v0.3.1: GUI Polish & Testing (see PLAN.md) - **MOSTLY COMPLETE**
     - ✅ CLI functional testing complete (27/27 tests pass)
     - ✅ Safe testing environment created (systemd-nspawn container)
   - v0.3.2: Frontend Layout & Accessibility - See [docs/FRONTEND_LAYOUT_PLAN.md](docs/FRONTEND_LAYOUT_PLAN.md) for detailed session breakdown:
     - ✅ Session 1: Critical overflow fixes (`min-width: 0`, grid templates, skip links, ARIA) - COMPLETE (2025-12-07)
     - ✅ Session 2: Responsive layout - **COMPLETE (2025-12-08)**
       - ✅ Spacing scale (`--space-xs` to `--space-2xl`)
       - ✅ Utility classes (`.flex`, `.flex-col`, `.grid`, `.gap-*`, `.items-*`, `.justify-*`)
       - ✅ Viewport testing (320px, 640px, 1920px)
       - ✅ Touch targets (44px min via `@media (pointer: coarse)`)
       - ✅ Card component refactoring complete (2025-12-08):
         - Created `card.rs` with `Card`, `CardVariant`, `HeadingLevel`
         - Refactored all section containers to use Card component
         - CSS cleanup: removed redundant container styles
         - Visual testing verified via Playwright MCP
     - ✅ Session 3: Theme & Accessibility - **COMPLETE (2025-12-08)**
       - ✅ Colour contrast audit: Adjusted `--text-secondary` and `--text-muted` for WCAG AA
       - ✅ `data-theme` CSS attribute selectors for all 5 themes
       - ✅ ThemeToggle dropdown component with localStorage persistence
       - ✅ Focus state improvements: 0.125rem outline for accessibility
     - ✅ Session 4: Polish & E2E testing - **COMPLETE (2025-12-08)**
       - ✅ Empty state styling with icons (📋, 🔍, 📊, ⚡, 💾)
       - ✅ CSS transitions: `--transition-fast/normal/slow`
       - ✅ Button hover lift effects with `translateY(-1px)`
       - ✅ Card/table/badge hover transitions
       - ✅ E2E tests: TC-11 to TC-14 passed
   - v0.3.3: Distribution-Specific Validation
   - v0.4.0 Web Interface planning

7. **Known Issues** (v0.3.2 scope - see [docs/FRONTEND_LAYOUT_PLAN.md](docs/FRONTEND_LAYOUT_PLAN.md)):
   - ~~GUI: "Loading..." text stays visible after app mounts~~ ✅ **FIXED (2025-12-05)**
   - ~~GUI: Styling needs significant improvement~~ ✅ **FIXED (2025-12-05)** - Dark terminal theme implemented
   - ~~CRITICAL: GUI State persistence bug~~ ✅ **FIXED (2025-12-05)** - SQLite storage implemented
   - ~~GUI: pkexec integration not working~~ ✅ **FIXED (2025-12-06)** - Tauri 2.x camelCase args fix
   - ~~GUI: Browser mode not rendering pages~~ ✅ **FIXED (2025-12-06)** - Added Tauri availability check
   - ~~GUI: Timestamp display on Checkpoints page shows raw numbers~~ ✅ **FIXED (2025-12-05)** - Human-readable formatting
   - ~~GUI: Background colour could be more personable~~ ✅ **ADDRESSED (2025-12-07)** - Created 5 security-focused themes
   - ~~GUI: Page navigation structure~~ ✅ **FIXED** - Consolidated to 3 pages (Dashboard, Analysis, Hardening)
   - ~~**Session 1 (Critical)**~~ ✅ **COMPLETE (2025-12-07)** - Flex/grid overflow fixes, skip link, tab ARIA attributes
   - **Session 2**: ✅ **COMPLETE (2025-12-08)** - Utility classes, viewport testing, Card component refactoring
   - **Session 3**: ✅ **COMPLETE (2025-12-08)** - Colour contrast audit (WCAG AA), theme switching UI (ThemeToggle component), focus state improvements
     - ✅ Additional fixes (2025-12-08): Text contrast brightened, select dropdown option styling, section header size increased
   - **Session 4**: ✅ **COMPLETE (2025-12-08)** - Empty states with icons, CSS transitions, hover animations, E2E tests passed
   - Wayland: Requires `WEBKIT_DISABLE_COMPOSITING_MODE=1` environment variable

8. **Theme System (2025-12-07, updated 2025-12-09)**:
   - Created 5 new themes based on security psychology in `crates/hardener-ui/themes/`:
     - **Fortress** (`fortress.css`): Deep slate-blue with gold accents - vault-like, enterprise feel
     - **Sentinel** (`sentinel.css`): Warm charcoal with amber - vigilant, cozy
     - **Command** (`command.css`): Deep navy with ice-blue - military precision, high-tech
     - **Guardian** (`guardian.css`): Forest black with emerald - natural protection, calming
     - **Daywatch** (`daywatch.css`): Warm off-white with teal - light mode for daytime
   - All themes tested via Playwright MCP in browser mode
   - ✅ Theme selection UI implemented (ThemeToggle dropdown in navigation)
   - ✅ Title colour now uses `--color-accent` (adapts to each theme's identity colour) (2025-12-09)
   - ✅ Tab animation reduced from 250ms to 120ms for snappier feel (2025-12-09)
   - ✅ Theme Design Guide created: `docs/THEME_DESIGN_GUIDE.md` (2025-12-09)
   - **TODO**: Add High Contrast theme for WCAG AAA accessibility

9. **FIXED: Security Score vs Compliance Mismatch (2025-12-09)**:
   - ✅ **Issues A-C FIXED**: Completely redesigned Security Score calculation
   - **New Algorithm**:
     - Based on compliance framework control pass/fail with severity weighting
     - Pass = 100pts, Critical fail = 0pts, High = 25pts, Medium = 50pts, Low = 75pts, Info = 90pts
     - Overall score = average of all framework weighted scores
   - **Files Changed**:
     - `security_score.rs` - New `calculate_framework_score()` and `calculate_all_scores()` functions
     - `quick_actions.rs` - Now generates compliance reports after scan for all 6 frameworks
     - `styles.css` - Added `.score-breakdown` styles for framework detail display
   - **New UI Features**:
     - Expandable "Framework Breakdown" showing per-framework scores (CIS, STIG, NIST, etc.)
     - Each framework shows weighted score + pass/total count
     - Color-coded by score level (green/yellow/red)
   - **Expected Result**: System with 82% CIS compliance now scores ~75-85 (accurate, severity-weighted)

10. **FIXED: False Positives When Not Running as Root (2025-12-09)**:
    - ✅ **Bug D FIXED**: UFW false positive - now uses `systemctl is-active ufw` first (doesn't need root)
      - Changed `crates/hardener-plugins/src/firewall/ufw.rs:146-181`
      - Changed `crates/hardener-plugins/src/firewall/mod.rs:233-270` (distinguishes permission error from disabled)
    - ✅ **Bug E FIXED**: Audit rules false positives - now detects permission denied from `auditctl -l`
      - Added `AuditRulesResult` enum in `crates/hardener-plugins/src/audit/mod.rs:267-300`
      - Scan now skips rule findings when permission denied instead of reporting 25 false positives
    - **Still pending**:
      - `nft list ruleset` (nftables) - may still need similar fix
    - **Plan file**: `/home/bakri/.claude/plans/jaunty-wondering-donut.md`

11. **CLI Verification Summary (2025-12-09, updated after fixes)**:
    | Category | Count | Accuracy |
    |----------|-------|----------|
    | Kernel | 4 | ✅ All correct |
    | FileSystem | 2 | ✅ All correct |
    | Authentication | 8 | ✅ All correct |
    | Network | 0-1 | ✅ Fixed - no false positive when permission denied |
    | Audit | 0-25 | ✅ Fixed - no false positives when permission denied |

12. **FIXED: Stub validate() Methods (2025-12-09)**:
    - ✅ **Bug F FIXED**: All three validate() stubs now properly report estimated changes
      - `permissions/mod.rs:353-401` - Now shows permission changes like "/root: 0755 → 0700"
      - `ssh/mod.rs:538-590` - Now shows directive changes like "PermitRootLogin: yes → no"
      - `firewall/mod.rs:368-418` - Now shows "Enable UFW firewall" and rule count

13. **FIXED: Kernel Rollback Gap (2025-12-09)**:
    - ✅ **Bug G FIXED**: apply() now creates `/etc/sysctl.d/99-hardener.conf` during apply
      - Changed `kernel/mod.rs:273-379`
      - Writes all hardening parameters to persistent config file
      - Rollback now properly removes this file and `sysctl --system` resets to pre-hardening state
      - Bonus: Kernel hardening now survives reboot automatically

14. **TESTS: Bug-Exposing Tests Added (2025-12-09)**:
    - Added `firewall_mock_tests.rs` with `test_firewall_scan_permission_denied_should_not_report_disabled`
      - ✅ **PASSING** - Bug D fixed (2025-12-09)
    - Added to `audit_mock_tests.rs`: `test_audit_scan_permission_denied_should_not_report_missing_rules`
      - ✅ **PASSING** - Bug E fixed (2025-12-09)
    - All bug-exposing tests now pass: `cargo test --package hardener-plugins`

15. **GUI ISSUES FIXED (2025-12-09)**:
    These issues were found during GUI testing after fixing bugs D, E, F, G, A-C:

    | Issue | Description | Priority | Status |
    |-------|-------------|----------|--------|
    | H | Score mismatch Dashboard vs Analysis pages | Medium | ✅ FIXED |
    | I | 11 findings - PAM false positives (pwquality.conf missing on Arch) | Low | Deferred (not a bug) |
    | J | "Generate Reports" button gives no visual feedback | Medium | ✅ FIXED |
    | K | Checkpoints not visible in UI after Apply Hardening | Medium | ✅ FIXED |
    | L | Theme selector text unreadable (same color as background) | High | ✅ FIXED |

    **Issue H Fix**: Unified `calculate_all_scores()` function shared between `SecurityScore` and `MiniSecurityScore` components.

    **Issue J Fix**: Added `status_message` reactive signal with success/error display styling.

    **Issue K Fix**: `get_checkpoints()` in `commands.rs` now reads from both user (`~/.local/share/linux-hardener/checkpoints.db`) and system (`/var/lib/linux-hardener/checkpoints.db`) databases and merges results.

    **Issue L Fix**: Added `appearance: none` CSS reset with custom SVG dropdown arrow for WebKit compatibility.

    **Issue I Details**: PAM findings are valid on Ubuntu/Debian but not actionable on Arch Linux where `pwquality.conf` doesn't exist by default. Not a bug - Arch uses `pam_unix` not `pam_pwquality`. May add distribution-specific handling in future.

    **Files Changed**:
    - `src-tauri/src/commands.rs` - Dual database reading for checkpoints
    - `crates/hardener-ui/src/components/mini_security_score.rs` - Use shared scoring
    - `crates/hardener-ui/src/components/security_score.rs` - Export `calculate_all_scores()`
    - `crates/hardener-ui/src/components/compliance_tab.rs` - Status message feedback
    - `crates/hardener-ui/src/components/history_section.rs` - Refresh button
    - `crates/hardener-ui/styles.css` - Theme selector CSS, status messages

16. **CLI FUNCTIONAL TESTING (2025-12-10)** - ✅ **COMPLETE**:
    Full CLI test results documented in `docs/CLI_V032_TEST_RESULTS.md`.

    **Non-Root Tests (Host):**
    | Category | Pass | Fail | Notes |
    |----------|------|------|-------|
    | Basic commands | 5/5 | 0 | All working |
    | Scan operations | 6/6 | 0 | Severity filter, exit code work |
    | Report generation | 10/10 | 0 | All 6 frameworks, all formats |
    | Apply/dry-run | 5/5 | 0 | Estimated changes shown (Bug F fixed) |
    | Checkpoint | 1/1 | 0 | List works |
    | Daemon/History | 2/2 | 0 | ✅ Fixed - user dir fallback |
    | Systemd | 2/2 | 0 | Generate/status work |
    | SSH remote | 1/1 | 0 | Error handling works |
    | **Total** | **27/27** | **0** | 100% pass rate |

    **Issue M (FIXED 2025-12-10):** Scheduler database path was hardcoded to `/var/lib/linux-hardener/scheduler.db`.
    - ✅ Added `default_data_dir()` helper that returns user path for non-root users
    - Root: `/var/lib/linux-hardener/scheduler.db`
    - User: `~/.local/share/linux-hardener/scheduler.db`
    - Files changed: `crates/hardener-scheduler/src/config.rs`, `Cargo.toml` (added `dirs`, `libc`)
    - Also fixed: `hardener-core` feature gating for `testing` module, clippy warning in `config_loader.rs`

    **Issue Q (FIXED 2025-12-10):** Invalid plugin name accepted silently - `--plugin nonexistent` returned `[]` with exit 0.
    - ✅ Added `validate_plugin_filter()` in `scan.rs` to validate plugin names before scanning
    - ✅ Added `is_valid_plugin_name()` helper supporting both full IDs and short names
    - Now returns error with valid plugin list and exit code 1
    - Short names work: `--plugin kernel` matches `kernel-hardening`
    - Files changed: `crates/hardener-cli/src/commands/scan.rs`

    **Issue R (FIXED 2025-12-10):** Test script showed 105% pass rate (108/102 tests).
    - ✅ Root cause: `log_pass()` called without `log_test()` in preflight checks
    - ✅ Added `log_check()` function for verification steps that shouldn't count as tests
    - ✅ Changed 7 occurrences from `log_pass` to `log_check`
    - Test suite now shows correct 100% (102/102)
    - Files changed: `scripts/full-test-suite.sh`

17. **ROOT TESTS VERIFIED (2025-12-09)**:
    All apply operations tested with sudo on main system:

    | Test | Result | Details |
    |------|--------|---------|
    | Kernel apply | ✅ Pass | 13 changes, `/etc/sysctl.d/99-hardener.conf` created |
    | Firewall apply | ✅ Pass | 2 rules added, UFW enabled |
    | SSH apply | ✅ Pass | Backup + config + sshd restart |

    **Recovery backup**: `/tmp/pre-test-backup-20251209-0203.tar.gz`

18. **SAFE ROOT TESTING INFRASTRUCTURE (2025-12-10)**:
    Two scripts added for comprehensive root testing in an isolated container:

    | Script | Purpose |
    |--------|---------|
    | `scripts/create-test-container.sh` | Create/manage systemd-nspawn container |
    | `scripts/root-test-suite.sh` | Run comprehensive root tests |

    **Test Results (2025-12-10):**
    ```
    ━━━ Test Summary ━━━
    Total tests: 36
    Passed: 35
    Failed: 0
    Skipped: 1 (test script pattern matching)
    ```

    **Key Results:**
    - **47 findings** detected as root (vs 11 as non-root)
    - **26 audit findings** now visible with root access
    - Kernel apply: ✅ Changes applied, `kptr_restrict=2` verified
    - All 6 compliance frameworks: ✅ Reports generated
    - PDF generation: ✅ 30KB PDF created
    - Daemon root path: ✅ `/var/lib/linux-hardener/scheduler.db` correct

    **Quick Start:**
    ```bash
    # Create container (one-time)
    sudo ./scripts/create-test-container.sh

    # Enter container
    sudo ./scripts/create-test-container.sh enter

    # Inside container (binary already built on host via bind mount):
    cd /project
    sudo ./scripts/root-test-suite.sh           # Safe tests only
    sudo ./scripts/root-test-suite.sh --apply   # Full tests (apply + rollback)
    ```

    **Why `--apply` is opt-in:** The flag explicitly enables destructive tests (apply hardening, rollback). Without it, only read-only tests run. Inside the container, both modes are safe since it's completely isolated from your real system. The separation prevents accidentally running destructive tests.

    **Container features:**
    - Full systemd support (needed for service/firewall testing)
    - Pre-installed: openssh, audit, ufw, nftables
    - Project bind-mounted at `/project` (no cargo needed in container)
    - Root: `test` / User: `testuser:test`
    - Complete isolation from host system

19. **BUGS FIXED: Checkpoint System (2025-12-10)**:
    Two critical bugs were discovered and fixed during iterative testing:

    | Bug | Description | Severity | Status |
    |-----|-------------|----------|--------|
    | O | Checkpoint not created during apply | Critical | ✅ FIXED |
    | P | Nested tokio runtime panic when checkpoint manager present | Critical | ✅ FIXED |

    **Bug O Root Cause**: In `apply.rs`, the context was created with executor, but checkpoint manager was assigned to a NEW context that was discarded:
    ```rust
    // BROKEN:
    let mut ctx = Context::with_executor(executor);
    if !dry_run {
        Context::with_checkpoint_manager(manager)  // Discarded!
    };
    ```

    **Bug O Fix**: Proper context creation with both executor and checkpoint manager:
    ```rust
    // FIXED:
    let mut ctx = if !dry_run {
        Context::with_executor_and_checkpoint(executor, manager)
    } else {
        Context::with_executor(executor)
    };
    ```

    **Bug P Root Cause**: `create_checkpoint_for_apply()` used `Runtime::new().block_on()` but was called from async `apply()` methods, causing "Cannot start a runtime from within a runtime" panic.

    **Bug P Fix**: Made `create_checkpoint_for_apply()` async and updated all 8 plugin call sites to use `.await`.

    **Files Changed**:
    - `crates/hardener-cli/src/commands/apply.rs` - Context creation fix
    - `crates/hardener-core/src/context.rs` - Added `with_executor_and_checkpoint()` method
    - `crates/hardener-plugins/src/lib.rs` - Made `create_checkpoint_for_apply` async
    - `crates/hardener-plugins/src/*/mod.rs` - Added `.await` to all 8 plugin apply methods

    **Verification**: Full iterative test cycle passed in container:
    - Checkpoint created: `cp_1765400837958_f5471c7d`
    - Rollback successful: `/etc/sysctl.d/99-hardener.conf` removed
    - All operations verified with evidence

20. **Always Remember**:
    - Update documentation after changes
    - Follow naming conventions strictly
    - No AI attributions
    - British English
    - Code must pass clippy

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

### Verification That Launch Succeeded

1. Console shows "Compiling hardener-ui" followed by "Finished dev"
2. Console shows Trunk serving on port 1420
3. App window appears with rendered content
4. NO "Waiting for your frontend dev server" messages looping

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

### Screenshot Workflow

#### When To Take Screenshots

- After visual changes to confirm rendering
- Before/after fixing visual bugs
- When iterating on design implementation
- To verify component placement matches specifications

#### When NOT To Take Screenshots

- After pure Rust/logic changes with no UI impact
- During build/compile phases
- Rapid iteration loops (batch screenshots at natural breakpoints)
- When previous screenshot shows correct state

#### Screenshot Capture Process

1. Wait for network idle (no pending requests)
2. Verify no loading states visible
3. Confirm viewport is 1920x1080
4. Capture screenshot
5. Verify captured content matches expected view
6. IF content incorrect → wait 2 seconds, retry once

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

*This document was prepared for continuity between development sessions.*

**Last Updated**: 2025-12-10
