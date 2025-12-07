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
   - v0.3.1: GUI Polish & Testing (see PLAN.md) - **IN PROGRESS**
   - v0.3.2: Frontend Layout & Accessibility - See [docs/FRONTEND_LAYOUT_PLAN.md](docs/FRONTEND_LAYOUT_PLAN.md) for detailed session breakdown:
     - ✅ Session 1: Critical overflow fixes (`min-width: 0`, grid templates, skip links, ARIA) - COMPLETE (2025-12-07)
     - 🔄 Session 2: Responsive layout - **IN PROGRESS (2025-12-08)**
       - ✅ Spacing scale (`--space-xs` to `--space-2xl`)
       - ✅ Utility classes (`.flex`, `.flex-col`, `.grid`, `.gap-*`, `.items-*`, `.justify-*`)
       - ✅ Viewport testing (320px, 640px, 1920px)
       - ✅ Touch targets (44px min via `@media (pointer: coarse)`)
       - 🔄 Card component standardisation (planned, pending decision)
     - Session 3: Theme & accessibility (contrast audit, theme switching)
     - Session 4+: Polish & E2E testing
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
   - **Session 2**: 🔄 **IN PROGRESS (2025-12-08)** - Utility classes added, viewport testing complete, Card component pending
   - **Session 3**: Colour contrast audit, theme switching UI, focus state improvements
   - **Session 4+**: E2E testing (Web + Desktop), animations, error states
   - Wayland: Requires `WEBKIT_DISABLE_COMPOSITING_MODE=1` environment variable

8. **Theme System (2025-12-07)**:
   - Created 5 new themes based on security psychology in `crates/hardener-ui/themes/`:
     - **Fortress** (`fortress.css`): Deep slate-blue with gold accents - vault-like, enterprise feel
     - **Sentinel** (`sentinel.css`): Warm charcoal with amber - vigilant, cozy
     - **Command** (`command.css`): Deep navy with ice-blue - military precision, high-tech
     - **Guardian** (`guardian.css`): Forest black with emerald - natural protection, calming
     - **Daywatch** (`daywatch.css`): Warm off-white with teal - light mode for daytime
   - All themes tested via Playwright MCP in browser mode
   - **TODO**: Implement theme selection UI (see Session 3 in FRONTEND_LAYOUT_PLAN.md)
   - **TODO**: Add High Contrast theme for WCAG AAA accessibility

9. **Always Remember**:
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

**Last Updated**: 2025-12-08
