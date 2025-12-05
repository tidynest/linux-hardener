# Next Development Session - Linux System Hardener

> **For the next assistant**: This document contains comprehensive findings and development plans for continuing work on this project. Read this thoroughly before starting.

---

## Project Summary

**Linux System Hardener** is a comprehensive Linux security automation tool written in Rust. It's a mature workspace-based project with:

- **10 Core Crates + 1 Tauri App**
- **8 Security Plugins**: Kernel, SSH, Firewall, PAM, Services, Audit, Permissions, MAC
- **378+ Passing Tests**
- **Multi-Distribution Support**: Ubuntu, Debian, Fedora, RHEL, Arch, openSUSE
- **Current Version**: 0.3.0 (Development Release)
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

# Build WASM frontend only
cd crates/hardener-ui && trunk build

# Verify WASM compilation
cargo check -p hardener-ui --target wasm32-unknown-unknown
```

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

5. **Next Tasks**:
   - v0.3.1: GUI Polish & Testing (see PLAN.md)
   - v0.3.2: Distribution-Specific Validation
   - v0.4.0 Web Interface planning

6. **Known Issues** (v0.3.1 scope):
   - GUI: "Loading..." text stays visible after app mounts (needs removal)
   - GUI: Styling needs significant improvement
   - Wayland: Requires `WEBKIT_DISABLE_COMPOSITING_MODE=1` environment variable

7. **Always Remember**:
   - Update documentation after changes
   - Follow naming conventions strictly
   - No AI attributions
   - British English
   - Code must pass clippy

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
