# Linux System Hardener - Architecture Documentation

**Last Updated:** 2026-06-28
**Version:** 1.2.0

---

## Overview

Linux System Hardener is a modular security hardening tool for Linux systems, providing:
- Plugin-based scanning and hardening across multiple security domains
- Checkpoint/rollback functionality for safe changes
- Compliance framework mapping (CIS, NIST, STIG, HIPAA, PCI-DSS, GDPR, ISO 27001:2022)
- Multiple interfaces: CLI, GUI (Tauri/Leptos), and programmatic APIs
- Cryptographically signed audit logs and tamper-proof state management

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Interfaces                          │
├────────────────────┬──────────────────────┬─────────────────────┤
│  CLI (hardener-cli)│  GUI (src-tauri)     │  Programmatic API   │
│   └─ Scan          │   └─ Leptos + Tauri  │   └─ hardener-core  │
│   └─ Apply         │   └─ Dashboard       │   └─ hardener-state │
│   └─ Rollback      │   └─ Analysis        │                     │
│   └─ Checkpoint    │   └─ Hardening       │                     │
│   └─ Report        │   └─ Remote          │                     │
│   └─ Batch         │   └─ Scheduler       │                     │
│                    │   └─ Fleet (v1.2.0)  │                     │
│   └─ Fleet Apply     │                     │
└────────────────────┴──────────────────────┴─────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Core Engine                              │
├─────────────────────────────────────────────────────────────────┤
│  hardener-core                                                  │
│  ├─ HardeningPlugin trait (universal plugin interface)          │
│  ├─ PluginRegistry (central plugin registry)                    │
│  ├─ PluginManager (orchestration, dependency resolution)        │
│  ├─ Context (execution context, system info, audit logging)     │
│  └─ Finding/ScanResult/ApplyResult types                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Plugin System                              │
├─────────────────────────────────────────────────────────────────┤
│  hardener-plugins                                               │
│  ├─ Audit (auditd configuration)                                │
│  ├─ Firewall (nftables, firewalld, ufw backends)                │
│  ├─ Kernel (sysctl hardening)                                   │
│  ├─ MAC (SELinux, AppArmor)                                     │
│  ├─ PAM (authentication hardening)                              │
│  ├─ Permissions (file permissions auditing)                     │
│  ├─ Services (service minimisation)                             │
│  └─ SSH (sshd_config hardening)                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────────────┐
│   State Management      │     │     Supporting Services         │
├─────────────────────────┤     ├─────────────────────────────────┤
│ hardener-state          │     │ hardener-common                 │
│ ├─ Checkpoint system    │     │ ├─ Error types                  │
│ ├─ CheckpointManager    │     │ ├─ Logging utilities            │
│ ├─ Hash chain auditing  │     │ ├─ File utilities               │
│ ├─ Ed25519 signing      │     │ ├─ Severity/Category enums      │
│ └─ SQLite database      │     │ ├─ SystemExecutor trait         │
│                         │     │ ├─ FileMetadata/CommandOutput   │
│                         │     │ └─ MockExecutor (test seam)     │
│                         │     │ hardener-distro                 │
│                         │     │ ├─ Distribution detection       │
│                         │     │ └─ Package managers             │
│                         │     │                                 │
│                         │     │ hardener-compliance             │
│                         │     │ ├─ Framework implementations    │
│                         │     │ ├─ Report generation            │
│                         │     │ └─ Output formatters (Text,     │
│                         │     │    JSON, CSV, HTML, PDF)        │
└─────────────────────────┘     └─────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Scheduling System                           │
├─────────────────────────────────────────────────────────────────┤
│ hardener-scheduler                                              │
│ ├─ SchedulerConfig (TOML configuration)                         │
│ ├─ ScanHistoryManager (SQLite storage)                          │
│ ├─ JsonStore (timestamped JSON output)                          │
│ ├─ ScanRunner (orchestrates plugin scans) ✓                     │
│ ├─ Daemon (cron-based scheduling) ✓                             │
│ ├─ Notifications (email, webhooks) ✓                            │
│ └─ SystemdGenerator (.service/.timer files) ✓                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     System Interface                            │
├─────────────────────────────────────────────────────────────────┤
│  Linux System APIs                                              │
│  ├─ /proc/sys (kernel parameters)                               │
│  ├─ /etc (config files)                                         │
│  ├─ systemctl (service management)                              │
│  ├─ auditctl (audit rules)                                      │
│  ├─ nftables/firewalld/ufw (firewall)                           │
│  └─ File system operations                                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Crate Overview

| Crate | Purpose | Key Exports |
|-------|---------|-------------|
| `hardener-types` | WASM-compatible shared types (4 source files: `lib.rs`, `config_picker.rs`, `remote.rs`, `scheduler.rs`) | `PluginId`, `Severity`, `Finding`, `ScanResult`, `ApplyResult`, `ComplianceReport`, `RollbackResult`, `ValidationReport`, `ConfigSummary`, `RemoteHostProfile`, `RemoteConnectionStatus`, `RemoteConnectionInfo`, `HostsConfig`, `SchedulerUiConfig`, `NotificationUiConfig`, `TestNotificationResult`, `FleetHostScan`, `FleetHostStatus`, `SeverityTallies` |
| `hardener-core` | Plugin framework, execution context, config | `HardeningPlugin`, `Context`, `PluginManager`, `HardenerConfig`, `ConfigLoader`, `LocalExecutor`, `SshExecutor` (re-exports `SystemExecutor` from hardener-common) |
| `hardener-common` | Shared utilities, error types, executor abstraction | `HardeningError`, `SystemExecutor`, `FileMetadata`, `CommandOutput`, `MockExecutor`, file utilities (re-exports types from hardener-types) |
| `hardener-plugins` | 8 security plugin implementations | All plugin structs |
| `hardener-state` | Checkpoint and audit system | `CheckpointManager`, `AuditLogger` |
| `hardener-compliance` | Compliance framework mapping | `ReportGenerator`, frameworks (PDF behind `pdf` feature) |
| `hardener-distro` | Distribution detection | `Distribution`, `DistroFamily`, `DistributionAdapter` |
| `hardener-scheduler` | Scheduled scanning daemon | `SchedulerConfig`, `Daemon`, `ScanHistoryManager`, `JsonStore`, `NotificationDispatcher`, `ScanRunner`, `ScanSummary`, `TriggerType`, `SystemdGenerator`, `cron_to_calendar` |
| `hardener-cli` | Command-line interface | Binary entry point |
| `hardener-ui` | Leptos WASM frontend | 7-page architecture (Dashboard, Analysis, Hardening, Remote, Scheduler, Fleet, Fleet Apply), dark terminal CSS theme (depends only on hardener-types) |
| `src-tauri` | Desktop app backend | Tauri commands |

### Tauri 2.x Integration Notes

**Critical:** When calling Tauri commands from WASM, argument keys must use **camelCase**:

```rust
// CORRECT - Tauri 2.x expects camelCase
let args = serde_json::json!({ "pluginIds": plugin_ids });

// WRONG - snake_case will cause silent failures
let args = serde_json::json!({ "plugin_ids": plugin_ids });
```

**Error Handling:** The `wasm-bindgen` extern binding for Tauri invoke must include the `catch` attribute:

```rust
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"], js_name = invoke, catch)]
    async fn tauri_invoke(cmd: &str, args: JsValue) -> Result<JsValue, JsValue>;
}
```

Without `catch`, Promise rejections cause WASM panics instead of returning errors.

### Browser Mode (Web App without Tauri)

The UI can run in browser mode via `trunk serve` without the Tauri desktop wrapper. This is useful for UI development and testing.

**Tauri Availability Check:**

```rust
// In tauri_bindings.rs
#[wasm_bindgen(inline_js = "export function is_tauri_available() { return typeof window.__TAURI__ !== 'undefined'; }")]
extern "C" {
    fn is_tauri_available() -> bool;
}

pub fn tauri_available() -> bool {
    is_tauri_available()
}
```

All Tauri command wrappers check `tauri_available()` before calling `tauri_invoke()`. In browser mode, commands return `Err("Tauri not available (running in browser mode)")` gracefully.

**Browser Mode Limitations:**
- Scanning, applying, and rollback operations are unavailable
- Compliance report generation is unavailable
- All navigation and UI rendering works normally
- Empty states display with helpful messages (e.g., "Run a scan to see results")

### Dual Database Pattern for Checkpoints

The GUI needs to display checkpoints created by both user-run and privileged (pkexec) operations:

```
┌────────────────────────────────────────────────────────────────────────┐
│ User clicks "Apply Hardening"                                          │
└────────────────────────┬───────────────────────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────────────────────┐
│ GUI runs: pkexec hardener apply --plugin kernel                        │
└────────────────────────┬───────────────────────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────────────────────┐
│ CLI runs as ROOT, writes checkpoint to:                                │
│   /var/lib/linux-hardener/checkpoints.db (system database)             │
└────────────────────────┬───────────────────────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────────────────────┐
│ GUI's get_checkpoints() reads from BOTH:                               │
│   - ~/.local/share/linux-hardener/checkpoints.db (user database)       │
│   - /var/lib/linux-hardener/checkpoints.db (system database)           │
│                                                                        │
│ Results are merged, deduplicated by ID, sorted by timestamp descending │
└────────────────────────────────────────────────────────────────────────┘
```

**Why this pattern?**

| Operation | Runs As | Writes To |
|-----------|---------|-----------|
| `hardener apply` (no pkexec) | User | User database |
| `pkexec hardener apply` | Root | System database |
| GUI scan (no root) | User | User database |

Without dual-database reading, checkpoints created via `pkexec` would be invisible to the GUI.

**Implementation** (`src-tauri/src/commands.rs`):

```rust
fn get_user_db_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("linux-hardener/checkpoints.db")
}

fn get_system_db_path() -> PathBuf {
    PathBuf::from("/var/lib/linux-hardener/checkpoints.db")
}

pub async fn get_checkpoints() -> Result<Vec<CheckpointInfo>, String> {
    let mut all = Vec::new();
    // Read from user database
    if let Ok(cp) = read_checkpoints(get_user_db_path()).await { all.extend(cp); }
    // Read from system database (if exists and readable)
    if let Ok(cp) = read_checkpoints(get_system_db_path()).await {
        // Deduplicate by ID
        for c in cp { if !all.iter().any(|x| x.id == c.id) { all.push(c); } }
    }
    all.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    Ok(all)
}
```

**Responsive CSS Design:**

The UI uses a mobile-first responsive approach with CSS custom properties:

| Breakpoint | Target | Layout Behaviour |
|------------|--------|------------------|
| < 480px | Mobile | Single column, stacked navigation |
| 480-768px | Tablet | 2-column grids, adapted spacing |
| 768-1024px | Small desktop | Full layouts, scanner sidebar |
| > 1024px | Desktop | Full 2-column scanner layout |
| > 1600px | Ultra-wide | Content constrained to 1600px max-width, centred |

Key CSS defensive measures:
- `.main-content`: `max-width: var(--content-max-width)` prevents ultra-wide stretching
- `.value-cell`: Overflow handling with `text-overflow: ellipsis` for long paths
- `#app`: `min-width: 320px` prevents layout collapse at extreme narrow widths
- `min-width: 0` on flex children (`.navigation`, `.nav-links`, `.header-content`) prevents overflow
- `minmax(0, 1fr)` in grid templates (`.dashboard-grid`, `.scanner-layout`) prevents content blowout

**Accessibility Features (WCAG 2.1 AA):**
- Skip link as first focusable element (`<a class="skip-link">Skip to main content</a>`)
- `<main id="main-content" tabindex="-1">` for skip link target
- Tab components with full WAI-ARIA pattern (`aria-controls`, `aria-labelledby`, `tabindex`)
- Utility classes: `.sr-only` (screen reader only), `.truncate`, `.line-clamp-*`
- Visible focus states via `:focus-visible` with accent colour ring
- Touch targets minimum 44x44px via `@media (pointer: coarse)`

**Playwright MCP Integration:**

Browser mode enables automated UI testing via Playwright MCP. Configure `playwright-brave` in `.mcp.json`:

```json
{
  "mcpServers": {
    "playwright-brave": {
      "command": "npx",
      "args": [
        "@playwright/mcp@latest",
        "--browser", "chromium",
        "--executable-path", "/usr/bin/brave",
        "--user-data-dir", "/tmp/playwright-brave-profile",
        "--viewport-size", "1920x1080"
      ]
    }
  }
}
```

See [browser-automation.md](../archive/browser-automation.md) for complete setup and troubleshooting guide.

---

## Key Traits

### HardeningPlugin

The core interface all plugins implement:

```rust
#[async_trait]
pub trait HardeningPlugin: Send + Sync {
    fn metadata(&self) -> PluginMetadata;
    fn dependencies(&self) -> Vec<PluginId>;
    async fn scan(&self, ctx: &Context) -> Result<ScanResult>;
    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult>;
    async fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()>;
    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport>;
}
```

### SystemExecutor

Abstraction for local and remote system operations. The trait, `FileMetadata`, `CommandOutput`, and `MockExecutor` are defined in **`hardener-common`** and re-exported from `hardener-core` so existing `hardener_core::SystemExecutor` paths continue to compile:

```rust
#[async_trait]
pub trait SystemExecutor: Send + Sync {
    fn description(&self) -> String;
    fn is_remote(&self) -> bool;
    async fn read_file(&self, path: &Path) -> Result<String>;
    async fn read_file_optional(&self, path: &Path) -> Result<Option<String>>;
    async fn write_file(&self, path: &Path, content: &str) -> Result<()>;
    async fn path_exists(&self, path: &Path) -> Result<bool>;
    async fn file_metadata(&self, path: &Path) -> Result<FileMetadata>;
    async fn execute_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput>;
    async fn command_exists(&self, program: &str) -> Result<bool>;
}
```

Implementations:
- `LocalExecutor` - Wraps `std::fs` and `std::process::Command`
- `SshExecutor` - Runs operations over SSH on remote hosts
- `MockExecutor` - Virtual filesystem for unit testing without real system access

### FirewallBackend

Abstraction for different firewall systems:

```rust
#[async_trait]
pub trait FirewallBackend: Send + Sync {
    fn backend_name(&self) -> &str;
    async fn detect(&self, ctx: &Context) -> Result<bool>;
    async fn is_enabled(&self, ctx: &Context) -> Result<()>;
    async fn enable(&self, ctx: &Context) -> Result<()>;
    async fn list_rules(&self, ctx: &Context) -> Result<Vec<Rule>>;
    async fn apply_rules(&self, ctx: &Context, rules: &[Rule]) -> Result<Vec<Change>>;
    fn get_default_rules(&self) -> Vec<Rule>;
}
```

---

## Plugins

| Plugin | Category | Checks |
|--------|----------|--------|
| `AuditHardeningPlugin` | Audit | auditd rules for time, users, permissions, modules |
| `FirewallHardeningPlugin` | Network | Firewall enabled, baseline rules |
| `KernelHardeningPlugin` | Kernel | ASLR, kptr_restrict, dmesg_restrict, ptrace_scope |
| `MacHardeningPlugin` | MAC | SELinux/AppArmor status |
| `PamHardeningPlugin` | Auth | Password complexity, lockout, reuse |
| `PermissionsHardeningPlugin` | FileSystem | Critical paths, SUID/SGID |
| `ServicesHardeningPlugin` | Services | Unnecessary services |
| `SshHardeningPlugin` | Network | PermitRootLogin, PasswordAuthentication |

---

## State Management

### Storage Locations

| Component | Location | Purpose |
|-----------|----------|---------|
| Checkpoints | `~/.local/share/linux-hardener/checkpoints.db` | System state snapshots |
| Audit Log | `~/.local/share/linux-hardener/audit.log` (JSONL file) | Tamper-proof action history |
| Signing Keys | `~/.local/share/linux-hardener/signing.key` | Ed25519 keys |

### Database Schema

```sql
-- Checkpoint metadata
CREATE TABLE checkpoints (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    username TEXT NOT NULL,
    signature BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

-- Captured file states
CREATE TABLE file_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    checkpoint_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    content BLOB,
    permissions INTEGER,
    owner_uid INTEGER,
    owner_gid INTEGER,
    FOREIGN KEY(checkpoint_id) REFERENCES checkpoints(id)
);

-- Audit logging uses file-based JSONL format (not SQLite).
-- Each entry is a JSON line in the audit log file (~/.local/share/linux-hardener/audit.log).
-- Fields per entry: entry_timestamp, entry_action_type, entry_user,
-- entry_target, entry_result, entry_details, entry_hash (SHA-256 hash chain).
-- See hardener-state/src/audit.rs for the AuditEntry struct.
```

---

## Compliance Frameworks

| Framework | Controls | Description |
|-----------|----------|-------------|
| CIS | 38 | Center for Internet Security Benchmarks |
| STIG | 20 | DISA Security Technical Implementation Guides |
| NIST 800-53 | 20 | US Federal security controls |
| PCI-DSS | 22 | Payment Card Industry standards |
| HIPAA | 14 | Healthcare security requirements |
| GDPR | 12 | EU data protection (Article 32) |
| ISO 27001:2022 | 93 | ISO/IEC 27001:2022 Annex A controls (4 themes) |

---

## Configuration System

The configuration system follows a security-first design where **configuration annotates findings; it never hides them**.

### Config Loading Order (later overrides earlier)

1. Built-in defaults (secure baseline)
2. System config: `/etc/linux-hardener/config.toml`
3. User config: `~/.config/linux-hardener/config.toml`
4. CLI config: `--config /path/to/file.toml`
5. Environment: `HARDENER_*` variables

### Scan Modes

| Mode | Flag | Behaviour |
|------|------|-----------|
| Default | (none) | Shows all findings with policy annotations |
| Audit | `--audit` | Ignores all config, pure security assessment |
| Compliance | `--compliance` | Only shows findings without valid policy exceptions |

### Key Types

```rust
pub struct HardenerConfig {
    pub global: GlobalConfig,
    pub ssh: PluginConfig,
    pub kernel: PluginConfig,
    pub firewall: PluginConfig,
    pub pam: PluginConfig,
    pub audit: PluginConfig,
    pub mac: PluginConfig,
    pub permissions: PluginConfig,
    pub services: PluginConfig,
}

pub struct PolicyException {
    pub value: String,
    pub allowed: bool,
    pub reason: String,
    pub approved_by: Option<String>,
    pub approved_date: Option<String>,
    pub ticket: Option<String>,
    pub expires: Option<String>,
    // Computed: is_expired() method, NOT a stored field
    // Computed: is_valid() — returns allowed && !is_expired()
}
```

---

## Security Features

1. **Cryptographic Signatures**: Ed25519 signatures on all checkpoints
2. **Hash Chain Audit Log**: SHA-256 chain makes tampering detectable
3. **Privilege Separation**: Scan runs unprivileged, apply requires root
4. **Atomic Operations**: File changes use atomic write patterns
5. **Rollback Safety**: Full state restoration from any checkpoint (including directory permissions)
6. **Transparent Config**: Configuration cannot hide security findings, only annotate them
7. **Post-Apply Verification**: Permissions plugin verifies chmod actually took effect (detects vfat/FAT32 no-ops)

---

## CI/CD Infrastructure

### GitHub Actions

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | Push/PR to `main` | Tests, clippy, fmt, security audit, build |
| `release.yml` | Tag `v*` | Multi-target builds, GitHub releases |

> **Note:** GitHub Actions CI/CD is connected and functional. Workflows trigger on
> push/PR to the `main` branch, running check, test, clippy, fmt, security audit,
> and multi-platform builds.

### GitLab CI

| Stage | Jobs | Purpose |
|-------|------|---------|
| check | check, fmt, clippy | Code quality |
| test | test, security-audit | Testing |
| build | build:linux-* | Release binaries |
| release | release | Create GitLab release |

### Release Artifacts

| Artifact | Target | Description |
|----------|--------|-------------|
| `hardener-linux-x86_64.tar.gz` | x86_64-unknown-linux-gnu | Standard Linux binary |
| `hardener-linux-x86_64-musl.tar.gz` | x86_64-unknown-linux-musl | Static binary (portable) |
| `hardener-linux-aarch64.tar.gz` | aarch64-unknown-linux-gnu | ARM64 Linux binary |

### Branch Strategy

The `main` branch is kept in sync on GitHub and GitLab. The release script (`scripts/release.sh`) automatically pushes to both remotes.

---

## See Also

- `docs/DATA_FLOW.md` - Detailed data flow diagrams
- `docs/CONFIG_DESIGN.md` - Configuration system security design
- `docs/RELEASING.md` - Versioning and release process
- `ROADMAP.md` - Development roadmap
- `README.md` - User documentation
