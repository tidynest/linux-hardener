# Linux System Hardener - Architecture Documentation

**Last Updated:** 2026-07-30
**Version:** 1.5.1

---

## Overview

Linux System Hardener is a modular security hardening tool for Linux systems, providing:
- Plugin-based scanning and hardening across multiple security domains
- Checkpoint/rollback functionality for safe changes
- Compliance framework mapping (CIS, NIST, STIG, HIPAA, PCI-DSS, GDPR, ISO 27001:2022, SOC 2, NIST SP 800-171, FedRAMP)
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
│   └─ Report        │   └─ Hosts           │                     │
│   └─ Batch         │   └─ Fleet Apply     │                     │
│                    │   └─ Scheduler       │                     │
│                    │   └─ Settings        │                     │
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
│                         │     │ ├─ MockExecutor (test seam)     │
│                         │     │ └─ Layered /etc + /usr/etc      │
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
│  ├─ /etc, /usr/etc (config files)                               │
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
| `hardener-types` | WASM-compatible shared types (4 source files: `lib.rs`, `config_picker.rs`, `remote.rs`, `scheduler.rs`) | `PluginId`, `Severity`, `Finding`, `ScanResult`, `UncheckedCheck`, `ApplyResult`, `ComplianceReport`, `RollbackResult`, `ValidationReport`, `ConfigSummary`, `RemoteHostProfile`, `RemoteConnectionStatus`, `RemoteConnectionInfo`, `HostsConfig`, `SchedulerUiConfig`, `NotificationUiConfig`, `TestNotificationResult`, `FleetHostScan`, `FleetHostStatus`, `SeverityTallies` |
| `hardener-core` | Plugin framework, execution context, config | `HardeningPlugin`, `Context`, `PluginManager`, `HardenerConfig`, `ConfigLoader`, `LocalExecutor`, `SshExecutor` (re-exports `SystemExecutor` from hardener-common) |
| `hardener-common` | Shared utilities, error types, executor abstraction, layered `/etc` + `/usr/etc` configuration resolution | `HardeningError`, `SystemExecutor`, `FileMetadata`, `CommandOutput`, `MockExecutor`, `ConfigLayer`, `LayeredRead`, `read_layered()`, `vendor_path_for()`, file utilities (re-exports types from hardener-types) |
| `hardener-plugins` | 8 security plugin implementations | All plugin structs |
| `hardener-state` | Checkpoint, audit, and scan-session persistence | `CheckpointManager`, `AuditLogger`, `ScanHistoryManager` |
| `hardener-compliance` | Compliance framework mapping | `ReportGenerator`, frameworks (PDF behind `pdf` feature) |
| `hardener-distro` | Distribution detection | `Distribution`, `DistroFamily`, `DistributionAdapter` |
| `hardener-scheduler` | Scheduled scanning daemon | `SchedulerConfig`, `Daemon`, `ScanHistoryManager`, `JsonStore`, `NotificationDispatcher`, `ScanRunner`, `ScanSummary`, `TriggerType`, `SystemdGenerator`, `cron_to_calendar` |
| `hardener-cli` | Command-line interface | Binary entry point |
| `hardener-ui` | Leptos WASM frontend | 7-page architecture (Dashboard, Analysis, Hardening, Hosts, Fleet Apply, Scheduler, Settings) behind a grouped left sidebar; 7-theme system (default "Midnight Teal", plus Fortress, Sentinel, Command, Guardian, Daywatch, High Contrast) driven by a shared `AppState.theme` signal and `<html data-theme>` (depends only on hardener-types) |
| `src-tauri` | Desktop app backend | Tauri commands |

### Tauri 2.x Integration Notes

**Per-command capability ACLs (SAM-039):** `src-tauri/build.rs` declares every
application command through `tauri_build::AppManifest::new().commands(&[...])`.
tauri-build autogenerates an `allow-<kebab-case>`/`deny-<kebab-case>` permission
pair per command (written to `src-tauri/permissions/autogenerated/`) and turns on
Tauri's runtime ACL check for application commands. The main-window capability
(`src-tauri/capabilities/default.json`) grants all 30 permissions explicitly,
ordered by risk tier (read-only, mutating-local, remote, config), so revoking a
single command means deleting one line. The command list in `build.rs` must stay
in sync with the `generate_handler!` block in `src-tauri/src/main.rs`; referencing
an unknown permission in the capability file fails the build, and runtime
enforcement is covered by `src-tauri/src/acl_tests.rs` on the mock runtime.

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
| < 480px | Mobile | Single column, sidebar shown as a collapsed icon rail |
| 480-768px | Tablet | 2-column grids, adapted spacing |
| 768-1024px | Small desktop | Full layouts, scanner sidebar |
| > 1024px | Desktop | Full 2-column scanner layout |
| > 1600px | Ultra-wide | Content constrained to 1600px max-width, centred |

Navigation itself is a grouped left sidebar (`aside.sidebar`, `components/sidebar.rs`; groups Local and Fleet plus a pinned Settings area), not the old top nav bar. Independent of the CSS breakpoints above, the sidebar auto-collapses to an icon rail below a 900px viewport width via a JS resize listener, unless the user has an explicit collapse preference stored, which wins in both directions.

Key CSS defensive measures:
- `.main-content`: `max-width: var(--content-max-width)` prevents ultra-wide stretching
- `.value-cell`: Overflow handling with `text-overflow: ellipsis` for long paths
- `#app`: `min-width: 320px` prevents layout collapse at extreme narrow widths
- `min-width: 0` on flex children (`.app-content`, `.header-content`) prevents overflow
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
    async fn scan(&self, ctx: &Context, config: &PluginConfig) -> Result<ScanResult>;
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
    async fn read_dir(&self, path: &Path) -> Result<Vec<PathBuf>>;
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
    fn systemd_unit(&self) -> &'static str;
    async fn detect(&self, ctx: &Context) -> Result<bool>;
    async fn is_enabled(&self, ctx: &Context) -> Result<()>;
    async fn enable(&self, ctx: &Context) -> Result<()>;
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

## Vendor Configuration Layer (`/etc` and `/usr/etc`)

openSUSE (Leap 15.6+, Tumbleweed, MicroOS) ships its configuration under
`/usr/etc` and reserves `/etc` for administrator overrides, and Fedora is moving
the same way. On those hosts the vendor copy is the file in force wherever `/etc`
holds nothing, so a plugin reading `/etc` alone reports on a file the system does
not obey. `hardener-common/src/vendor_config.rs` is the single place that knows
this:

| Item | Purpose |
|------|---------|
| `ConfigLayer { Admin, Vendor }` | Which directory supplied a file |
| `LayeredRead { Found, Absent, Unreadable }` | The three outcomes of a layered read; `Found` names the path and the layer that answered |
| `read_layered()` | Reads whichever copy is in force for an `/etc` path |
| `vendor_path_for()` | The `/usr/etc` counterpart of an `/etc` path, when there is one (nothing outside `/etc`, and not `/etc` itself) |

Two rules hold everywhere:

1. **`/etc` wins, and `/usr/etc` is consulted only on an absence positively
   confirmed at `/etc`.** An `/etc` file that exists but cannot be read is still
   the file the system obeys, so answering with the vendor copy would report a
   configuration that is not in force. Every other outcome is `Unreadable`,
   never a fallthrough to the vendor layer.
2. **The vendor file is never written.** SSH states its deviation in a drop-in
   under `/etc/ssh/sshd_config.d`, PAM copies the vendor file into `/etc` and
   edits the managed directives into that copy, and permissions reports the
   violation with a copy into `/etc` as the remediation. Editing a package-owned
   file in place would be reverted by the next package update.

Three plugins consult the layer. Permissions was the last one blind to it, until
2026-07-30:

| Plugin | What it asks the vendor layer | Through |
|--------|-------------------------------|---------|
| `SshHardeningPlugin` | The contents of the `sshd_config` in force | `read_layered()` |
| `PamHardeningPlugin` | The contents of the `login.defs` and `pam` files in force, and which keys an `/etc` copy masks | `read_layered()`, `vendor_path_for()` |
| `PermissionsHardeningPlugin` | The **mode** of the vendor counterpart of a path confirmed absent from `/etc` | `vendor_path_for()`, then `path_exists`/`file_metadata` |

Permissions is the odd one out because it audits modes rather than content, so it
probes the counterpart path directly instead of reading a file. Its scan gained a
`PermissionCheck::VendorOnly` outcome, which is a finding rather than an
unchecked check: the mode was read and it does violate, so what is missing is a
remediation this tool may perform, not the evidence. The finding is keyed on the
`/etc` path, so the report, the CLI/GUI dedupe and the differential suite still
resolve it by the identifier they already ask for, while its title and
explanation name the `/usr/etc` file that is actually in force. `apply` and
`validate` are unchanged: apply does nothing for a path absent from `/etc`, and
the dry run accordingly previews nothing, so `scan` is where a vendor violation
is reported. A path absent from both layers stays silent, and a vendor path whose
existence or mode cannot be determined is reported as unchecked, never as
absence.

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

-- Persisted scan sessions (same database). The desktop writes a session per
-- scan; its compliance report and security score derive from the LATEST
-- completed session, so a deep (privileged) scan moves the numeric score.
CREATE TABLE scan_sessions (
    id TEXT PRIMARY KEY,
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    total_findings INTEGER NOT NULL DEFAULT 0,
    total_plugins INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    success INTEGER NOT NULL,
    duration_us INTEGER NOT NULL,
    error_message TEXT,
    unchecked_json TEXT,   -- privilege-blocked/not-applicable checks (additive)
    FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
);
-- scan_findings holds one row per finding, FK to scan_results.

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
| CIS | 41 | Center for Internet Security Benchmarks |
| STIG | 20 | DISA Security Technical Implementation Guides |
| NIST 800-53 | 20 | US Federal security controls |
| PCI-DSS | 22 | Payment Card Industry standards |
| HIPAA | 14 | Healthcare security requirements |
| GDPR | 12 | EU data protection (Article 32) |
| ISO 27001:2022 | 93 | ISO/IEC 27001:2022 Annex A controls (4 themes) |
| SOC 2 | 5 | AICPA Trust Services Criteria (2017, CC-series; coverage-derived) |
| NIST SP 800-171 | 14 | Revision 3 CUI requirements, crosswalked from the plugins' 800-53 controls (coverage-derived) |
| FedRAMP | 19 | Moderate (Rev 5) baseline members among the plugins' 800-53 controls (coverage-derived) |

### Compliance profiles (report-time ID translation)

Plugins always emit **canonical** control identifiers (RHEL 8 baseline for
STIG, distribution-independent CIS numbering); that scheme is the internal
source of truth and never varies by target. Profiles are applied at report
time: `hardener-compliance/src/profiles.rs` holds sourced translation tables
(canonical → benchmark-specific id + title, one-to-many where a benchmark
split a collapsed control), and the `ReportGenerator` passes findings,
plugin coverage, and the curated catalogue through the same `translate` pass
so both sides of every match render one identifier scheme. A canonical id
with no sourced counterpart is omitted from the profiled report: honest
absence, never a guessed mapping.

Profiles: `generic` (default everywhere; STIG headings name their RHEL 8
baseline) and `rhel10` (DISA RHEL 10 STIG V1R1 + CIS RHEL 10 Benchmark
v1.0.1). Resolution reads the scanned system's `/etc/os-release` through the
scan executor (per host in `batch report` and desktop fleet scans, so mixed
fleets assess each host against its own benchmark) and is overridable with
`--profile`. RHEL-family major 10 selects `rhel10`; detection failure
degrades to `generic` and never fails a scan.

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
    // Computed: is_valid() returns allowed && !is_expired()
}
```

---

## Security Features

1. **Cryptographic Signatures**: Ed25519 signatures on all checkpoints
2. **Hash Chain Audit Log**: SHA-256 chain makes tampering detectable
3. **Privilege Separation**: Scan runs unprivileged, apply requires root
4. **Atomic Operations**: File changes use atomic write patterns
5. **Rollback Safety**: Full state restoration from any checkpoint (including directory permissions). Rollback is itself reversible: it snapshots the current state as a new signed checkpoint before restoring, and fails closed (refuses the rollback, writes nothing) if that snapshot cannot be taken. A checkpoint row that records a protected system path (`UNDELETABLE_ROLLBACK_PATHS`: account databases, `/etc/ssh`, `/etc/sudoers` and similar) as absent is never trusted to mean the file should be removed: if that path exists on the host, rollback refuses to delete it and reports it as skipped rather than guessing
6. **Transparent Config**: Configuration cannot hide security findings, only annotate them
7. **Non-POSIX Filesystem Awareness**: Permissions plugin recognises filesystems that ignore `chmod` (vfat/FAT32, exfat, ntfs, iso9660, udf) - e.g. a vfat `/boot` ESP - and reports an unchecked check with fstab `fmask`/`dmask` guidance instead of a false HIGH finding or a futile `chmod`; apply records these as Skipped, and the remote chmod path still verifies the mode actually changed
8. **Vendor Configuration Awareness**: On a distribution that keeps its configuration under `/usr/etc` and reserves `/etc` for administrator overrides, the copy in force is the vendor one wherever `/etc` holds nothing. `hardener-common/src/vendor_config.rs` resolves both layers for the ssh, pam and permissions plugins: `/etc` always wins, `/usr/etc` is consulted only on an absence positively confirmed at `/etc` (an `/etc` file that exists but cannot be read is never answered with the vendor copy), and the vendor file is never written. Until 2026-07-30 the permissions plugin read `/etc` alone, so a confirmed absence there was silence: on the openSUSE test container `/usr/etc/sudoers` sat at 0444 against a required 0440 and the scan reported neither a finding nor an unchecked check, so a Critical severity check passed on evidence nobody had collected. `scan` now reports that mode as a finding keyed on the `/etc` path, with a copy into `/etc` at the required mode as its remediation, while a path absent from both layers, which is what `/etc/gshadow` reads on that host, is still nothing to report

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

The `main` branch is kept in sync on GitHub and GitLab. The release script (`scripts/release/release.sh`) automatically pushes to both remotes.

---

## See Also

- `docs/reference/data-flow.md` - Detailed data flow diagrams
- `docs/plans/archive/CONFIG_DESIGN.md` - Configuration system security design
- `docs/contributing/releasing.md` - Versioning and release process
- `docs/ROADMAP.md` - Development roadmap
- `README.md` - User documentation
