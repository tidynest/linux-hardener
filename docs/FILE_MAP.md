# Linux System Hardener - File Map

**Last Updated:** 2026-02-22

This document lists all source files with their purpose and key exports.

---

## hardener-types (WASM-Compatible Shared Types)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/lib.rs` | All shared type definitions | `PluginId`, `Severity`, `FindingCategory`, `ComplianceFramework`, `ComplianceMapping`, `ControlStatus`, `FindingPolicyException`, `PluginMetadata`, `ScanResult`, `Finding`, `ApplyResult`, `Change`, `ChangeType`, `ValidationReport`, `ValidationIssue`, `ComplianceReport`, `ControlResult`, `ComplianceSummary` |

### Key Types (lib.rs)

```rust
// Core identifiers
pub struct PluginId(String);

// Severity levels (ordered)
pub enum Severity { Info, Low, Medium, High, Critical }

// Finding categories
pub enum FindingCategory { Audit, Authentication, Cryptography, FileSystem, Kernel, MandatoryAccessControl, Network, Services }

// Compliance frameworks
pub enum ComplianceFramework { CIS, HIPAA, ISO27001, NIST, PCIDSS, STIG, GDPR }

// Scan/Apply results
pub struct ScanResult { scan_plugin_id, scan_success, scan_findings, scan_duration_us, scan_error }
pub struct ApplyResult { apply_plugin_id, apply_success, apply_changes, apply_checkpoint_id, apply_error }
pub struct Finding { finding_id, finding_title, finding_severity, ... }

// Compliance report types
pub struct ComplianceReport { report_framework, report_generated_at, report_controls, report_summary }
pub struct ControlResult { control_id, control_title, control_section, control_status, control_findings }
pub struct ComplianceSummary { summary_total_controls, summary_passing, summary_failing, ... }
```

---

## hardener-cli (CLI Binary)

| File | Purpose | Key Exports/Functions |
|------|---------|----------------------|
| `src/main.rs` | Entry point, command routing | `main()` |
| `src/cli.rs` | Clap argument definitions | `Cli`, `Command`, `DaemonAction`, `HistoryAction`, `SystemdAction`, `OutputFormat` |
| `src/output.rs` | Output formatting utilities | `format_findings()`, `format_json()` |
| `src/commands/mod.rs` | Command module exports | - |
| `src/commands/scan.rs` | Scan command implementation | `run()`, `validate_plugin_filter()`, `is_valid_plugin_name()` |
| `src/commands/apply.rs` | Apply command implementation | `run()` |
| `src/commands/checkpoint.rs` | Checkpoint management | `list()`, `create()`, `show()`, `delete()` |
| `src/commands/plugins.rs` | List plugins command | `run()` |
| `src/commands/report.rs` | Compliance report generation | `run()` |
| `src/commands/report_wizard.rs` | Interactive report wizard | `run_interactive()` |
| `src/commands/daemon.rs` | Daemon management commands | `start()`, `run_once()`, `status()` |
| `src/commands/systemd.rs` | Systemd unit file commands | `generate()`, `install()`, `uninstall()`, `status()` |
| `src/commands/history.rs` | Scan history commands | `list()`, `show()`, `export()` |
| `src/ssh_config.rs` | SSH connection config helper | `SshConnectionConfig` |

---

## hardener-core (Plugin Framework)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/lib.rs` | Module exports, feature flags | Re-exports all public types |
| `src/plugin.rs` | Core plugin trait and types | `HardeningPlugin`, `Finding`, `ScanResult`, `ApplyResult` |
| `src/context.rs` | Execution context | `Context`, `SystemInfo` |
| `src/plugin_manager.rs` | Plugin orchestration | `PluginManager` |
| `src/registry.rs` | Plugin registration | `PluginRegistry` |
| `src/config.rs` | Configuration structs | `HardenerConfig`, `GlobalConfig`, `PluginConfig`, `PolicyException` |
| `src/config_loader.rs` | Config loading and merging | `ConfigLoader` |
| `src/testing.rs` | MockPlugin builder for tests | `MockPlugin` |
| `src/executor/mod.rs` | SystemExecutor trait and types | `SystemExecutor`, `CommandOutput`, `FileMetadata` |
| `src/executor/local.rs` | Local file/command operations | `LocalExecutor` |
| `src/executor/ssh.rs` | SSH remote operations | `SshExecutor`, `SshConfig` |
| `src/executor/mock.rs` | Virtual filesystem for testing | `MockExecutor` |

### Key Trait (plugin.rs)

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

---

## hardener-common (Shared Utilities)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/lib.rs` | Module exports | Re-exports |
| `src/types.rs` | Re-exports from hardener-types | `pub use hardener_types::*` (backwards compatibility) |
| `src/error.rs` | Error types | `HardeningError`, `Result<T>` |
| `src/logging.rs` | Logging setup | `init_logging()` |
| `src/file_utils.rs` | File utilities | `update_file_atomically()`, `read_config_file()`, `set_config_directive()`, `create_timestamped_backup()` |

**Note**: Core types (Severity, FindingCategory, etc.) are now defined in `hardener-types` and re-exported here for backwards compatibility.

---

## hardener-plugins (Security Plugins)

| File | Purpose | Plugin Struct |
|------|---------|---------------|
| `src/lib.rs` | Module exports, helpers | `create_checkpoint_for_apply()`, `rollback_files_from_checkpoint()` |
| `src/macros.rs` | Plugin definition macro | `define_plugin!` |

### Individual Plugins

| Plugin File | Category | Key Checks |
|-------------|----------|------------|
| `src/ssh/mod.rs` | Network | PermitRootLogin, PasswordAuthentication, MaxAuthTries, X11Forwarding, Protocol, ClientAliveInterval |
| `src/kernel/mod.rs` | Kernel | ASLR, kptr_restrict, dmesg_restrict, ptrace_scope, suid_dumpable, rp_filter, tcp_syncookies |
| `src/firewall/mod.rs` | Network | Firewall enabled, baseline rules |
| `src/firewall/nftables.rs` | Network | nftables backend |
| `src/firewall/firewalld.rs` | Network | firewalld backend |
| `src/firewall/ufw.rs` | Network | UFW backend |
| `src/pam/mod.rs` | Auth | Password complexity, aging, lockout |
| `src/services/mod.rs` | Services | Unnecessary services (xinetd, cups, avahi, etc.) |
| `src/permissions/mod.rs` | FileSystem | Critical paths, SUID/SGID, world-writable |
| `src/audit/mod.rs` | Audit | auditd rules for time, users, permissions |
| `src/mac/mod.rs` | MAC | SELinux/AppArmor status |

### Plugin Constants (Examples)

**SSH (ssh/mod.rs):**
```rust
const SSH_DIRECTIVES: &[SshConfigDirective] = &[
    SshConfigDirective { ssh_directive_name: "PermitRootLogin", ssh_secure_value: "no", ... },
    SshConfigDirective { ssh_directive_name: "PasswordAuthentication", ssh_secure_value: "no", ... },
    // ... 8 total
];
```

**Kernel (kernel/mod.rs):**
```rust
const KERNEL_PARAMS: &[(&str, &str, &str)] = &[
    ("kernel.randomize_va_space", "2", "Enable ASLR"),
    ("kernel.kptr_restrict", "2", "Hide kernel pointers"),
    // ... 12 total
];
```

---

## hardener-state (State Management)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/lib.rs` | Module exports | Re-exports |
| `src/checkpoint.rs` | Checkpoint types | `Checkpoint`, `CheckpointId`, `FileState` |
| `src/manager.rs` | Checkpoint operations | `CheckpointManager` |
| `src/audit.rs` | Audit logging | `AuditEntry`, `AuditLogger`, `ActionType` |
| `src/hash_chain.rs` | Tamper detection | `HashChain` |
| `src/signing.rs` | Cryptographic signing | `CheckpointSigner` |
| `src/db.rs` | Database schema | `init_database()` |
| `src/scan_history.rs` | GUI scan session types | `ScanSessionId`, `ScanStatus`, `ScanSession` |
| `src/scan_manager.rs` | GUI scan persistence | `ScanHistoryManager` |

### Key Structures

```rust
pub struct Checkpoint {
    pub checkpoint_id: CheckpointId,
    pub checkpoint_name: String,
    pub checkpoint_timestamp: i64,
    pub checkpoint_username: String,
    pub checkpoint_signature: Vec<u8>,
}

pub struct FileState {
    pub file_path: String,
    pub file_content: Option<Vec<u8>>,
    pub file_permissions: u32,
    pub file_owner_uid: u32,
    pub file_owner_gid: u32,
}
```

---

## hardener-compliance (Compliance Reports)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/lib.rs` | Module exports | Re-exports |
| `src/report.rs` | Report types | `ComplianceReport`, `ControlResult`, `ComplianceSummary` |
| `src/generator.rs` | Report generation | `ReportGenerator` |
| `src/config.rs` | Report configuration | `ReportConfig` |
| `src/frameworks/mod.rs` | Framework routing | `get_framework_controls()` |
| `src/frameworks/cis.rs` | CIS Benchmark | CIS control mappings |
| `src/frameworks/nist.rs` | NIST 800-53 | NIST control mappings |
| `src/frameworks/stig.rs` | DISA STIG | STIG control mappings |
| `src/frameworks/hipaa.rs` | HIPAA | HIPAA control mappings |
| `src/frameworks/pci.rs` | PCI-DSS | PCI control mappings |
| `src/frameworks/gdpr.rs` | GDPR | GDPR control mappings |
| `src/output/mod.rs` | Formatter routing | `format_report()` |
| `src/output/text.rs` | Text formatter | `TextFormatter` |
| `src/output/json.rs` | JSON formatter | `JsonFormatter` |
| `src/output/csv.rs` | CSV formatter | `CsvFormatter` |
| `src/output/html.rs` | HTML formatter | `HtmlFormatter` |
| `src/output/pdf.rs` | PDF formatter | `PdfFormatter` |
| `src/fonts/NotoSans-Regular.ttf` | Embedded font | Regular weight |
| `src/fonts/NotoSans-Bold.ttf` | Embedded font | Bold weight |

---

## hardener-distro (Distribution Detection)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/lib.rs` | Module exports | Re-exports |
| `src/adapter.rs` | Distribution adapter | `DistributionAdapter`, `Distribution`, `DistroFamily` |
| `src/package/mod.rs` | Package manager abstraction | `PackageManager` trait |
| `src/package/apt.rs` | Debian family | `AptPackageManager` |
| `src/package/dnf.rs` | Red Hat family | `DnfPackageManager` |
| `src/package/pacman.rs` | Arch family | `PacmanPackageManager` |
| `src/package/zypper.rs` | SUSE family | `ZypperPackageManager` |

---

## hardener-scheduler (Scheduled Scanning)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/lib.rs` | Module exports | Re-exports public types |
| `src/config.rs` | Scheduler configuration | `SchedulerConfig`, `StorageConfig`, `NotificationConfig`, `EmailConfig`, `WebhookConfig` |
| `src/db.rs` | SQLite scan history | `ScanHistoryManager`, `ScanSession`, `ScanFinding`, `SeverityCounts` |
| `src/json_store.rs` | JSON file storage | `JsonStore`, `StoredScan` |
| `src/runner.rs` | Scan execution orchestrator | `ScanRunner`, `ScanSummary`, `TriggerType` |
| `src/daemon.rs` | Cron-scheduled scanning daemon | `Daemon` |
| `src/notification/mod.rs` | Notification system module | `Notifier`, `NotificationResult`, `parse_severity()`, `meets_severity_threshold()` |
| `src/notification/email.rs` | SMTP email notifications | `EmailNotifier` |
| `src/notification/webhook.rs` | HTTP webhook notifications | `WebhookNotifier` |
| `src/notification/dispatcher.rs` | Notification coordinator | `NotificationDispatcher` |
| `src/systemd.rs` | Systemd unit file generation | `SystemdGenerator`, `cron_to_calendar()`, `service_name()`, `timer_name()` |

### Key Structures (daemon.rs)

```rust
/// Cron-scheduled scanning daemon with graceful shutdown.
pub struct Daemon {
    daemon_config: SchedulerConfig,
    daemon_runner: Arc<ScanRunner>,
    daemon_scheduler: Option<JobScheduler>,
    daemon_shutdown_tx: Option<broadcast::Sender<()>>,
    daemon_scan_in_progress: Arc<AtomicBool>,
}

impl Daemon {
    pub fn new(config: SchedulerConfig, db: Arc<ScanHistoryManager>, json_store: Arc<JsonStore>) -> Self;
    pub async fn start(&mut self, pm: Arc<PluginManager>, ctx: Arc<Context>) -> Result<()>;
    pub async fn run_once(&self, pm: &PluginManager, ctx: &Context, trigger: TriggerType) -> Result<ScanSummary>;
    pub async fn stop(&mut self) -> Result<()>;
}
```

### Key Structures (config.rs)

```rust
pub struct SchedulerConfig {
    pub scheduler_enabled: bool,
    pub scheduler_schedule: String,           // Cron expression
    pub scheduler_plugins: Vec<String>,
    pub scheduler_min_severity: String,
    pub scheduler_storage: StorageConfig,
    pub scheduler_notifications: NotificationConfig,
}

pub struct StorageConfig {
    pub storage_database_path: PathBuf,
    pub storage_json_output_dir: PathBuf,
    pub storage_retention_count: u32,
    pub storage_retention_days: u32,
}
```

### Database Schema (db.rs)

```sql
CREATE TABLE scan_sessions (
    id TEXT PRIMARY KEY,
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    status TEXT NOT NULL DEFAULT 'running',
    trigger_type TEXT NOT NULL,
    host_identifier TEXT NOT NULL,
    plugins_scanned TEXT NOT NULL,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    error_message TEXT,
    json_file_path TEXT,
    hash TEXT
);

CREATE TABLE scan_findings (...);
CREATE TABLE notification_log (...);
```

### Key Trait (notification/mod.rs)

```rust
/// Trait for notification channels.
#[async_trait]
pub trait Notifier: Send + Sync {
    /// Sends a notification with the scan summary.
    async fn send(&self, summary: &ScanSummary) -> NotificationResult;
    /// Returns the channel identifier for logging.
    fn channel(&self) -> &str;
}

/// Result of a notification attempt.
pub struct NotificationResult {
    pub channel: String,
    pub success: bool,
    pub error: Option<String>,
}
```

### Key Structures (dispatcher.rs)

```rust
/// Dispatches notifications to all configured channels.
pub struct NotificationDispatcher {
    notifiers: Vec<Box<dyn Notifier>>,
    min_severity: Severity,
    db: Arc<ScanHistoryManager>,
}

impl NotificationDispatcher {
    pub fn new(config: &NotificationConfig, db: Arc<ScanHistoryManager>) -> Self;
    pub async fn dispatch(&self, summary: &ScanSummary) -> Vec<NotificationResult>;
}
```

### Key Structures (runner.rs)

```rust
/// Trigger source for a scan session.
pub enum TriggerType {
    Scheduled,  // Cron scheduler daemon
    Manual,     // CLI command
    Systemd,    // Systemd timer
}

/// Summary of a completed scan for notifications.
pub struct ScanSummary {
    pub session_id: String,
    pub host: String,
    pub plugins_scanned: Vec<String>,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub json_path: Option<String>,
    pub json_hash: Option<String>,
    pub had_errors: bool,
}

/// Orchestrates plugin scans with database and JSON persistence.
pub struct ScanRunner {
    db: Arc<ScanHistoryManager>,
    json_store: Arc<JsonStore>,
    min_severity: Severity,
    plugins: Vec<String>,
    host: String,
}
```

---

## hardener-ui (Leptos WASM Frontend)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `index.html` | Entry HTML with font links | `#app` mount point |
| `styles.css` | Dark terminal theme CSS | CSS Variables, utility classes (.truncate, .sr-only, .skip-link), tabs, navigation, score gauge, buttons, tables, forms |
| `src/lib.rs` | Main App component, WASM entry point | `App`, `#[wasm_bindgen(start)] main()` |
| `src/types.rs` | Re-exports from hardener-types | `pub use hardener_types::*`, `CheckpointInfo` |
| `src/state/mod.rs` | Reactive state | `AppState` |
| `src/tauri_bindings.rs` | Tauri command bindings | `tauri_available`, `invoke_scan`, `invoke_apply`, `invoke_generate_report`, `invoke_get_latest_scan`, `invoke_get_checkpoints`, `invoke_rollback` |
| `src/utils/mod.rs` | Utils module exports | Re-exports (mock_data) |
| `src/utils/mock_data.rs` | Development mocks | Mock data generators |
| `src/pages/mod.rs` | Pages module exports | `DashboardPage`, `AnalysisPage`, `HardeningPage` |
| `src/components/mod.rs` | Components module exports | All component re-exports, `Card`, `CardVariant`, `HeadingLevel` |

### Pages (3-page architecture)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/pages/dashboard_page.rs` | Dashboard with security score and quick actions | `DashboardPage` |
| `src/pages/analysis_page.rs` | Tabbed interface for findings and compliance | `AnalysisPage` |
| `src/pages/hardening_page.rs` | Sectioned interface for configuration and history | `HardeningPage` |

### Components

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/components/security_score.rs` | Main security score gauge with compliance-based calculation | `SecurityScore`, `calculate_all_scores()`, `FrameworkScore` |
| `src/components/mini_security_score.rs` | Compact score for headers | `MiniSecurityScore` |
| `src/components/quick_actions.rs` | Dashboard quick action buttons | `QuickActions` |
| `src/components/recent_activity.rs` | Recent scan/apply activity summary | `RecentActivity` |
| `src/components/tabs.rs` | Reusable tab bar and panel with WAI-ARIA | `TabBar`, `TabDef` (id, label, badge), `TabPanel` (id, index, active_tab) |
| `src/components/findings_grid.rs` | Findings table display | `FindingsGrid` |
| `src/components/finding_detail.rs` | Individual finding details panel | `FindingDetail` |
| `src/components/findings_tab.rs` | Findings tab wrapper for Analysis page | `FindingsTab` |
| `src/components/compliance_tab.rs` | Compliance framework selection and reports with status feedback | `ComplianceTab` |
| `src/components/configure_section.rs` | Profile selection and plugin toggles | `ConfigureSection` |
| `src/components/history_section.rs` | Apply results and checkpoint management with refresh button | `HistorySection` |
| `src/components/severity_badge.rs` | Severity level badge display | `SeverityBadge` |
| `src/components/card.rs` | Reusable card container component | `Card`, `CardVariant`, `HeadingLevel` |
| `src/components/theme_toggle.rs` | Theme selector dropdown component | `ThemeToggle` |

**Note**: This crate depends only on `hardener-types` for shared types to ensure WASM compatibility. External dependencies include Leptos (WASM framework), wasm-bindgen, and web-sys for browser APIs.

### Theme Files (crates/hardener-ui/themes/)

| File | Purpose |
|------|---------|
| `themes/README.md` | Theme system documentation |
| `themes/fortress.css` | Deep slate-blue with gold accents |
| `themes/sentinel.css` | Warm charcoal with amber accents |
| `themes/command.css` | Navy with ice-blue accents |
| `themes/guardian.css` | Forest black with emerald accents |
| `themes/daywatch.css` | Light mode with warm off-white |
| `themes/github-dark.css` | GitHub-inspired dark theme |
| `themes/midnight-teal.css` | Deep teal dark theme |

**Note**: Active theme definitions are in `styles.css` using `[data-theme="..."]` selectors. Individual theme files serve as reference and documentation.

### Tauri Bindings (tauri_bindings.rs)

```rust
/// Check if Tauri runtime is available (desktop app vs browser).
#[wasm_bindgen(inline_js = "export function is_tauri_available() { return typeof window.__TAURI__ !== 'undefined'; }")]
extern "C" {
    fn is_tauri_available() -> bool;
}

/// Returns true if running inside Tauri desktop app, false if in browser.
pub fn tauri_available() -> bool;

/// All invoke_* functions check tauri_available() first.
/// In browser mode, they return Err("Tauri not available (running in browser mode)").
pub async fn invoke_scan() -> Result<Vec<ScanResult>, String>;
pub async fn invoke_apply(plugin_ids: Vec<String>) -> Result<Vec<ApplyResult>, String>;
pub async fn invoke_generate_report(frameworks: Vec<String>) -> Result<Vec<ComplianceReport>, String>;
pub async fn invoke_get_latest_scan() -> Result<Option<Vec<ScanResult>>, String>;
pub async fn invoke_get_checkpoints() -> Result<Vec<CheckpointInfo>, String>;
pub async fn invoke_rollback(checkpoint_id: String) -> Result<(), String>;
```

---

## src-tauri (Desktop Backend)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/main.rs` | Tauri app entry | `main()` |
| `src/commands.rs` | Tauri invoke handlers | `run_scan`, `run_apply`, `run_rollback`, `get_checkpoints`, `get_latest_scan`, `generate_compliance_report` |

### Tauri Commands

```rust
#[tauri::command]
pub async fn run_scan() -> Result<Vec<ScanResult>, String>

#[tauri::command]
pub async fn run_apply(plugin_ids: Vec<String>) -> Result<Vec<ApplyResult>, String>

#[tauri::command]
pub async fn run_rollback(checkpoint_id: String) -> Result<bool, String>

#[tauri::command]
pub async fn get_checkpoints() -> Result<Vec<CheckpointInfo>, String>
// Note: Reads from BOTH user (~/.local/share/linux-hardener/checkpoints.db) AND
// system (/var/lib/linux-hardener/checkpoints.db) databases to merge checkpoints
// from privileged (pkexec) and non-privileged operations

#[tauri::command]
pub async fn get_latest_scan() -> Result<Option<Vec<ScanResult>>, String>

#[tauri::command]
pub async fn generate_compliance_report(frameworks: Vec<String>) -> Result<Vec<ComplianceReport>, String>
```

---

## Configuration Files

| File | Purpose |
|------|---------|
| `Cargo.toml` | Workspace definition |
| `.cargo/config.toml` | WASM rustflags (getrandom backend) |
| `.cargo/audit.toml` | Cargo audit configuration |
| `rustfmt.toml` | Rust formatting config |
| `deny.toml` | Cargo deny (dependency policy) configuration |
| `release.toml` | cargo-release configuration |
| `cliff.toml` | git-cliff changelog generation |
| `.gitignore` | Git ignore rules |
| `src-tauri/tauri.conf.json` | Tauri app configuration |
| `src-tauri/build.rs` | Tauri build script |
| `crates/hardener-ui/Trunk.toml` | Trunk WASM build configuration |
| `crates/hardener-ui/index.html` | WASM app entry HTML |

---

## CI/CD Files

| File | Purpose |
|------|---------|
| `.github/workflows/ci.yml` | GitHub Actions: check, test, clippy, fmt, security audit, build |
| `.github/workflows/release.yml` | GitHub Actions: multi-target builds, GitHub releases on tag push |
| `.gitlab-ci.yml` | GitLab CI: check, test, build, release stages |

---

## Scripts

| File | Purpose |
|------|---------|
| `scripts/README.md` | Comprehensive script documentation |
| `scripts/validate_naming.py` | Naming convention validator |
| `scripts/validate_all.py` | Master validation orchestrator |
| `scripts/validate_cli_docs.py` | CLI command documentation validator |
| `scripts/validate_compliance_docs.py` | Compliance framework documentation validator |
| `scripts/validate_file_map.py` | FILE_MAP.md accuracy validator |
| `scripts/validate_last_updated.py` | Last Updated timestamp validator |
| `scripts/validate_plugin_docs.py` | Plugin documentation validator |
| `scripts/validate_tauri_docs.py` | Tauri integration documentation validator |
| `scripts/update_all_docs.py` | Batch documentation updater |
| `scripts/release.sh` | Automated version bumping and release |
| `scripts/tauri-dev.sh` | Tauri development launcher |
| `scripts/full-test-suite.sh` | Complete 102-test validation suite |
| `scripts/root-test-suite.sh` | 36 root-level privilege tests |
| `scripts/manual-verification-test.sh` | Interactive verification tests |
| `scripts/create-test-container.sh` | Arch Linux systemd-nspawn container |
| `scripts/create-debian-container.sh` | Debian 12 test container |
| `scripts/create-fedora-container.sh` | Fedora 41 test container |
| `scripts/create-opensuse-container.sh` | openSUSE Leap test container |

---

## Documentation Files

| File | Purpose |
|------|---------|
| `README.md` | User documentation |
| `ROADMAP.md` | Development roadmap |
| `NEXT.md` | Session handoff and current state |
| `CHANGELOG.md` | Version history |
| `CONTRIBUTING.md` | Contribution guidelines |
| `SECURITY.md` | Security policy |
| `LICENSE` | Apache-2.0 licence |
| `MCP_INSTRUCTIONS.md` | MCP configuration instructions |
| `docs/ARCHITECTURE.md` | Architecture overview |
| `docs/browser-automation.md` | Playwright MCP browser automation setup and troubleshooting |
| `docs/claude-code-configuration.md` | Claude Code MCP configuration reference |
| `docs/CLI_V032_TEST_RESULTS.md` | CLI v0.3.2 validation results |
| `docs/COMPREHENSIVE_AUDIT_REPORT.md` | Full project audit: 13 bugs found and fixed |
| `docs/CONFIG_DESIGN.md` | Config system security design |
| `docs/css-architecture.md` | CSS architecture and patterns |
| `docs/DATA_FLOW.md` | Data flow diagrams |
| `docs/DEPENDENCY_AUDIT_2025-12-08.md` | Dependency security audit |
| `docs/DISTRIBUTION_VALIDATION.md` | Multi-distro validation results |
| `docs/DOCUMENTATION_AUDIT.md` | Documentation completeness audit |
| `docs/FILE_MAP.md` | This file |
| `docs/FRONTEND_LAYOUT_PLAN.md` | GUI layout implementation plan |
| `docs/GUI_CLI_PARITY_PLAN.md` | GUI-CLI feature parity plan |
| `docs/GUI_V031_TEST_PLAN.md` | GUI v0.3.1 test plan |
| `docs/NAMING_CONVENTIONS.md` | Naming standards |
| `docs/PENDING_TASKS.md` | Tracked pending tasks and follow-ups |
| `docs/RELEASING.md` | Versioning and release process |
| `docs/REPO_COMPARISON.md` | Repository structure comparison |
| `docs/SSH_REMOTE_SCANNING.md` | SSH remote scanning user guide |
| `docs/tauri-plus-leptos-development-on-arch-linux-with-hyprland.md` | Tauri + Leptos dev guide |
| `docs/THEME_DESIGN_GUIDE.md` | GUI theming system documentation |
| `docs/WASM_FIX_PLAN.md` | WASM compilation fix implementation |
| `docs/plans/2026-02-22-trait-refactor.md` | Trait refactor execution log |
| `docs/plans/2026-02-22-trait-refactor-design.md` | Trait refactor design document |

---

## Test Files

Tests are co-located with source files using `#[cfg(test)]` modules, plus integration tests in `tests/` directories within each crate.

| Crate | Unit Tests | Integration Tests | Total |
|-------|------------|-------------------|-------|
| hardener-common | `error.rs`, `file_utils.rs`, `logging.rs` | `common_types.rs` | 30 |
| hardener-compliance | `config.rs`, `report.rs`, `output/*.rs`, `generator.rs` | `framework_tests.rs` | 46 |
| hardener-state | `audit.rs`, `hash_chain.rs`, `signing.rs`, `db.rs` | `checkpoint_system.rs` | 31 |
| hardener-distro | `adapter.rs`, `package/*.rs` | - | 15 |
| hardener-scheduler | `config.rs`, `db.rs`, `json_store.rs`, `runner.rs`, `daemon.rs`, `notification/*.rs` | - | 48 |
| hardener-cli | `cli.rs`, `output.rs`, `history.rs` | - | 31 |
| hardener-plugins | - | `*_tests.rs` (8 files), `*_mock_tests.rs` (8 files), `ssh_integration_tests.rs` | 128+ |
| hardener-core | `config.rs`, `context.rs`, `plugin.rs`, `registry.rs`, `config_loader.rs` | `plugin_manager_tests.rs`, `mock_executor_tests.rs`, `ssh_executor_tests.rs` | 43+ |

### New Test Files (v0.3.0)

| File | Purpose | Tests |
|------|---------|-------|
| `hardener-core/tests/mock_executor_tests.rs` | MockExecutor unit tests | 14 |
| `hardener-core/tests/ssh_executor_tests.rs` | SshExecutor unit/integration tests | 14 |
| `hardener-plugins/tests/*_mock_tests.rs` | Mock-based plugin tests (8 files) | 80 |
| `hardener-plugins/tests/ssh_integration_tests.rs` | Plugin SSH integration tests | 10 |

---

## Configuration Files (Implemented)

| File | Purpose |
|------|---------|
| `hardener-core/src/config.rs` | Config structs: `HardenerConfig`, `GlobalConfig`, `PluginConfig`, `PolicyException` |
| `hardener-core/src/config_loader.rs` | Config loading and merging from multiple sources |
| `hardener-common/src/types.rs` | Added `FindingPolicyException` struct |
| `hardener-cli/src/cli.rs` | Added `--config`, `--audit`, `--compliance`, `--exit-code` flags, `ScanMode` enum |

**Last Updated**: 2026-02-22
