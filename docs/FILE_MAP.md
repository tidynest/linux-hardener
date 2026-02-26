# Linux System Hardener - File Map

**Last Updated:** 2026-02-26

This document lists all source files with their purpose and key exports.

---

## hardener-types (WASM-Compatible Shared Types)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/lib.rs` | All shared type definitions | `PluginId`, `Severity`, `FindingCategory`, `ComplianceFramework`, `ComplianceMapping`, `ControlStatus`, `FindingPolicyException`, `PluginMetadata`, `ScanResult`, `Finding`, `ApplyResult`, `Change`, `ChangeType`, `ValidationReport`, `ValidationIssue`, `ComplianceReport`, `ControlResult`, `ComplianceSummary`, `ConfigSummary` |
| `src/config_picker.rs` | Config file picker types | `ConfigSummary`, WASM-safe validation results for config file picker |
| `src/remote.rs` | Remote SSH scanning types | `RemoteHostProfile`, `HostsConfig`, `RemoteConnectionStatus`, `RemoteConnectionInfo` |
| `src/scheduler.rs` | Scheduler UI types | `SchedulerUiConfig`, `NotificationUiConfig`, `EmailUiConfig`, `WebhookUiConfig`, `TestNotificationResult` |

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
| `src/output.rs` | Output formatting utilities | `status()`, `info()`, `error()`, `scan_results()`, `apply_results()`, `plugin_list()`, `checkpoint_list()`, `checkpoint_created()`, `checkpoint_details()`, `rollback_result()`, `validation_reports()` |
| `src/commands/mod.rs` | Command module exports | - |
| `src/commands/scan.rs` | Scan command implementation | `run()`, `validate_plugin_filter()`, `is_valid_plugin_name()`, `persist_scan_session()` |
| `src/commands/apply.rs` | Apply command implementation | `run()` |
| `src/commands/checkpoint.rs` | Checkpoint management | `list()`, `create()`, `show()`, `delete()` |
| `src/commands/plugins.rs` | List plugins command | `run()` |
| `src/commands/report.rs` | Compliance report generation | `run()` |
| `src/commands/report_wizard.rs` | Interactive report wizard | `run_interactive()` |
| `src/commands/daemon.rs` | Daemon management commands | `start()`, `run_once()`, `status()` |
| `src/commands/systemd.rs` | Systemd unit file commands | `generate()`, `install()`, `uninstall()`, `status()` |
| `src/commands/history.rs` | Scan history commands | `list()`, `show()`, `export()` |
| `src/ssh_config.rs` | SSH connection config helper | `SshConnectionConfig` |
| `src/commands/state.rs` | Shared state initialisation (DB + signing key paths) | `get_checkpoint_manager()`, `get_audit_logger()`, `effective_user()` |

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
| `src/config_validation.rs` | Config directive validation at load time | `validate_config()`, per-plugin validators (kernel, SSH, firewall, PAM, permissions) |
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
| `src/binary_utils.rs` | Safe binary path resolution (CWE-426 prevention) | `resolve_binary()`, `TRUSTED_PATH` |

**Note**: Core types (Severity, FindingCategory, etc.) are now defined in `hardener-types` and re-exported here for backwards compatibility.

---

## hardener-plugins (Security Plugins)

| File | Purpose | Plugin Struct |
|------|---------|---------------|
| `src/lib.rs` | Module exports, helpers | `create_checkpoint_for_apply()`, `create_checkpoint_metadata_only_for_apply()`, `rollback_files_from_checkpoint()` |
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
| `src/checkpoint.rs` | Checkpoint types | `Checkpoint`, `CheckpointId`, `FileState`; re-exports `RollbackResult`, `FileRestoreResult`, `FileRestoreAction` from `hardener-types` |
| `src/manager.rs` | Checkpoint operations | `CheckpointManager`, `create_checkpoint_metadata_only()`, `capture_directory_entry()` |
| `src/audit.rs` | Audit logging | `AuditEntry`, `AuditLogger`, `ActionType` |
| `src/hash_chain.rs` | Tamper detection | `HashChain` |
| `src/signing.rs` | Cryptographic signing | `CheckpointSigner` |
| `src/db.rs` | Database schema | `init_db()` |
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
    pub enabled: bool,
    pub schedule: String,                     // Cron expression
    pub plugins: Vec<String>,
    pub min_severity: String,
    pub storage: StorageConfig,
    pub notifications: NotificationConfig,
}

pub struct StorageConfig {
    pub database_path: PathBuf,
    pub json_output_dir: PathBuf,
    pub retention_count: u32,
    pub retention_days: u32,
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
| `src/types.rs` | Re-exports from hardener-types | `pub use hardener_types::*` (ApplyResult, Change, ChangeType, ComplianceFramework, ComplianceMapping, ComplianceReport, ComplianceSummary, ConfigSummary, ControlResult, ControlStatus, FileRestoreAction, FileRestoreResult, Finding, FindingCategory, FindingPolicyException, PluginId, PluginMetadata, RollbackResult, ScanResult, Severity, ValidationIssue, ValidationReport), scheduler re-exports (SchedulerUiConfig, NotificationUiConfig, EmailUiConfig, WebhookUiConfig, TestNotificationResult), `CheckpointInfo`, `ScanSessionInfo`, `CheckpointDetail`, `CheckpointFileInfo` |
| `src/state/mod.rs` | Reactive state | `AppState` |
| `src/tauri_bindings.rs` | Tauri command bindings | `tauri_available`, `invoke_scan`, `invoke_apply`, `invoke_apply_dry_run`, `invoke_generate_report`, `invoke_export_report`, `invoke_get_latest_scan`, `invoke_get_checkpoints`, `invoke_create_checkpoint`, `invoke_delete_checkpoint`, `invoke_get_scan_history`, `invoke_get_scan_session`, `invoke_get_checkpoint_detail`, `invoke_rollback`, `invoke_list_remote_hosts`, `invoke_save_remote_host`, `invoke_delete_remote_host`, `invoke_connect_remote`, `invoke_disconnect_remote`, `invoke_remote_scan`, `invoke_get_scheduler_config`, `invoke_save_scheduler_config`, `invoke_test_notification`, `invoke_validate_config`, `invoke_pick_config_file` |
| `src/utils/mod.rs` | Utils module exports | Re-exports (mock_data) |
| `src/utils/mock_data.rs` | Development mocks | Mock data generators |
| `src/pages/mod.rs` | Pages module exports | `DashboardPage`, `AnalysisPage`, `HardeningPage` |
| `src/components/mod.rs` | Components module exports | All component re-exports, `Card`, `CardVariant`, `HeadingLevel` |

### Pages (5-page architecture)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/pages/dashboard_page.rs` | Dashboard with security score and quick actions | `DashboardPage` |
| `src/pages/analysis_page.rs` | Tabbed interface for findings and compliance | `AnalysisPage` |
| `src/pages/hardening_page.rs` | Sectioned interface for configuration and history | `HardeningPage` |
| `src/pages/remote_page.rs` | Remote SSH host management and scanning | `RemotePage` |
| `src/pages/scheduler_page.rs` | Scheduler and notification configuration | `SchedulerPage` |

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
| `src/components/host_list.rs` | Remote host profile list sidebar | `HostList` |
| `src/components/host_form.rs` | Add/edit remote host profile form | `HostForm` |
| `src/components/remote_status.rs` | Remote connection status and scan results | `RemoteStatus` |
| `src/components/scan_history_tab.rs` | Scan history timeline for Analysis page | `ScanHistoryTab` |
| `src/components/schedule_section.rs` | Cron schedule configuration form | `ScheduleSection` |
| `src/components/notification_section.rs` | Email and webhook notification config | `NotificationSection` |
| `src/components/config_file_card.rs` | Config file picker card component (text input, browse, validation) | `ConfigFileCard` |

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

// Core scan/apply/rollback
pub async fn invoke_scan(plugin_ids: Vec<String>, config_path: Option<String>) -> Result<Vec<ScanResult>, String>;
pub async fn invoke_apply(plugin_ids: Vec<String>, config_path: Option<String>) -> Result<Vec<ApplyResult>, String>;
pub async fn invoke_apply_dry_run(plugin_ids: Vec<String>, config_path: Option<String>) -> Result<Vec<ValidationReport>, String>;
pub async fn invoke_rollback(checkpoint_id: String, config_path: Option<String>) -> Result<RollbackResult, String>;

// Compliance reports
pub async fn invoke_generate_report(frameworks: Vec<String>) -> Result<Vec<ComplianceReport>, String>;
pub async fn invoke_export_report(frameworks: Vec<String>, format: String, output_path: Option<String>) -> Result<String, String>;

// Scan history
pub async fn invoke_get_latest_scan() -> Result<Option<Vec<ScanResult>>, String>;
pub async fn invoke_get_scan_history(limit: Option<i32>) -> Result<Vec<ScanSessionInfo>, String>;
pub async fn invoke_get_scan_session(session_id: String) -> Result<Vec<ScanResult>, String>;

// Checkpoints
pub async fn invoke_get_checkpoints() -> Result<Vec<CheckpointInfo>, String>;
pub async fn invoke_create_checkpoint(name: String) -> Result<String, String>;
pub async fn invoke_delete_checkpoint(checkpoint_id: String) -> Result<bool, String>;
pub async fn invoke_get_checkpoint_detail(checkpoint_id: String) -> Result<CheckpointDetail, String>;

// Remote scanning
pub async fn invoke_list_remote_hosts() -> Result<Vec<RemoteHostProfile>, String>;
pub async fn invoke_save_remote_host(profile: RemoteHostProfile) -> Result<(), String>;
pub async fn invoke_delete_remote_host(name: String) -> Result<(), String>;
pub async fn invoke_connect_remote(name: String) -> Result<RemoteConnectionStatus, String>;
pub async fn invoke_disconnect_remote() -> Result<(), String>;
pub async fn invoke_remote_scan(plugin_ids: Option<Vec<String>>) -> Result<Vec<ScanResult>, String>;

// Scheduler
pub async fn invoke_get_scheduler_config() -> Result<SchedulerUiConfig, String>;
pub async fn invoke_save_scheduler_config(config: SchedulerUiConfig) -> Result<String, String>;
pub async fn invoke_test_notification() -> Result<TestNotificationResult, String>;

// Config file picker
pub async fn invoke_validate_config(path: String) -> Result<ConfigSummary, String>;
pub async fn invoke_pick_config_file() -> Result<Option<String>, String>;
```

---

## src-tauri (Desktop Backend)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/main.rs` | Tauri app entry | `main()` |
| `src/commands.rs` | Tauri invoke handlers | `run_scan`, `run_apply`, `run_apply_dry_run`, `run_rollback`, `get_checkpoints`, `create_checkpoint`, `delete_checkpoint`, `get_checkpoint_detail`, `generate_compliance_report`, `export_compliance_report`, `get_scan_history`, `get_scan_session`, `list_plugins`, `get_latest_scan`, `list_remote_hosts`, `save_remote_host`, `delete_remote_host`, `connect_remote`, `disconnect_remote`, `run_remote_scan`, `get_scheduler_config`, `save_scheduler_config`, `test_notification`, `validate_config`, `pick_config_file` |
| `src/validation.rs` | IPC input validation layer | `validate_ipc_string()`, `validate_plugin_ids()`, `validate_checkpoint_id()`, `validate_checkpoint_name()`, `validate_privileged_config_path()`, `validate_user_config_path()`, `validate_output_path()`, `validate_ssh_key_path()` |

### Tauri Commands

```rust
// Core scan/apply/rollback
#[tauri::command]
pub async fn run_scan(plugin_ids: Option<Vec<String>>, config_path: Option<String>) -> Result<Vec<ScanResult>, String>
#[tauri::command]
pub async fn run_apply(plugin_ids: Vec<String>, config_path: Option<String>) -> Result<Vec<ApplyResult>, String>
#[tauri::command]
pub async fn run_apply_dry_run(plugin_ids: Vec<String>, config_path: Option<String>) -> Result<Vec<ValidationReport>, String>
#[tauri::command]
pub async fn run_rollback(checkpoint_id: String, config_path: Option<String>) -> Result<RollbackResult, String>

// Checkpoints
#[tauri::command]
pub async fn get_checkpoints() -> Result<Vec<CheckpointInfo>, String>
// Note: Reads from BOTH user (~/.local/share/linux-hardener/checkpoints.db) AND
// system (/var/lib/linux-hardener/checkpoints.db) databases to merge checkpoints
// from privileged (pkexec) and non-privileged operations
#[tauri::command]
pub async fn create_checkpoint(name: String) -> Result<String, String>
#[tauri::command]
pub async fn delete_checkpoint(checkpoint_id: String) -> Result<bool, String>
#[tauri::command]
pub async fn get_checkpoint_detail(checkpoint_id: String) -> Result<CheckpointDetail, String>

// Compliance reports
#[tauri::command]
pub async fn generate_compliance_report(frameworks: Vec<String>) -> Result<Vec<ComplianceReport>, String>
#[tauri::command]
pub async fn export_compliance_report(frameworks: Vec<String>, format: String, output_path: Option<String>) -> Result<String, String>

// Scan history
#[tauri::command]
pub async fn get_scan_history(limit: Option<i32>) -> Result<Vec<ScanSessionInfo>, String>
#[tauri::command]
pub async fn get_scan_session(session_id: String) -> Result<Vec<ScanResult>, String>
#[tauri::command]
pub async fn get_latest_scan() -> Result<Option<Vec<ScanResult>>, String>

// Plugins
#[tauri::command]
pub async fn list_plugins() -> Result<Vec<PluginMetadata>, String>

// Remote scanning
#[tauri::command]
pub async fn list_remote_hosts() -> Result<Vec<RemoteHostProfile>, String>
#[tauri::command]
pub async fn save_remote_host(profile: RemoteHostProfile) -> Result<(), String>
#[tauri::command]
pub async fn delete_remote_host(name: String) -> Result<(), String>
#[tauri::command]
pub async fn connect_remote(name: String, state: tauri::State<'_, RemoteState>) -> Result<RemoteConnectionStatus, String>
#[tauri::command]
pub async fn disconnect_remote(state: tauri::State<'_, RemoteState>) -> Result<(), String>
#[tauri::command]
pub async fn run_remote_scan(plugin_ids: Option<Vec<String>>, state: tauri::State<'_, RemoteState>) -> Result<Vec<ScanResult>, String>

// Scheduler
#[tauri::command]
pub async fn get_scheduler_config() -> Result<hardener_types::scheduler::SchedulerUiConfig, String>
#[tauri::command]
pub async fn save_scheduler_config(config: hardener_types::scheduler::SchedulerUiConfig) -> Result<String, String>
#[tauri::command]
pub async fn test_notification() -> Result<hardener_types::scheduler::TestNotificationResult, String>

// Config file picker
#[tauri::command]
pub async fn validate_config(path: String) -> Result<ConfigSummary, String>
#[tauri::command]
pub async fn pick_config_file(app: tauri::AppHandle) -> Result<Option<String>, String>
```

---

## Configuration Files

| File | Purpose |
|------|---------|
| `Cargo.toml` | Workspace definition |
| `.cargo/config.toml` | WASM rustflags (getrandom backend) |
| `.cargo/audit.toml` | Cargo audit configuration |
| `deny.toml` | Cargo deny (dependency policy) configuration |
| `release.toml` | cargo-release configuration |
| `cliff.toml` | git-cliff changelog generation |
| `.gitignore` | Git ignore rules |
| `src-tauri/tauri.conf.json` | Tauri app configuration |
| `src-tauri/build.rs` | Tauri build script |
| `crates/hardener-ui/Trunk.toml` | Trunk WASM build configuration |
| `crates/hardener-ui/index.html` | WASM app entry HTML |

---

## Systemd Units

| File | Purpose |
|------|---------|
| `systemd/linux-hardener.service` | Oneshot service for scheduled security scans |
| `systemd/linux-hardener.timer` | Timer unit triggering daily scans at 02:00 |

---

## Data Files

| File | Purpose |
|------|---------|
| `data/linux-hardener.desktop` | XDG desktop entry for the GUI application |
| `data/config.toml.example` | Commented example configuration with all 8 plugin sections |
| `data/hardener.1` | Unix man page (troff) for the `hardener` CLI |

---

## Packaging

| File | Purpose |
|------|---------|
| `packaging/PKGBUILD` | AUR (Arch Linux) package build script |
| `packaging/linux-system-hardener.spec` | RPM (Fedora/RHEL/openSUSE) spec file |
| `packaging/debian/control` | Debian package metadata and dependencies |
| `packaging/debian/rules` | Debian build instructions (debhelper) |
| `packaging/debian/changelog` | Debian changelog |
| `packaging/debian/postinst` | Post-installation script (systemd reload, permissions) |
| `packaging/debian/prerm` | Pre-removal script (stop/disable timer) |
| `packaging/debian/copyright` | Apache-2.0 licence in Debian format |

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
| `scripts/full-test-suite.sh` | Complete 123-test validation suite (26 sections) |
| `scripts/run-cross-distro-tests.sh` | Non-interactive cross-distro test orchestrator |
| `scripts/root-test-suite.sh` | 36 root-level privilege tests |
| `scripts/manual-verification-test.sh` | Interactive verification tests |
| `scripts/create-test-container.sh` | Arch Linux systemd-nspawn container |
| `scripts/create-debian-container.sh` | Debian 12 test container |
| `scripts/create-fedora-container.sh` | Fedora 41 test container |
| `scripts/create-opensuse-container.sh` | openSUSE Leap test container |
| `scripts/create-rhel-container.sh` | Rocky Linux 9 / RHEL container for cross-distro testing |
| `scripts/verify-rollback.sh` | Rollback verification tests (5 tests, 10 assertions) for nspawn containers |

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
| `docs/ARCHITECTURE.md` | Architecture overview |
| `docs/COMPREHENSIVE_AUDIT_REPORT.md` | Full project audit: 13 bugs found and fixed |
| `docs/CONFIG_DESIGN.md` | Config system security design |
| `docs/DATA_FLOW.md` | Data flow diagrams |
| `docs/DISTRIBUTION_VALIDATION.md` | Multi-distro validation results |
| `docs/FILE_MAP.md` | This file |
| `docs/GUI_CLI_PARITY_PLAN.md` | GUI-CLI feature parity plan |
| `docs/NAMING_CONVENTIONS.md` | Naming standards |
| `docs/RELEASING.md` | Versioning and release process |
| `docs/SSH_REMOTE_SCANNING.md` | SSH remote scanning user guide |
| `docs/THEME_DESIGN_GUIDE.md` | GUI theming system documentation |
| `docs/browser-automation.md` | Playwright browser automation setup and troubleshooting |
| `docs/css-architecture.md` | CSS architecture and theming implementation details |
| `docs/FRONTEND_LAYOUT_PLAN.md` | Frontend page layout and component plan |
| `docs/DOCUMENTATION_AUDIT.md` | Documentation coverage audit results |
| `docs/GUI_V031_TEST_PLAN.md` | GUI v0.3.1 Playwright test plan |
| `docs/tauri-plus-leptos-development-on-arch-linux-with-hyprland.md` | Tauri + Leptos development environment setup on Arch/Hyprland |
| `docs/claude-code-configuration.md` | Development tooling configuration reference |
| `docs/plans/2026-02-22-trait-refactor.md` | Trait refactor execution log |
| `docs/plans/2026-02-22-trait-refactor-design.md` | Trait refactor design document |
| `docs/plans/2026-02-24-severity-filter-design.md` | Severity filter feature design |
| `docs/plans/2026-02-24-severity-filter.md` | Severity filter implementation plan |
| `docs/plans/2026-02-24-remote-scanning-ui-design.md` | Remote scanning UI design document |
| `docs/plans/2026-02-24-remote-scanning-ui.md` | Remote scanning UI implementation plan |
| `docs/plans/2026-02-24-scheduler-ui-design.md` | Scheduler UI design document |
| `docs/plans/2026-02-24-scheduler-ui.md` | Scheduler UI implementation plan |
| `docs/plans/2026-02-24-config-file-picker-design.md` | Config file picker design document |
| `docs/plans/2026-02-24-config-file-picker.md` | Config file picker implementation plan |
| `docs/plans/2026-02-24-ui-polish-design.md` | UI polish pass design document |
| `docs/plans/2026-02-24-ui-polish.md` | UI polish pass implementation plan |

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

## GUI Tests (Playwright)

84 Playwright tests validate the Web UI across 5 distributions. Tests use a Tauri IPC mock to simulate backend commands without requiring the desktop app.

### Test Files

| File | Purpose |
|------|---------|
| `gui-tests/package.json` | npm dependencies (Playwright) |
| `gui-tests/playwright.config.js` | Playwright configuration (base URL, browser, timeouts) |
| `gui-tests/tauri-mock.js` | Tauri IPC mock (`window.__TAURI__`) covering all IPC commands |
| `gui-tests/spa-server.py` | SPA-aware HTTP server (port 8787, client-side routing) |
| `gui-tests/tests/helpers.js` | Shared test helpers and utilities |
| `gui-tests/tests/dashboard.spec.js` | T-DASH-01..09 (9 tests): score, scan trigger, navigation, activity |
| `gui-tests/tests/analysis.spec.js` | T-FIND-01..10, T-COMP-01..08 (18 tests): findings + compliance |
| `gui-tests/tests/hardening.spec.js` | T-CONF-01..10, T-HIST-01..06 (16 tests): configure + history |
| `gui-tests/tests/themes.spec.js` | T-THEME-01..07 (7 tests + 30 screenshots): all 6 themes |
| `gui-tests/tests/errors.spec.js` | T-ERR-01..04 (4 tests): error handling and dismiss |

### Runner Scripts

| File | Purpose |
|------|---------|
| `scripts/run-gui-tests.sh` | Host orchestrator for Web UI tests across all distros |
| `scripts/gui-test-inner.sh` | Container inner script (Xvfb + SPA server + Playwright); dynamically generates `index.html` at serve-time by stripping SRI `integrity` attributes and injecting `tauri-mock.js` into the built `dist/index.html` |
| `scripts/run-tauri-gui-tests.sh` | Host orchestrator for Tauri desktop tests |
| `scripts/tauri-gui-test-inner.sh` | Container inner script for Tauri desktop tests |

---

## Configuration Files (Implemented)

| File | Purpose |
|------|---------|
| `hardener-core/src/config.rs` | Config structs: `HardenerConfig`, `GlobalConfig`, `PluginConfig`, `PolicyException` |
| `hardener-core/src/config_loader.rs` | Config loading and merging from multiple sources |
| `hardener-common/src/types.rs` | Added `FindingPolicyException` struct |
| `hardener-cli/src/cli.rs` | Added `--config`, `--audit`, `--compliance`, `--exit-code` flags, `ScanMode` enum |

**Last Updated**: 2026-02-25
