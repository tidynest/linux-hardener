# Linux System Hardener - File Map

**Last Updated:** 2026-07-28

This document lists all source files with their purpose and key exports.

---

## hardener-types (WASM-Compatible Shared Types)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/lib.rs` | All shared type definitions | `PluginId`, `Severity`, `FindingCategory`, `ComplianceFramework`, `ComplianceMapping`, `ControlStatus`, `FindingPolicyException`, `PluginMetadata`, `ScanResult`, `Finding`, `UncheckedCheck`, `ApplyResult`, `Change`, `ChangeType`, `ValidationReport`, `ValidationIssue`, `ComplianceReport`, `ControlResult`, `ComplianceSummary`, `ConfigSummary`, `FleetHostScan`, `FleetHostStatus`, `SeverityTallies` |
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
pub enum ComplianceFramework { CIS, HIPAA, ISO27001, NIST, PCIDSS, STIG, GDPR, SOC2, NIST800171, FedRAMP }

// Scan/Apply results
pub struct ScanResult { scan_plugin_id, scan_success, scan_findings, scan_unchecked, scan_duration_us, scan_error }
pub struct ApplyResult { apply_plugin_id, apply_success, apply_changes, apply_checkpoint_id, apply_error }
pub struct Finding { finding_id, finding_title, finding_severity, ... }
pub struct UncheckedCheck { unchecked_check_id, unchecked_title, unchecked_category, unchecked_reason, unchecked_needs_privilege, unchecked_compliance }
pub fn unchecked_summary(...)  // the one roll-up line every renderer prints

// Compliance report types
pub struct ComplianceReport { report_framework, report_generated_at, report_controls, report_summary }
pub struct ControlResult { control_id, control_title, control_section, control_status, control_findings }
pub struct ComplianceSummary { summary_total_controls, summary_passing, summary_failing, ... }

// Fleet scan types
pub enum FleetHostStatus { Ok, Failed(String) }
pub struct SeverityTallies { critical, high, medium, low, info: u32 }
pub struct FleetHostScan { host_name: String, status: FleetHostStatus, tallies: SeverityTallies, scan_results: Vec<ScanResult> }
```

---

## hardener-cli (CLI Binary)

| File | Purpose | Key Exports/Functions |
|------|---------|----------------------|
| `src/main.rs` | Entry point, command routing | `main()` |
| `src/cli.rs` | Clap argument definitions | `Cli`, `Command`, `BatchAction`, `CheckpointAction`, `DaemonAction`, `HistoryAction`, `SystemdAction`, `OutputFormat` |
| `src/output.rs` | Output formatting utilities | `status()`, `info()`, `error()`, `warning()`, `scan_results()`, `scan_timings()`, `apply_results()`, `plugin_list()`, `checkpoint_list()`, `checkpoint_created()`, `checkpoint_details()`, `rollback_result()`, `validation_reports()` |
| `src/commands/mod.rs` | Command module exports | - |
| `src/commands/scan.rs` | Scan command implementation | `run()`, `persist_scan_session()` |
| `src/commands/plugin_filter.rs` | Shared `--plugin` filter resolution, so `scan`, `apply` and `batch` agree on which names are valid and what order they run in. A filter entry naming no plugin is refused rather than dropped, which is what let `apply -p services` harden nothing and exit 0 | `matches()`, `validate()`, `expand()` |
| `src/commands/apply.rs` | Apply command implementation | `run()` |
| `src/commands/checkpoint.rs` | Checkpoint management | `list()`, `create()`, `show()`, `delete()`, `rollback()` |
| `src/commands/plugins.rs` | List plugins command | `run()` |
| `src/commands/report.rs` | Compliance report generation | `run()` |
| `src/commands/report_wizard.rs` | Interactive report wizard | `run()` |
| `src/commands/daemon.rs` | Daemon management commands | `start()`, `run_once()`, `status()` |
| `src/commands/systemd.rs` | Systemd unit file commands | `generate()`, `install()`, `uninstall()`, `status()` |
| `src/commands/history.rs` | Scan history commands | `list()`, `show()`, `export()`, `trends()`, `regressions()` |
| `src/commands/batch.rs` | Multi-host concurrent scan/report/apply/rollback commands | `run()`, `run_report()`, `run_apply()`, `run_rollback()`, `BatchOptions`, `BatchReportOptions`, `BatchApplyOptions`, `BatchRollbackOptions`, `resolve_and_scan()`, `run_on_all()` |
| `src/ssh_config.rs` | SSH connection config helper | `SshConnectionConfig` |
| `src/commands/state.rs` | Shared state initialisation (DB + signing key paths) | `get_checkpoint_manager()`, `get_audit_logger()`, `effective_user()` |
| `src/commands/privilege.rs` | Shared privilege probe for mutating commands; asks the executor session (`id -u` / `sudo -n`) so `--ssh` targets gate correctly | `is_privileged()` |

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
| `src/executor/mod.rs` | Re-exports executor abstraction from `hardener-common` | `SystemExecutor`, `CommandOutput`, `FileMetadata`, `MockExecutor` |
| `src/executor/local.rs` | Local file/command operations | `LocalExecutor` |
| `src/executor/ssh.rs` | SSH remote operations | `SshExecutor`, `SshConfig` |
| `src/inventory.rs` | Shared host-inventory persistence | `HostsConfig`, `load_hosts()`, `save_hosts()`, `default_hosts_path()` |

### Key Trait (plugin.rs)

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
| `src/executor/mod.rs` | Executor abstraction (trait + types) | `SystemExecutor`, `CommandOutput`, `FileMetadata` |
| `src/executor/mock.rs` | Virtual filesystem for unit testing | `MockExecutor` |
| `src/vendor_config.rs` | Resolves configuration a distribution layers across `/etc` and `/usr/etc`. `/usr/etc` is consulted only on absence positively confirmed at `/etc`, because an `/etc` file that exists but cannot be read is still the file the system obeys, and answering with the vendor copy would report a configuration that is not in force | `ConfigLayer`, `LayeredRead`, `read_layered()`, `vendor_path_for()` |

**Note**: Core types (Severity, FindingCategory, etc.) are now defined in `hardener-types` and re-exported here for backwards compatibility. The executor abstraction (`SystemExecutor`, `CommandOutput`, `FileMetadata`, `MockExecutor`) relocated here from `hardener-core` and is re-exported from that crate for source compatibility.

---

## hardener-plugins (Security Plugins)

| File | Purpose | Plugin Struct |
|------|---------|---------------|
| `src/lib.rs` | Module exports, helpers | `create_checkpoint_for_apply()`, `create_checkpoint_metadata_only_for_apply()`, `checkpoint_change()` (shared `ChangeType::Checkpoint` bookkeeping change), `rollback_files_from_checkpoint()`, `create_plugin_registry()`, `compliance_coverage()` |
| `src/macros.rs` | Plugin definition macro | `define_plugin!` |
| `src/scan_outcome.rs` | Turns per-plugin scan results into the flat lists a compliance report consumes. A plugin that contributed no evidence gets an entry carrying its whole declared coverage, so its controls route to Manual Review instead of passing on the silence its own absence caused; a run that could not enumerate its plugins at all gets one carrying the engine's whole coverage, for the same reason at the only scope left. Shared by the CLI and the desktop, beside the coverage table it depends on | `Unassessed`, `flatten_scans()`, `flatten_persisted_scans()`, `failed_scan()`, `unassessed_check()` |

### Individual Plugins

| Plugin File | Category | Key Checks |
|-------------|----------|------------|
| `src/ssh/mod.rs` | Network | PermitRootLogin, PasswordAuthentication, MaxAuthTries, X11Forwarding, Protocol, ClientAliveInterval |
| `src/ssh/dropin.rs` | Network | Writes SSH hardening to `/etc/ssh/sshd_config.d/00-hardener.conf`, which sorts before the fragments distributions ship, so sshd takes this file's values first. Precedence is verified after writing by re-resolving, never assumed from the filename, and an empty directive set removes the file rather than leaving an empty one | `DROPIN_PATH`, `Directive`, `render()`, `write_dropin()` |
| `src/ssh/include.rs` | Network | Resolves `Include` directives in sshd's own order, so scan reports the value sshd will actually use and names the file supplying it. sshd takes the **first** value it obtains and distributions put the Include above everything this tool writes, so a drop-in silently won while the tool reported its own write |
| `src/kernel/mod.rs` | Kernel | ASLR, kptr_restrict, dmesg_restrict, ptrace_scope, suid_dumpable, rp_filter, tcp_syncookies |
| `src/firewall/mod.rs` | Network | Firewall enabled, baseline rules |
| `src/firewall/nftables.rs` | Network | nftables backend |
| `src/firewall/firewalld.rs` | Network | firewalld backend |
| `src/firewall/ufw.rs` | Network | UFW backend |
| `src/pam/mod.rs` | Auth | Password complexity, aging, lockout |
| `src/pam/login_defs.rs` | Auth | Carries a `/usr/etc` configuration file into `/etc` before the managed directives are edited into it, with the vendor file's own permissions rather than the temporary file's | `mode_for_copy_of()` |
| `src/pam/layer_drift.rs` | Auth | Reports the keys an `/etc` file hides from its `/usr/etc` counterpart, for every layered file the plugin reads rather than for `login.defs` alone | `LAYERED_CONFS`, `masked_keys()`, `masked_keys_finding()` |
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
const KERNEL_PARAMS: &[(&str, &str, &str, Severity)] = &[
    ("kernel.randomize_va_space", "2", "Enable ASLR", Severity::High),
    ("kernel.kptr_restrict", "2", "Hide kernel pointers", Severity::Medium),
    // ... 18 total
];
```

---

## hardener-state (State Management)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/lib.rs` | Module exports | Re-exports |
| `src/checkpoint.rs` | Checkpoint types | `Checkpoint`, `CheckpointId`, `FileState`; re-exports `RollbackResult`, `FileRestoreResult`, `FileRestoreAction` from `hardener-types` |
| `src/manager.rs` | Checkpoint operations | `CheckpointManager`, `create_checkpoint_metadata_only()`, `capture_directory_entry()`, `latest_named_for_host()` |
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
| `src/profiles.rs` | Report-time profile ID translation (sourced RHEL 10 STIG V1R1 / CIS v1.0.1 tables) | `translate()`, `translate_all()`, `profile_label()`, `resolve_profile()` |
| `src/config.rs` | Report configuration | `ReportConfig` |
| `src/frameworks/mod.rs` | Framework routing and curated catalogue aggregation | `curated_controls()` |
| `src/frameworks/cis.rs` | CIS Benchmark curated catalogue | `get_controls()` (CIS control definitions) |
| `src/frameworks/iso27001.rs` | ISO/IEC 27001:2022 Annex A curated catalogue | `get_controls()` (93 controls across 4 themes: Organizational, People, Physical, Technological) |
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
| `styles.css` | Base styles plus the 7-theme system (`[data-theme="..."]` overrides, incl. light Daywatch and WCAG AAA High Contrast) | CSS Variables, utility classes (.truncate, .sr-only, .skip-link), tabs, sidebar, score gauge, buttons, tables, forms |
| `src/lib.rs` | Main App component and WASM entry point; defines seven routes (Dashboard, Analysis, Hardening, Hosts at `/fleet`, Fleet Apply, Scheduler, Settings) plus a `/remote` -> `/fleet` redirect, mounts the grouped `Sidebar`, and owns the sole theme apply/persist `Effect` | `App`, `#[wasm_bindgen(start)] main()` |
| `src/types.rs` | Re-exports from hardener-types | `pub use hardener_types::*` (ApplyResult, Change, ChangeType, ComplianceFramework, ComplianceMapping, ComplianceReport, ComplianceSummary, ConfigSummary, ControlResult, ControlStatus, FileRestoreAction, FileRestoreResult, Finding, FindingCategory, FindingPolicyException, PluginId, PluginMetadata, RollbackResult, ScanResult, Severity, UncheckedCheck, ValidationIssue, ValidationReport), scheduler re-exports (SchedulerUiConfig, NotificationUiConfig, EmailUiConfig, WebhookUiConfig, TestNotificationResult), `CheckpointInfo`, `ScanSessionInfo`, `CheckpointDetail`, `CheckpointFileInfo` |
| `src/state/mod.rs` | Reactive state | `AppState` |
| `src/tauri_bindings.rs` | Tauri command bindings | `tauri_available`, `invoke_scan`, `invoke_deep_scan`, `invoke_apply`, `invoke_apply_dry_run`, `invoke_generate_report`, `invoke_export_report`, `invoke_get_latest_scan`, `invoke_get_checkpoints`, `invoke_create_checkpoint`, `invoke_delete_checkpoint`, `invoke_get_scan_history`, `invoke_get_scan_session`, `invoke_get_checkpoint_detail`, `invoke_rollback`, `invoke_list_remote_hosts`, `invoke_save_remote_host`, `invoke_delete_remote_host`, `invoke_connect_remote`, `invoke_disconnect_remote`, `invoke_remote_scan`, `invoke_fleet_scan`, `invoke_fleet_apply`, `invoke_fleet_rollback`, `invoke_get_host_history`, `invoke_list_plugins`, `invoke_get_scheduler_config`, `invoke_save_scheduler_config`, `invoke_test_notification`, `invoke_validate_config`, `invoke_pick_config_file` |
| `src/keyboard.rs` | Global keyboard event handler | Ctrl+1-5 page nav (Dashboard/Analysis/Hardening/Hosts/Scheduler; Ctrl+4 reaches Hosts via the retained `/remote` redirect - Fleet Apply and Settings have no shortcut yet), Ctrl+Shift+S scan from anywhere, Alt+T theme cycle, Escape close, F11 fullscreen |
| `src/navigation.rs` | Navigation signal helpers | Page routing helpers for keyboard and UI nav |
| `src/utils/mod.rs` | Utils module exports and preview/apply helpers | `annotate_preview()`, `PreviewDecision`, `apply_change_summary()`, `is_auth_cancelled()`, `parse_rate_limit_wait_secs()`; `mock_data` mod, `theme` mod |
| `src/utils/mock_data.rs` | Development mocks | Mock data generators |
| `src/utils/theme.rs` | Shared theme metadata plus the single apply/persist side effects; the only writer of `<html data-theme>` and the `theme` localStorage key | `THEMES` (7 themes), `apply_theme()`, `get_stored_theme()`, `store_theme()` |
| `src/pages/mod.rs` | Pages module exports | `DashboardPage`, `AnalysisPage`, `HardeningPage`, `HostsPage`, `SchedulerPage`, `SettingsPage`, `FleetApplyPage` |
| `src/components/mod.rs` | Components module exports | All component re-exports, `Card`, `CardVariant`, `HeadingLevel` |

### Pages (7-page architecture)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/pages/dashboard_page.rs` | Dashboard with security score and quick actions | `DashboardPage` |
| `src/pages/analysis_page.rs` | Tabbed interface for findings and compliance | `AnalysisPage` |
| `src/pages/hardening_page.rs` | Sectioned interface for configuration and history | `HardeningPage` |
| `src/pages/hosts_page.rs` | Hosts page: the merged inventory - bulk read-only scan across selected hosts plus the single-host connect session, both surfaced through one expandable row per host (replaces the former Remote and Fleet pages) | `HostsPage` |
| `src/pages/fleet_apply_page.rs` | Mutating multi-host **Fleet Apply** page: apply/roll back across saved hosts by shelling out to the audited `batch apply/rollback` CLI; mode toggle, host+plugin select, mandatory dry-run + confirm modal | `FleetApplyPage` |
| `src/pages/scheduler_page.rs` | Scheduler and notification configuration | `SchedulerPage` |
| `src/pages/settings_page.rs` | Settings page: Appearance theme swatch grid plus a static About block | `SettingsPage` |

### Components

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/components/security_score.rs` | Main security score gauge with compliance-based calculation; also renders the deep-scan "Run with sudo" offer inline when unprivileged results contain unverifiable checks (replaces the old UncheckedBanner) | `SecurityScore`, `calculate_all_scores()`, `FrameworkScore` |
| `src/components/recent_activity.rs` | Recent scan/apply activity summary | `RecentActivity` |
| `src/components/sidebar.rs` | Grouped left sidebar navigation with a collapsible icon rail; replaces the old flat top nav bar (groups Local and Fleet, plus a pinned Settings area) | `Sidebar` |
| `src/components/tabs.rs` | Reusable tab bar and panel with WAI-ARIA | `TabBar`, `TabDef` (id, label, badge), `TabPanel` (id, index, active_tab) |
| `src/components/findings_tab.rs` | Findings tab wrapper for Analysis page | `FindingsTab` |
| `src/components/compliance_tab.rs` | Compliance framework selection and reports with status feedback | `ComplianceTab` |
| `src/components/configure_section.rs` | Profile selection and plugin toggles | `ConfigureSection` |
| `src/components/segmented_control.rs` | Reusable WAI-ARIA segmented control (roving-tabindex radiogroup); shared by the Fleet Apply mode toggle and the Hardening protection-level control | `SegmentedControl` |
| `src/components/history_section.rs` | Apply results and checkpoint management with refresh button | `HistorySection` |
| `src/components/modal.rs` | Shared modal shell used by every dialog: backdrop, Escape and backdrop-click dismissal, dialog ARIA, and focus-on-mount. Swallows Escape so dismissing a dialog cannot also advance the global `keyboard.rs` priority chain and discard a pending apply review | `Modal` |
| `src/components/rollback_modal.rs` | Rollback confirmation modal for the Hardening History timeline (confirm, restoring, and per-file result stages) | `RollbackModal` |
| `src/components/card.rs` | Reusable card container component | `Card`, `CardVariant`, `HeadingLevel` |
| `src/components/theme_toggle.rs` | Theme quick-switch `<select>` in the sidebar, bound to the shared `AppState.theme` signal (presentational only; the App `Effect` applies/persists it) | `ThemeToggle` |
| `src/components/theme_picker.rs` | Settings page theme swatch grid: WAI-ARIA radiogroup of live-coloured preview cards, one per `THEMES` entry | `ThemePicker` |
| `src/components/status_icons.rs` | Shared status/flag inline SVG icon set (applied/failed/manual/skipped, help affordance, diff arrow) | `IconCheck`, `IconInfo`, `IconX`, `IconWrench`, `IconMinus`, `IconArrowRight` |
| `src/components/icons.rs` | Inline SVG icon set for the sidebar navigation and brand mark | `IconDashboard`, `IconAnalysis`, `IconHardening`, `IconFleet`, `IconFleetApply`, `IconScheduler`, `IconSettings`, `IconChevronCollapse`, `IconShieldMark` |
| `src/components/host_form.rs` | Add/edit remote host profile form | `HostForm` |
| `src/components/host_panel.rs` | Expanded per-host panel: connection strip, collapsible compliance detail, collapsible findings, and the per-host scan-history timeline; rendered when a `HostRow` is expanded | `HostPanel`, `HostConnState` |
| `src/components/host_row.rs` | One Hosts-page inventory row (name, target, connection dot, severity tallies, framework score strip) that expands in place into a `HostPanel` | `HostRow` |
| `src/components/scan_history_tab.rs` | Scan history timeline for Analysis page | `ScanHistoryTab` |
| `src/components/schedule_section.rs` | Cron schedule configuration form | `ScheduleSection` |
| `src/components/notification_section.rs` | Email and webhook notification config | `NotificationSection` |
| `src/components/config_file_card.rs` | Config file picker card component (text input, browse, validation) | `ConfigFileCard` |
| `src/components/clipboard.rs` | Copy-to-clipboard button with async Clipboard API | `CopyButton` |
| `src/components/confirm_delete.rs` | Inline delete confirmation component | `ConfirmDeleteButton` |
| `src/components/form_helpers.rs` | Shared JsCast event extraction helpers | `input_value()`, `checkbox_checked()`, `select_value()` |
| `src/components/fleet_outcome_row.rs` | One host's Fleet Apply/rollback outcome row, rendered from a pre-computed `OutcomeView` (`utils::fleet_apply_cells` / `fleet_rollback_cells`) | `FleetOutcomeRow` |
| `src/components/adhoc_host_input.rs` | Ad-hoc SSH target entry for fleet scans (host:user@addr rows, add/remove) | `AdhocHostInput` |

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
| `themes/high-contrast.css` | WCAG AAA maximum-contrast accessibility theme |

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
pub async fn invoke_deep_scan(plugin_ids: Vec<String>, config_path: Option<String>) -> Result<Vec<ScanResult>, String>;  // pkexec, privileged
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

// Fleet scanning (read-only, multiple inventory hosts)
pub async fn invoke_fleet_scan(host_names: Vec<String>, plugin_ids: Vec<String>) -> Result<Vec<FleetHostScan>, String>;

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
| `src/commands.rs` | Tauri invoke handlers | `run_scan`, `run_deep_scan` (pkexec-elevated sibling of run_scan), `run_apply`, `run_apply_dry_run`, `run_rollback`, `get_checkpoints`, `create_checkpoint`, `delete_checkpoint`, `get_checkpoint_detail`, `generate_compliance_report`, `export_compliance_report`, `get_scan_history`, `get_scan_session`, `get_host_history`, `list_plugins`, `get_latest_scan`, `list_remote_hosts`, `save_remote_host`, `delete_remote_host`, `connect_remote`, `disconnect_remote`, `run_remote_scan`, `scan_with_executor` (shared scan helper), `scan_fleet` (bounded-concurrent orchestrator), `run_fleet_scan`/`run_fleet_apply`/`run_fleet_rollback` (#[tauri::command]), `run_fleet_mutation`/`build_batch_args`/`parse_outcomes` (fleet-mutation helpers), `get_scheduler_config`, `save_scheduler_config`, `test_notification`, `validate_config`, `pick_config_file` |
| `src/validation.rs` | IPC input validation layer | `validate_ipc_string()`, `validate_plugin_ids()`, `validate_checkpoint_id()`, `validate_checkpoint_name()`, `validate_privileged_config_path()`, `validate_user_config_path()`, `validate_output_path()`, `validate_ssh_key_path()` |
| `src/acl_tests.rs` | Tests for per-command Tauri ACL scoping (SAM-039) | `#[cfg(test)]` ACL coverage |

### Tauri Commands
```rust
pub async fn connect_remote(name: String,
    state: tauri::State<'_, RemoteState>,) -> Result<RemoteConnectionStatus, String>
pub async fn create_checkpoint(name: String) -> Result<String, String>
pub async fn delete_checkpoint(checkpoint_id: String) -> Result<bool, String>
pub async fn delete_remote_host(name: String) -> Result<(), String>
pub async fn disconnect_remote(state: tauri::State<'_, RemoteState>) -> Result<(), String>
pub async fn export_compliance_report(frameworks: Vec<String>,
    format: String,
    output_path: Option<String>,) -> Result<String, String>
pub async fn generate_compliance_report(frameworks: Vec<String>,) -> Result<Vec<ComplianceReport>, String>
pub async fn get_checkpoint_detail(checkpoint_id: String) -> Result<CheckpointDetail, String>
pub async fn get_checkpoints() -> Result<Vec<CheckpointInfo>, String>
pub async fn get_host_history(host: String,
    limit: Option<u32>,) -> Result<Vec<HostSessionInfo>, String>
pub async fn get_latest_scan() -> Result<Option<Vec<ScanResult>>, String>
pub async fn get_scan_history(limit: Option<i32>) -> Result<Vec<ScanSessionInfo>, String>
pub async fn get_scan_session(session_id: String) -> Result<Vec<ScanResult>, String>
pub async fn get_scheduler_config() -> Result<hardener_types::scheduler::SchedulerUiConfig, String>
pub async fn list_plugins() -> Result<Vec<PluginMetadata>, String>
pub async fn list_remote_hosts() -> Result<Vec<RemoteHostProfile>, String>
pub async fn pick_config_file(app: tauri::AppHandle) -> Result<Option<String>, String>
pub async fn run_apply(plugin_ids: Vec<String>,
    config_path: Option<String>,) -> Result<Vec<ApplyResult>, String>
pub async fn run_apply_dry_run(plugin_ids: Vec<String>,
    config_path: Option<String>,) -> Result<Vec<ValidationReport>, String>
pub async fn run_deep_scan(plugin_ids: Option<Vec<String>>,
    config_path: Option<String>,) -> Result<Vec<ScanResult>, String>
pub async fn run_fleet_apply(hosts: Vec<String>,
    adhoc: Option<Vec<String>>,
    plugins: Vec<String>,
    execute: bool,) -> Result<Vec<ApplyOutcome>, String>
pub async fn run_fleet_rollback(hosts: Vec<String>,
    adhoc: Option<Vec<String>>,
    plugins: Vec<String>,
    execute: bool,) -> Result<Vec<RollbackOutcome>, String>
pub async fn run_fleet_scan(host_names: Vec<String>,
    adhoc: Option<Vec<String>>,
    plugin_ids: Option<Vec<String>>,
    app: tauri::AppHandle,) -> Result<Vec<FleetHostScan>, String>
pub async fn run_remote_scan(plugin_ids: Option<Vec<String>>,
    state: tauri::State<'_, RemoteState>,) -> Result<Vec<ScanResult>, String>
pub async fn run_rollback(checkpoint_id: String,
    config_path: Option<String>,) -> Result<RollbackResult, String>
pub async fn run_scan(plugin_ids: Option<Vec<String>>,
    config_path: Option<String>,) -> Result<Vec<ScanResult>, String>
pub async fn save_remote_host(profile: RemoteHostProfile) -> Result<(), String>
pub async fn save_scheduler_config(config: hardener_types::scheduler::SchedulerUiConfig,) -> Result<String, String>
pub async fn test_notification() -> Result<hardener_types::scheduler::TestNotificationResult, String>
pub async fn validate_config(path: String) -> Result<ConfigSummary, String>
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
| `packaging/systemd/linux-hardener.service` | Oneshot service for scheduled security scans |
| `packaging/systemd/linux-hardener.timer` | Timer unit triggering daily scans at 02:00 |

---

## Packaging Assets

| File | Purpose |
|------|---------|
| `packaging/assets/linux-hardener.desktop` | XDG desktop entry for the GUI application |
| `packaging/assets/config.toml.example` | Commented example configuration with all 8 plugin sections |
| `packaging/assets/hardener.1` | Unix man page (troff) for the `hardener` CLI |
| `packaging/assets/com.tidynest.linux-hardener.policy` | Polkit policy for privileged desktop operations |

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
| `scripts/lib/common.sh` | Shared colours, box-banner helper, `resolve_target_dir`, and the distro/container name tables sourced by the test runners and container tooling |
| `scripts/lib/parallel.sh` | Shared bounded-concurrency job pool for the `--parallel` cross-distro and Web UI GUI test runners |
| `scripts/validate/validate_naming.py` | Naming convention validator |
| `scripts/validate/validate_all.py` | Master validation orchestrator |
| `scripts/validate/validate_cli_docs.py` | CLI command documentation validator |
| `scripts/validate/validate_compliance_docs.py` | Compliance framework documentation validator |
| `scripts/validate/validate_file_map.py` | file-map.md accuracy validator |
| `scripts/validate/validate_last_updated.py` | Last Updated timestamp validator |
| `scripts/validate/validate_plugin_docs.py` | Plugin documentation validator |
| `scripts/validate/validate_tauri_docs.py` | Tauri integration documentation validator |
| `scripts/validate/update_all_docs.py` | Batch documentation updater |
| `scripts/release/release.sh` | Automated version bumping and release |
| `scripts/dev/tauri-dev.sh` | Tauri development launcher |
| `scripts/test/full-test-suite.sh` | Complete 127-test validation suite (26 sections) |
| `scripts/test/differential-suite.sh` | Differential harness: applies hardening, then asks `sshd -T` and `chage -l` what the system enforces and compares that against `scan` (`--self-test` runs anywhere) |
| `scripts/test/run-cross-distro-tests.sh` | Non-interactive cross-distro test orchestrator (`--differential` swaps in the differential suite) |
| `scripts/test/root-test-suite.sh` | 36 root-level privilege tests |
| `scripts/test/manual-verification-test.sh` | Interactive verification tests |
| `scripts/containers/create-container.sh` | systemd-nspawn test containers for all five distros (`arch`, `debian`, `fedora`, `rhel`, `opensuse`) |
| `scripts/test/verify-rollback.sh` | Rollback verification tests (5 tests, 10 assertions) for nspawn containers |

---

## Documentation Files

Root files follow GitHub convention; everything else lives under `docs/` in
purpose-named directories.

| File | Purpose |
|------|---------|
| `README.md` | User documentation |
| `CHANGELOG.md` | Version history |
| `CONTRIBUTING.md` | Contribution guidelines |
| `SECURITY.md` | Security policy |
| `LICENSE` | Apache-2.0 licence |
| `docs/README.md` | Documentation index (map of everything under `docs/`) |
| `docs/ROADMAP.md` | Development roadmap |
| `docs/NEXT.md` | Session handoff and current state |

### End-user guide (`docs/guide/`)

| File | Purpose |
|------|---------|
| `docs/guide/getting-started.md` | First scan to first compliance report, task by task |
| `docs/guide/installation.md` | Installation guide for all supported distros (incl. Docker) |
| `docs/guide/troubleshooting.md` | Symptom-organised fixes (GUI launch, polkit, timer, partial scans) |
| `docs/guide/ssh-remote-scanning.md` | SSH remote scanning user guide |
| `docs/guide/desktop-environment-compatibility.md` | Polkit agent matrix per desktop environment |

### Reference (`docs/reference/`)

| File | Purpose |
|------|---------|
| `docs/reference/cli.md` | CLI command reference |
| `docs/reference/configuration.md` | Configuration reference (config.toml, scheduler, hosts.toml) |
| `docs/reference/naming-conventions.md` | Naming standards |
| `docs/reference/file-map.md` | This file |
| `docs/reference/data-flow.md` | Data flow diagrams |
| `docs/reference/distribution-validation.md` | Multi-distro validation results |

### Architecture (`docs/architecture/`)

| File | Purpose |
|------|---------|
| `docs/architecture/architecture.md` | Architecture overview |

### Contributing (`docs/contributing/`)

| File | Purpose |
|------|---------|
| `docs/contributing/building.md` | Build commands and workflow |
| `docs/contributing/testing.md` | Test commands and container suites |
| `docs/contributing/plugin-authoring.md` | How to write a hardening plugin |
| `docs/contributing/documentation.md` | Documentation validation and update commands |
| `docs/contributing/releasing.md` | Versioning and release process |

### Design (`docs/design/`)

| File | Purpose |
|------|---------|
| `docs/design/theming.md` | GUI theming system documentation |

### Plans and archives

| Location | Purpose |
|----------|---------|
| `docs/plans/` | Active plans (currently the docs-and-repo reorganisation plan) |
| `docs/plans/archive/` | Completed or superseded plans and design docs |
| `docs/security/external-audit-scope.md` | External audit scope (forward-looking) |
| `docs/security/archive/2026-02-25-internal-audit/` | 2026-02-25 internal audit record (report, tracker, threat model, domain notes) |
| `docs/archive/` | Historical one-off docs (frontend layout plan, GUI test plans, environment setup notes) |
| `docs/assets/` | Logo and badge artwork |

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
| hardener-cli | `cli.rs`, `output.rs`, `history.rs` | `batch_ssh_integration.rs` (live-sshd, `#[ignore]`) | 31 |
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

## GUI Tests (Playwright + Desktop)

113 Playwright tests validate the Web UI across 5 distributions. 95 desktop tests validate the Tauri app via Hyprland keyboard/screenshot automation. 21 Node.js tests validate desktop UX features via Playwright.

### Test Files

| File | Purpose |
|------|---------|
| `gui-tests/package.json` | npm dependencies (Playwright) |
| `gui-tests/playwright.config.js` | Playwright configuration (base URL, browser, timeouts) |
| `gui-tests/tauri-mock.js` | Tauri IPC mock (`window.__TAURI__`) covering all IPC commands |
| `gui-tests/spa-server.py` | SPA-aware HTTP server (port 8787, client-side routing) |
| `gui-tests/run-tests.mjs` | Node.js Playwright test orchestrator (21 tests: keyboard nav, themes, ARIA, clipboard, TabBar) |
| `scripts/test/gui/tauri-functional-test.sh` | Hyprland-based functional tests (46 tests: scan, apply, checkpoints, scheduler, remote, themes) |
| `scripts/test/gui/tauri-ux-test.sh` | Hyprland-based UX tests (49 tests: keyboard nav, tab bars, detail panels, fullscreen, skip link) |
| `gui-tests/debug-tabs.mjs` | Tab system debugging helper |
| `gui-tests/tests/helpers.js` | Shared test helpers and utilities |
| `gui-tests/tests/dashboard.spec.js` | T-DASH-01..09 (9 tests): score, scan trigger, navigation, activity |
| `gui-tests/tests/analysis.spec.js` | T-FIND-01..10, T-COMP-01..08 (18 tests): findings + compliance |
| `gui-tests/tests/hardening.spec.js` | T-CONF-01..10, T-HIST-01..06 (16 tests): configure + history |
| `gui-tests/tests/themes.spec.js` | T-THEME-01..07 (7 tests + 30 screenshots): 6 of the 7 themes (default/Midnight Teal, fortress, sentinel, command, guardian, daywatch; High Contrast has no coverage yet) |
| `gui-tests/tests/errors.spec.js` | T-ERR-01..04 (4 tests): error handling and dismiss |

### Runner Scripts

| File | Purpose |
|------|---------|
| `scripts/test/gui/run-gui-tests.sh` | Host orchestrator for Web UI tests across all distros |
| `scripts/test/gui/gui-test-inner.sh` | Container inner script (Xvfb + SPA server + Playwright); dynamically generates `index.html` at serve-time by stripping SRI `integrity` attributes and injecting `tauri-mock.js` into the built `dist/index.html` |
| `scripts/test/gui/run-tauri-gui-tests.sh` | Host orchestrator for Tauri desktop tests |
| `scripts/test/gui/tauri-gui-test-inner.sh` | Container inner script for Tauri desktop tests |

---

## Configuration Files (Implemented)

| File | Purpose |
|------|---------|
| `hardener-core/src/config.rs` | Config structs: `HardenerConfig`, `GlobalConfig`, `PluginConfig`, `PolicyException` |
| `hardener-core/src/config_loader.rs` | Config loading and merging from multiple sources |
| `hardener-common/src/types.rs` | Added `FindingPolicyException` struct |
| `hardener-cli/src/cli.rs` | Added `--config`, `--audit`, `--exit-code` flags, `ScanMode` enum |

**Last Updated**: 2026-07-27
