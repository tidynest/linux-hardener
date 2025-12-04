# Linux System Hardener - File Map

**Last Updated:** 2025-12-04

This document lists all source files with their purpose and key exports.

---

## hardener-cli (CLI Binary)

| File | Purpose | Key Exports/Functions |
|------|---------|----------------------|
| `src/main.rs` | Entry point, command routing | `main()` |
| `src/cli.rs` | Clap argument definitions | `Cli`, `Command`, `DaemonAction`, `OutputFormat` |
| `src/output.rs` | Output formatting utilities | `format_findings()`, `format_json()` |
| `src/commands/mod.rs` | Command module exports | - |
| `src/commands/scan.rs` | Scan command implementation | `run()` |
| `src/commands/apply.rs` | Apply command implementation | `run()` |
| `src/commands/checkpoint.rs` | Checkpoint management | `list()`, `create()`, `show()`, `delete()` |
| `src/commands/plugins.rs` | List plugins command | `run()` |
| `src/commands/report.rs` | Compliance report generation | `run()` |
| `src/commands/report_wizard.rs` | Interactive report wizard | `run_interactive()` |
| `src/commands/daemon.rs` | Daemon management commands | `start()`, `run_once()`, `status()` |
| `src/ssh_config.rs` | SSH connection config helper | `SshConnectionConfig` |

---

## hardener-core (Plugin Framework)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/lib.rs` | Module exports, feature flags | Re-exports all public types |
| `src/plugin.rs` | Core plugin trait and types | `HardeningPlugin`, `Finding`, `ScanResult`, `ApplyResult`, `Config` |
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
    async fn apply(&self, ctx: &mut Context, config: &Config) -> Result<ApplyResult>;
    async fn rollback(&self, ctx: &mut Context, checkpoint: &Checkpoint) -> Result<()>;
    async fn validate(&self, ctx: &Context, config: &Config) -> Result<ValidationReport>;
}
```

---

## hardener-common (Shared Types)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/lib.rs` | Module exports | Re-exports |
| `src/types.rs` | Core type definitions | `PluginId`, `Severity`, `FindingCategory`, `ComplianceFramework`, `ComplianceMapping`, `FindingPolicyException` |
| `src/error.rs` | Error types | `HardeningError`, `Result<T>` |
| `src/logging.rs` | Logging setup | `init_logging()` |
| `src/file_utils.rs` | File utilities | `update_file_atomically()` |

### Key Enums (types.rs)

```rust
pub enum Severity { Info, Low, Medium, High, Critical }

pub enum FindingCategory {
    Audit, Authentication, Cryptography, FileSystem,
    Kernel, MandatoryAccessControl, Network, Services
}

pub enum ComplianceFramework {
    CIS, HIPAA, ISO27001, NIST, PCIDSS, STIG, GDPR
}
```

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
| `src/package/apt.rs` | Debian/Ubuntu | `AptPackageManager` |
| `src/package/dnf.rs` | RHEL/Fedora | `DnfPackageManager` |
| `src/package/pacman.rs` | Arch Linux | `PacmanPackageManager` |
| `src/package/zypper.rs` | openSUSE | `ZypperPackageManager` |

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

### Pending Files (Phase 3-4)

| File | Purpose | Status |
|------|---------|--------|
| `src/systemd.rs` | Systemd file generation | Pending |
| `src/notification/mod.rs` | Notifier trait | Pending |
| `src/notification/email.rs` | SMTP via lettre | Pending |
| `src/notification/webhook.rs` | HTTP POST notifications | Pending |

---

## hardener-ui (Leptos Frontend)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/lib.rs` | Main App component | `App` |
| `src/types.rs` | Frontend types | UI-specific types |
| `src/state/mod.rs` | Reactive state | `AppState` |
| `src/pages/dashboard_page.rs` | Dashboard view | `DashboardPage` |
| `src/pages/scanner_page.rs` | Scan interface | `ScannerPage` |
| `src/pages/configuration_page.rs` | Config UI | `ConfigurationPage` |
| `src/pages/compliance_page.rs` | Compliance reports | `CompliancePage`, `ReportCard` |
| `src/pages/results_page.rs` | Results view | `ResultsPage` |
| `src/pages/checkpoints_page.rs` | Checkpoint management | `CheckpointsPage` |
| `src/components/findings_grid.rs` | Findings display | `FindingsGrid` |
| `src/components/checkpoint_list.rs` | Checkpoint list | `CheckpointList` |
| `src/components/apply_results.rs` | Apply results | `ApplyResults` |
| `src/tauri_bindings.rs` | Tauri command bindings | `invoke_*` functions |
| `src/utils/mock_data.rs` | Development mocks | Mock data generators |

---

## src-tauri (Desktop Backend)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/main.rs` | Tauri app entry | `main()` |
| `src/commands.rs` | Tauri invoke handlers | `run_scan`, `run_apply`, `run_rollback`, `get_checkpoints`, `generate_compliance_report` |

### Tauri Commands

```rust
#[tauri::command]
pub fn run_scan(plugin: Option<String>) -> Result<Vec<ScanResult>, String>

#[tauri::command]
pub fn run_apply(plugins: Vec<String>) -> Result<Vec<ApplyResult>, String>

#[tauri::command]
pub fn run_rollback(checkpoint_id: String) -> Result<(), String>

#[tauri::command]
pub fn get_checkpoints() -> Result<Vec<Checkpoint>, String>

#[tauri::command]
pub fn generate_compliance_report(frameworks: Vec<String>) -> Result<Vec<ComplianceReport>, String>
```

---

## Configuration Files

| File | Purpose |
|------|---------|
| `Cargo.toml` | Workspace definition |
| `rustfmt.toml` | Rust formatting config |
| `tauri.conf.json` | Tauri app config |
| `release.toml` | cargo-release configuration |
| `cliff.toml` | git-cliff changelog generation |
| `.gitignore` | Git ignore rules |

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
| `scripts/validate_naming.py` | Naming convention validator |
| `scripts/release.sh` | Automated version bumping and release |
| `.git/hooks/pre-commit` | Pre-commit naming convention check |

---

## Documentation Files

| File | Purpose |
|------|---------|
| `README.md` | User documentation |
| `PLAN.md` | Development roadmap |
| `CHANGELOG.md` | Version history |
| `CONTRIBUTING.md` | Contribution guidelines |
| `SECURITY.md` | Security policy |
| `docs/ARCHITECTURE.md` | Architecture overview |
| `docs/DATA_FLOW.md` | Data flow diagrams |
| `docs/CONFIG_DESIGN.md` | Config system security design |
| `docs/HANDOFF.md` | Developer handoff |
| `docs/FILE_MAP.md` | This file |
| `docs/NAMING_CONVENTIONS.md` | Naming standards |
| `docs/RELEASING.md` | Versioning and release process |
| `docs/SSH_REMOTE_SCANNING.md` | SSH remote scanning user guide |
| `docs/SSH_REMOTE_PLAN.md` | SSH implementation plan (internal) |

---

## Test Files

Tests are co-located with source files using `#[cfg(test)]` modules, plus integration tests in `tests/` directories within each crate.

| Crate | Unit Tests | Integration Tests | Total |
|-------|------------|-------------------|-------|
| hardener-common | `error.rs`, `file_utils.rs`, `logging.rs` | `common_types.rs` | 30 |
| hardener-compliance | `config.rs`, `report.rs`, `output/*.rs`, `generator.rs` | `framework_tests.rs` | 46 |
| hardener-state | `audit.rs`, `hash_chain.rs`, `signing.rs`, `db.rs` | `checkpoint_system.rs` | 31 |
| hardener-distro | `adapter.rs`, `package/*.rs` | - | 15 |
| hardener-scheduler | `config.rs`, `db.rs`, `json_store.rs`, `runner.rs`, `daemon.rs` | - | 29 |
| hardener-cli | `cli.rs`, `output.rs` | - | 23 |
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
