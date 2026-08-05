# Linux System Hardener - File Map

**Last Updated**: 2026-08-04

This document lists all source files with their purpose and key exports.

---

## hardener-types (WASM-Compatible Shared Types)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/lib.rs` | All shared type definitions | `PluginId`, `Severity`, `FindingCategory`, `ComplianceFramework`, `ComplianceMapping`, `ControlStatus`, `FindingPolicyException`, `PluginMetadata`, `ScanResult`, `Finding`, `UncheckedCheck`, `ApplyResult`, `Change`, `ChangeType`, `ValidationReport`, `ValidationIssue`, `ComplianceReport`, `ControlResult`, `ComplianceSummary`, `ConfigSummary`, `FleetHostScan`, `FleetHostStatus`, `SeverityTallies` |
| `src/config_picker.rs` | Config file picker types | `ConfigSummary`, WASM-safe validation results for config file picker |
| `src/remote.rs` | Remote SSH scanning types | `RemoteHostProfile`, `HostsConfig`, `RemoteConnectionStatus`, `RemoteConnectionInfo` |
| `src/scheduler.rs` | Scheduler UI types | `SchedulerUiConfig`, `NotificationUiConfig`, `EmailUiConfig`, `WebhookUiConfig` (converted to the on-disk endpoint list by the private `WebhookWire`), `TestNotificationResult` |
| `src/tests.rs` | Unit tests for the crate root, seven modules split out of `lib.rs` | Test-only; a child of the crate root, so it still reaches private items |
| `src/remote/tests.rs` | Unit tests for `src/remote.rs` | Test-only; `super` resolves to `crate::remote`, so its imports carried across unchanged |
| `src/scheduler/tests.rs` | Unit tests for `src/scheduler.rs` | Test-only; `super` resolves to `crate::scheduler`, so the private webhook wire types stay reachable. Uses `toml` as a dev-dependency, because the webhook config's subject is the shape it takes in a TOML file |

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
pub struct UncheckedCheck { unchecked_check_id, unchecked_title, unchecked_category, unchecked_reason, unchecked_blocker, unchecked_compliance }
pub enum UncheckedBlocker { Privilege, Environment, Unknown }
pub fn unchecked_summary(...)  // the one roll-up line every CLI renderer prints
pub struct UncheckedTally { total, needing_privilege }  // and privilege_would_help()

// Compliance report types
pub struct ComplianceReport { report_framework, report_profile, report_generated_at, report_controls, report_summary }
pub struct ControlResult { control_id, control_title, control_section, control_status, control_findings }
pub struct ComplianceSummary { summary_total_controls, summary_passing, summary_failing, ... }

// Fleet scan types
pub enum FleetHostStatus { Ok, Failed(String) }
pub struct SeverityTallies { critical, high, medium, low, info: u32 }
pub struct FleetHostScan { host_name: String, status: FleetHostStatus, tallies: SeverityTallies, scan_results: Vec<ScanResult>, compliance: Vec<FleetFrameworkPosture> }
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
| `src/commands/report_wizard.rs` | Interactive report wizard | `run()`. Every line it prints goes to stderr, where `dialoguer` puts its prompts; the single `writeln!` to stdout is the report body |
| `src/commands/daemon.rs` | Daemon management commands | `start()`, `run_once()`, `status()` |
| `src/commands/systemd.rs` | Systemd unit file commands | `generate()`, `install()`, `uninstall()`, `status()` |
| `src/commands/history.rs` | Scan history commands | `list()`, `show()`, `export()`, `trends()`, `regressions()` |
| `src/commands/batch.rs` | Multi-host concurrent scan/report/apply/rollback commands | `run()`, `run_report()`, `run_apply()`, `run_rollback()`, `BatchOptions`, `BatchReportOptions`, `BatchApplyOptions`, `BatchRollbackOptions`, `resolve_and_scan()`, `run_on_all()` |
| `src/ssh_config.rs` | SSH connection config helper | `SshConnectionConfig` |
| `src/commands/state.rs` | Shared state initialisation (DB + signing key paths) | `get_checkpoint_manager()`, `get_audit_logger()`, `effective_user()` |
| `src/commands/privilege.rs` | Shared privilege probe for mutating commands; asks the executor session (`id -u` / `sudo -n`) so `--ssh` targets gate correctly | `is_privileged()` |
| `src/cli/tests.rs` | Unit tests for `src/cli.rs`, 39 tests of argument parsing | Test-only; `super` resolves to `crate::cli`, so its imports carried across unchanged |
| `src/output/tests.rs` | Unit tests for `src/output.rs`, 21 tests of the renderers | Test-only; `super` resolves to `crate::output`, so its imports carried across unchanged |
| `src/ssh_config/tests.rs` | Unit tests for `src/ssh_config.rs` | Test-only; `super` resolves to `crate::ssh_config`, so its imports carried across unchanged |
| `src/commands/scan/tests.rs` | Unit tests for `src/commands/scan.rs` | Test-only; `super` resolves to `crate::commands::scan`, so its imports carried across unchanged |
| `src/commands/plugin_filter/tests.rs` | Unit tests for `src/commands/plugin_filter.rs` | Test-only; `super` resolves to `crate::commands::plugin_filter`, so its imports carried across unchanged |
| `src/commands/apply/tests.rs` | Unit tests for `src/commands/apply.rs` | Test-only; `super` resolves to `crate::commands::apply`, so its imports carried across unchanged |
| `src/commands/report/tests.rs` | Unit tests for `src/commands/report.rs` | Test-only; `super` resolves to `crate::commands::report`, so its imports carried across unchanged |
| `src/commands/systemd/tests.rs` | Unit tests for `src/commands/systemd.rs` | Test-only; `super` resolves to `crate::commands::systemd`. The four verbs shell out to `systemctl`, so what is covered is the decision each makes about what to report |
| `src/commands/report_wizard/tests.rs` | Unit tests for `src/commands/report_wizard.rs` | Test-only; `super` resolves to `crate::commands::report_wizard`, so its imports carried across unchanged |
| `src/commands/history/tests.rs` | Unit tests for `src/commands/history.rs` | Test-only; `super` resolves to `crate::commands::history`, so its imports carried across unchanged |
| `src/commands/batch/tests.rs` | Unit tests for `src/commands/batch.rs`, 70 tests | Test-only; `super` resolves to `crate::commands::batch`, so its imports carried across unchanged |
| `src/commands/checkpoint/tests.rs` | Unit tests for `src/commands/checkpoint.rs` | Test-only; `super` resolves to `crate::commands::checkpoint`, so its imports carried across unchanged |
| `src/commands/state/tests.rs` | Unit tests for `src/commands/state.rs` | Test-only; `super` resolves to `crate::commands::state`, so its imports carried across unchanged |
| `src/commands/privilege/tests.rs` | Unit tests for `src/commands/privilege.rs` | Test-only; `super` resolves to `crate::commands::privilege`, so its imports carried across unchanged |

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
| `src/inventory.rs` | Shared host-inventory persistence: the one definition of where `~/.config/linux-hardener/hosts.toml` lives, read and written by both the CLI `batch` command and the desktop backend. The `HostsConfig` it moves is defined in `hardener-types`, not here | `default_path()`, `load()`, `save()` |
| `src/config/tests.rs` | Unit tests for `src/config.rs` | Test-only; `super` resolves to `crate::config` |
| `src/config_loader/tests.rs` | Unit tests for `src/config_loader.rs` | Test-only; `super` resolves to `crate::config_loader` |
| `src/config_validation/tests.rs` | Unit tests for `src/config_validation.rs` | Test-only; `super` resolves to `crate::config_validation` |
| `src/plugin/tests.rs` | Unit tests for `src/plugin.rs` | Test-only; `super` resolves to `crate::plugin` |
| `src/inventory/tests.rs` | Unit tests for `src/inventory.rs` | Test-only; `super` resolves to `crate::inventory` |
| `src/executor/local/tests.rs` | Unit tests for `src/executor/local.rs`, 12 of them | Test-only; `super` resolves to `crate::executor::local` |
| `src/executor/ssh/tests.rs` | Unit tests for `src/executor/ssh.rs` | Test-only; `super` resolves to `crate::executor::ssh` |

### Key Trait (plugin.rs)

```rust
#[async_trait]
pub trait HardeningPlugin: Send + Sync {
    fn metadata(&self) -> PluginMetadata;
    fn dependencies(&self) -> Vec<PluginId>;
    async fn scan(&self, ctx: &Context, config: &PluginConfig) -> Result<ScanResult>;
    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult>;
    fn reloads_for_path(&self, path: &Path) -> bool { false }
    async fn reload_after_rollback(&self, ctx: &Context) -> Result<Option<String>> { Ok(None) }
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
| `src/logging.rs` | Logging setup | `init_logger()` |
| `src/file_utils.rs` | File utilities | `update_file_atomically()`, `read_config_file()`, `set_config_directive()`, `create_timestamped_backup()` |
| `src/binary_utils.rs` | Safe binary path resolution (CWE-426 prevention) | `resolve_binary()`, `TRUSTED_PATH` |
| `src/executor/mod.rs` | Executor abstraction (trait + types) | `SystemExecutor`, `CommandOutput`, `FileMetadata` |
| `src/executor/mock.rs` | Virtual filesystem for unit testing | `MockExecutor` |
| `src/vendor_config.rs` | Resolves configuration a distribution layers across `/etc` and `/usr/etc`. `/usr/etc` is consulted only on absence positively confirmed at `/etc`, because an `/etc` file that exists but cannot be read is still the file the system obeys, and answering with the vendor copy would report a configuration that is not in force | `ConfigLayer`, `LayeredRead`, `read_layered()`, `vendor_path_for()` |
| `src/error/tests.rs` | Unit tests for `src/error.rs` | Test-only; `super` resolves to `crate::error` |
| `src/logging/tests.rs` | Unit tests for `src/logging.rs` | Test-only; `super` resolves to `crate::logging` |
| `src/binary_utils/tests.rs` | Unit tests for `src/binary_utils.rs` | Test-only; `super` resolves to `crate::binary_utils` |
| `src/vendor_config/tests.rs` | Unit tests for `src/vendor_config.rs` | Test-only; `super` resolves to `crate::vendor_config` |
| `src/file_utils/tests.rs` | Unit tests for `src/file_utils.rs`, the first of the two test modules that file carried | Test-only; `super` resolves to `crate::file_utils` |
| `src/file_utils/global_scope_tests.rs` | The second, kept under its own name: that a directive written at global scope is not confused with the same directive inside an sshd `Match` block | Test-only; `super` resolves to `crate::file_utils` |
| `src/executor/tests.rs` | Unit tests for `src/executor/mod.rs`, 23 of them | Test-only; that file *is* the module `executor`, so its tests go in the directory it already owns |
| `src/executor/mock/tests.rs` | Unit tests for `src/executor/mock.rs`, 11 of them | Test-only; `super` resolves to `crate::executor::mock` |

**Note**: Core types (Severity, FindingCategory, etc.) are now defined in `hardener-types` and re-exported here for backwards compatibility. The executor abstraction (`SystemExecutor`, `CommandOutput`, `FileMetadata`, `MockExecutor`) relocated here from `hardener-core` and is re-exported from that crate for source compatibility.

---

## hardener-plugins (Security Plugins)

| File | Purpose | Plugin Struct |
|------|---------|---------------|
| `src/lib.rs` | Module exports, helpers | `create_checkpoint_for_apply()`, `create_checkpoint_metadata_only_for_apply()`, `checkpoint_change()` (shared `ChangeType::Checkpoint` bookkeeping change), `reload_plugins_after_rollback()`, `create_plugin_registry()`, `compliance_coverage()` |
| `src/macros.rs` | Plugin definition macro | `define_plugin!` |
| `src/scan_outcome.rs` | Turns per-plugin scan results into the flat lists a compliance report consumes. A plugin that contributed no evidence gets an entry carrying its whole declared coverage, so its controls route to Manual Review instead of passing on the silence its own absence caused; a run that could not enumerate its plugins at all gets one carrying the engine's whole coverage, for the same reason at the only scope left. Shared by the CLI and the desktop, beside the coverage table it depends on | `Unassessed`, `flatten_scans()`, `flatten_persisted_scans()`, `failed_scan()`, `unassessed_check()` |
| `src/strictness.rs` | The one definition of which direction counts as stricter for a configuration value, shared by the pam, ssh and kernel plugins. Comparing a host's value against the baseline for equality has no direction, so a stricter host reads as violating and apply writes the baseline over it; every variant here carries a direction, and there is deliberately no equality variant to give a directive added later. Also the single place an operator's directive override is clamped, so an override can tighten a target but never relax it | `Strictness` (`AtMost`, `AtLeast`, `NonZeroAtMost`, `Ranked`), `clamp_target()`, `violated_by()`, `resolved_target()` |

### Individual Plugins

| Plugin File | Category | Key Checks |
|-------------|----------|------------|
| `src/ssh/mod.rs` | Network | PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, MaxAuthTries, X11Forwarding, ClientAliveInterval, ClientAliveCountMax |
| `src/ssh/dropin.rs` | Network | Writes SSH hardening to `/etc/ssh/sshd_config.d/00-hardener.conf`, which sorts before the fragments distributions ship, so sshd takes this file's values first. Precedence is verified after writing by re-resolving, never assumed from the filename, and an empty directive set removes the file rather than leaving an empty one | `DROPIN_PATH`, `Directive`, `render()`, `write_dropin()` |
| `src/ssh/include.rs` | Network | Resolves `Include` directives in sshd's own order, so scan reports the value sshd will actually use and names the file supplying it. sshd takes the **first** value it obtains and distributions put the Include above everything this tool writes, so a drop-in silently won while the tool reported its own write |
| `src/kernel/mod.rs` | Kernel | ASLR, kptr_restrict, dmesg_restrict, ptrace_scope, suid_dumpable, rp_filter, tcp_syncookies |
| `src/kernel/persistence.rs` | Kernel | Reports a managed parameter that a file applied after `99-hardener.conf` sets looser than its target, so hardening that will not survive the next reboot is named rather than assumed to hold. Report-only; the apply writes nothing for it | `procfs_key()`, `boot_persistence()` |
| `src/firewall/mod.rs` | Network | Firewall enabled, baseline rules |
| `src/firewall/nftables.rs` | Network | nftables backend |
| `src/firewall/firewalld.rs` | Network | firewalld backend |
| `src/firewall/ufw.rs` | Network | UFW backend |
| `src/pam/mod.rs` | Auth | Password complexity, aging, lockout |
| `src/pam/login_defs.rs` | Auth | Carries a `/usr/etc` configuration file into `/etc` before the managed directives are edited into it, with the vendor file's own permissions rather than the temporary file's | `mode_for_copy_of()` |
| `src/pam/layer_drift.rs` | Auth | Reports the keys an `/etc` file hides from its `/usr/etc` counterpart, for every layered file the plugin reads rather than for `login.defs` alone | `LAYERED_CONFS`, `masked_keys()`, `masked_keys_finding()` |
| `src/services/mod.rs` | Services | Unnecessary services (xinetd, cups, avahi, etc.) |
| `src/permissions/mod.rs` | FileSystem | Critical paths, SUID/SGID, world-writable. Where `/etc` holds nothing at all, `scan` reads the `/usr/etc` copy through `vendor_path_for()` and reports a violating vendor mode as a finding keyed on the `/etc` path, so the id stays `perm--etc-sudoers` while the title names the file in force. The vendor file is never written, so that finding's remediation is an install into `/etc`; `apply` is unchanged and still leaves a path absent from `/etc` alone | `PermissionCheck::VendorOnly`, `check_vendor_layer_permissions()`, `effective_directive()` |
| `src/audit/mod.rs` | Audit | auditd rules for time, users, permissions |
| `src/mac/mod.rs` | MAC | SELinux/AppArmor status |
| `src/tests.rs` | Tests | Unit tests for the crate root | Test-only; reached the crate through `crate::` already, so no import changed |
| `src/reload_tests.rs` | Tests | Unit tests for `reload_plugins_after_rollback()` in `src/lib.rs`, against four stub plugins rather than any real plugin's `scan`/`apply`/`validate` | Test-only; reached the crate through `crate::` already, so no import changed |
| `src/audit/tests.rs` | Tests | Unit tests for `src/audit/mod.rs` | Test-only; `super` resolves to `crate::audit` |
| `src/firewall/tests.rs` | Tests | Unit tests for `src/firewall/mod.rs`, 54 of them | Test-only; `super` resolves to `crate::firewall` |
| `src/kernel/tests.rs` | Tests | Unit tests for `src/kernel/mod.rs` | Test-only; `super` resolves to `crate::kernel` |
| `src/kernel/persistence/tests.rs` | Tests | Unit tests for `src/kernel/persistence.rs` | Test-only; `super` resolves to `crate::kernel::persistence` |
| `src/mac/tests.rs` | Tests | Unit tests for `src/mac/mod.rs` | Test-only; `super` resolves to `crate::mac` |
| `src/pam/tests.rs` | Tests | Unit tests for `src/pam/mod.rs` | Test-only; `super` resolves to `crate::pam` |
| `src/pam/layer_drift/tests.rs` | Tests | Unit tests for `src/pam/layer_drift.rs` | Test-only; `super` resolves to `crate::pam::layer_drift` |
| `src/pam/login_defs/tests.rs` | Tests | Unit tests for `src/pam/login_defs.rs` | Test-only; `super` resolves to `crate::pam::login_defs` |
| `src/permissions/tests.rs` | Tests | Unit tests for `src/permissions/mod.rs` | Test-only; `super` resolves to `crate::permissions` |
| `src/services/tests.rs` | Tests | Unit tests for `src/services/mod.rs` | Test-only; `super` resolves to `crate::services` |
| `src/scan_outcome/tests.rs` | Tests | Unit tests for `src/scan_outcome.rs` | Test-only; `super` resolves to `crate::scan_outcome` |
| `src/ssh/tests.rs` | Tests | Unit tests for `src/ssh/mod.rs` | Test-only; `super` resolves to `crate::ssh` |
| `src/ssh/dropin/tests.rs` | Tests | Unit tests for `src/ssh/dropin.rs` | Test-only; `super` resolves to `crate::ssh::dropin` |
| `src/ssh/include/tests.rs` | Tests | Unit tests for `src/ssh/include.rs` | Test-only; `super` resolves to `crate::ssh::include` |
| `src/strictness/tests.rs` | Tests | Unit tests for `src/strictness.rs` | Test-only; `super` resolves to `crate::strictness` |

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
const KERNEL_PARAMS: &[KernelParameter] = &[
    KernelParameter {
        kernel_parameter_name: "kernel.randomize_va_space",
        kernel_secure_value: "2",
        kernel_description: "Enable full address space layout randomisation (ASLR)",
        kernel_severity: Severity::High,
        kernel_compare: Strictness::AtLeast,
    },
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
| `src/manager/tests.rs` | Unit tests for `src/manager.rs`, 46 of them | Test-only; `super` resolves to `crate::manager`, so imports carried across unchanged |
| `src/hash_chain/tests.rs` | Unit tests for `src/hash_chain.rs` | Test-only; same shape |
| `src/signing/tests.rs` | Unit tests for `src/signing.rs` | Test-only; same shape |
| `src/db/tests.rs` | Unit tests for `src/db.rs` | Test-only; same shape |

### Key Structures

```rust
pub struct Checkpoint {
    pub checkpoint_id: CheckpointId,
    pub checkpoint_name: String,
    pub checkpoint_timestamp: i64,
    pub checkpoint_username: String,
    pub checkpoint_signature: Vec<u8>,
    pub host_key: String,
}

pub struct FileState {
    pub file_path: String,
    pub file_content: Option<Vec<u8>>,
    pub file_permissions: u32,
    pub file_owner_uid: u32,
    pub file_owner_gid: u32,
    pub file_link_target: Option<String>,
    pub file_content_absence: Option<ContentAbsence>,
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
| `src/output/mod.rs` | Formatter routing | `CsvFormatter`, `HtmlFormatter`, `JsonFormatter`, `PdfFormatter`, `TextFormatter` (re-exports) |
| `src/output/text.rs` | Text formatter | `TextFormatter` |
| `src/output/json.rs` | JSON formatter | `JsonFormatter` |
| `src/output/csv.rs` | CSV formatter | `CsvFormatter` |
| `src/output/html.rs` | HTML formatter | `HtmlFormatter` |
| `src/output/pdf.rs` | PDF formatter | `PdfFormatter` |
| `src/fonts/NotoSans-Regular.ttf` | Embedded font | Regular weight |
| `src/fonts/NotoSans-Bold.ttf` | Embedded font | Bold weight |
| `src/generator/tests.rs` | Unit tests for `src/generator.rs` | Test-only; `super` resolves to `crate::generator`, so its imports carried across unchanged |
| `src/profiles/tests.rs` | Unit tests for `src/profiles.rs` | Test-only; `super` resolves to `crate::profiles` |
| `src/frameworks/iso27001/tests.rs` | Unit tests for `src/frameworks/iso27001.rs` | Test-only; `super` resolves to `crate::frameworks::iso27001` |
| `src/output/test_support.rs` | Fixtures shared by the formatter test modules, split out of `src/output/mod.rs` | Test-only; that file *is* the module `output`, so this sits in the directory it already owns and the formatter tests still reach it as `crate::output::test_support` |
| `src/output/text/tests.rs` | Unit tests for `src/output/text.rs` | Test-only; `super` resolves to `crate::output::text` |
| `src/output/json/tests.rs` | Unit tests for `src/output/json.rs` | Test-only; `super` resolves to `crate::output::json` |
| `src/output/csv/tests.rs` | Unit tests for `src/output/csv.rs` | Test-only; `super` resolves to `crate::output::csv` |
| `src/output/html/tests.rs` | Unit tests for `src/output/html.rs` | Test-only; `super` resolves to `crate::output::html` |
| `src/output/pdf/tests.rs` | Unit tests for `src/output/pdf.rs` | Test-only; `super` resolves to `crate::output::pdf` |

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
| `src/tests.rs` | Unit tests for the crate root, split out of `lib.rs` | Test-only; a crate root cannot become a directory, so `super` here means this file and its `use super::*` became `use crate::*` |
| `src/adapter/tests.rs` | Unit tests for `src/adapter.rs` | Test-only; `super` resolves to `crate::adapter`, so its imports carried across unchanged |
| `src/package/tests.rs` | Unit tests for `src/package/mod.rs` | Test-only; `super` resolves to `crate::package`, the directory that file already owns |

---

## hardener-scheduler (Scheduled Scanning)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/lib.rs` | Module exports | Re-exports public types |
| `src/config.rs` | Scheduler configuration | `SchedulerConfig`, `StorageConfig`, `NotificationConfig`, `EmailConfig`, `WebhookConfig` |
| `src/db.rs` | SQLite scan history | `ScanHistoryManager`, `ScanSession`, `ScanFinding`, `SeverityCounts` |
| `src/json_store.rs` | JSON file storage | `JsonStore` |
| `src/runner.rs` | Scan execution orchestrator | `ScanRunner`, `ScanSummary`, `TriggerType` |
| `src/daemon.rs` | Cron-scheduled scanning daemon | `Daemon` |
| `src/notification/mod.rs` | Notification system module | `Notifier`, `NotificationResult`, `parse_severity()`, `meets_severity_threshold()` |
| `src/notification/email.rs` | SMTP email notifications | `EmailNotifier` |
| `src/notification/webhook.rs` | HTTP webhook notifications | `WebhookNotifier` |
| `src/notification/dispatcher.rs` | Notification coordinator | `NotificationDispatcher` |
| `src/systemd.rs` | Systemd unit file generation | `SystemdGenerator`, `cron_to_calendar()`, `service_name()`, `timer_name()` |
| `src/config/tests.rs` | Unit tests for `src/config.rs` | Test-only; `super` resolves to `crate::config`, so its imports carried across unchanged |
| `src/db/tests.rs` | Unit tests for `src/db.rs`, 13 tests over the host-aware scan history | Test-only; `super` resolves to `crate::db`, so its imports carried across unchanged |
| `src/json_store/tests.rs` | Unit tests for `src/json_store.rs` | Test-only; `super` resolves to `crate::json_store`, so its imports carried across unchanged |
| `src/runner/tests.rs` | Unit tests for `src/runner.rs` | Test-only; `super` resolves to `crate::runner`, so its imports carried across unchanged |
| `src/daemon/tests.rs` | Unit tests for `src/daemon.rs` | Test-only; `super` resolves to `crate::daemon`, so its imports carried across unchanged |
| `src/notification/tests.rs` | Unit tests for `src/notification/mod.rs`, that file is the module, so its tests go to the directory it already owns | Test-only; `super` resolves to `crate::notification`, so its imports carried across unchanged |
| `src/notification/email/tests.rs` | Unit tests for `src/notification/email.rs` | Test-only; `super` resolves to `crate::notification::email`, so its imports carried across unchanged |
| `src/notification/webhook/tests.rs` | Unit tests for `src/notification/webhook.rs`, 33 tests, the largest block in this crate | Test-only; `super` resolves to `crate::notification::webhook`, so its imports carried across unchanged |
| `src/notification/dispatcher/tests.rs` | Unit tests for `src/notification/dispatcher.rs` | Test-only; `super` resolves to `crate::notification::dispatcher`, so its imports carried across unchanged |
| `src/systemd/tests.rs` | Unit tests for `src/systemd.rs` | Test-only; `super` resolves to `crate::systemd`, so its imports carried across unchanged |

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
    mode: NotifyMode,
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
    pub regression: Option<RegressionInfo>,
}

/// Orchestrates plugin scans with database and JSON persistence.
pub struct ScanRunner {
    db: Arc<ScanHistoryManager>,
    json_store: Arc<JsonStore>,
    min_severity: Severity,
    plugins: Vec<String>,
    host: String,
    dispatcher: Option<NotificationDispatcher>,
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
| `src/state/mod.rs` | Reactive state | `AppState`, `unchecked_tally()` |
| `src/tauri_bindings.rs` | Tauri command bindings | `tauri_available`, `invoke_scan`, `invoke_deep_scan`, `invoke_apply`, `invoke_apply_dry_run`, `invoke_generate_report`, `invoke_export_report`, `invoke_get_latest_scan`, `invoke_get_checkpoints`, `invoke_create_checkpoint`, `invoke_delete_checkpoint`, `invoke_get_scan_history`, `invoke_get_scan_session`, `invoke_get_checkpoint_detail`, `invoke_rollback`, `invoke_list_remote_hosts`, `invoke_save_remote_host`, `invoke_delete_remote_host`, `invoke_connect_remote`, `invoke_disconnect_remote`, `invoke_remote_scan`, `invoke_fleet_scan`, `invoke_fleet_apply`, `invoke_fleet_rollback`, `invoke_get_host_history`, `invoke_list_plugins`, `invoke_get_scheduler_config`, `invoke_save_scheduler_config`, `invoke_test_notification`, `invoke_validate_config`, `invoke_pick_config_file` |
| `src/keyboard.rs` | Global keyboard event handler | Ctrl+1-5 page nav (`/`, `/analysis`, `/hardening`, `/fleet`, `/scheduler`; Ctrl+4 navigates straight to `/fleet`, not through the retained `/remote` redirect - Fleet Apply and Settings have no shortcut yet), Ctrl+Shift+S scan from anywhere, Alt+T theme cycle, Escape priority chain, F11 fullscreen |
| `src/navigation.rs` | Navigation signal helpers | Page routing helpers for keyboard and UI nav |
| `src/utils/mod.rs` | Utils module exports and preview/apply helpers | `annotate_preview()`, `PreviewDecision`, `apply_change_summary()`, `is_auth_cancelled()`, `parse_rate_limit_wait_secs()`, `unchecked_honesty_line()`; `mock_data` mod, `theme` mod |
| `src/utils/mock_data.rs` | Development mocks | Mock data generators |
| `src/utils/theme.rs` | Shared theme metadata plus the single apply/persist side effects; the only writer of `<html data-theme>` and the `theme` localStorage key | `THEMES` (7 themes), `apply_theme()`, `get_stored_theme()`, `store_theme()` |
| `src/utils/tests.rs` | Unit tests for `src/utils/mod.rs` | Test-only; that file *is* the module `utils`, so its tests go in the directory it already owns |
| `src/utils/theme/tests.rs` | Unit tests for `src/utils/theme.rs` | Test-only; `super` resolves to `crate::utils::theme` |
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
| `src/pages/fleet_apply_page/tests.rs` | Unit tests for `src/pages/fleet_apply_page.rs` | Test-only; `super` resolves to `crate::pages::fleet_apply_page` |
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
| `src/components/configure_section/tests.rs` | Unit tests for `src/components/configure_section.rs` | Test-only; `super` resolves to `crate::components::configure_section` |
| `src/components/segmented_control.rs` | Reusable WAI-ARIA segmented control (roving-tabindex radiogroup); shared by the Fleet Apply mode toggle and the Hardening protection-level control | `SegmentedControl` |
| `src/components/history_section.rs` | Apply results and checkpoint management with refresh button | `HistorySection` |
| `src/components/modal.rs` | Shared modal shell used by every dialog: backdrop, Escape and backdrop-click dismissal, dialog ARIA, and focus-on-mount. Swallows Escape so dismissing a dialog cannot also advance the global `keyboard.rs` priority chain and discard a pending apply review | `Modal` |
| `src/components/rollback_modal.rs` | Rollback confirmation modal for the Hardening History timeline (confirm, restoring, and per-file result stages) | `RollbackModal` |
| `src/components/card.rs` | Reusable card container component | `Card`, `CardVariant`, `HeadingLevel` |
| `src/components/theme_toggle.rs` | Theme quick-switch `<select>` in the sidebar, bound to the shared `AppState.theme` signal (presentational only; the App `Effect` applies/persists it) | `ThemeToggle` |
| `src/components/theme_picker.rs` | Settings page theme swatch grid: WAI-ARIA radiogroup of live-coloured preview cards, one per `THEMES` entry | `ThemePicker` |
| `src/components/status_icons.rs` | Shared status/flag inline SVG icon set (applied/failed/manual/skipped plus the help affordance), declared through a `status_icon!` macro and re-exported from `components/mod.rs` | `IconCheck`, `IconInfo`, `IconX`, `IconWrench`, `IconMinus` |
| `src/components/icons.rs` | Inline SVG icon set for the sidebar navigation, the brand mark and the findings-row disclosure, declared through a `nav_icon!` macro. The module is private; callers reach it as `super::icons::...` | `IconDashboard`, `IconAnalysis`, `IconHardening`, `IconFleet`, `IconFleetApply`, `IconScheduler`, `IconSettings`, `IconChevronCollapse`, `IconChevron`, `IconShieldMark` |
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
| `src/components/adhoc_host_input/tests.rs` | Unit tests for `src/components/adhoc_host_input.rs` | Test-only; `super` resolves to `crate::components::adhoc_host_input` |

**Note**: This crate depends only on `hardener-types` for shared types to ensure WASM compatibility. External dependencies include Leptos (WASM framework), wasm-bindgen, and web-sys for browser APIs.

### Theme Files (crates/hardener-ui/themes/)

**This directory is gitignored** (`.gitignore`, `crates/hardener-ui/themes/`), so a
fresh clone will not contain it. It is a local reference copy kept beside the
build, listed here so the mapping between a theme id and its palette has a
written home.

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

**Note**: Active theme definitions are in `styles.css` using `[data-theme="..."]` selectors. Individual theme files serve as reference and documentation. The directory holds eight files where the application offers **seven** themes: `THEMES` in `src/utils/theme.rs` lists `default` (Midnight Teal), `fortress`, `sentinel`, `command`, `guardian`, `daywatch` and `high-contrast`. `github-dark.css` is a leftover reference palette and is not selectable.

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
pub async fn invoke_fleet_scan(host_names: Vec<String>, adhoc: Vec<String>, plugin_ids: Option<Vec<String>>) -> Result<Vec<FleetHostScan>, String>;

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
| `src/decoration_tests.rs` | Unit tests for `desktop_is_tiling()` in `src/main.rs` | Test-only; `main.rs` is the crate root, so this sits beside it exactly as `acl_tests.rs` does |
| `src/validation/tests.rs` | Unit tests for `src/validation.rs` | Test-only; `super` resolves to `crate::validation` |
| `src/commands/fleet_tests.rs` | Fleet command tests, the first of the three test modules `src/commands.rs` carried | Test-only; `super` resolves to `crate::commands` |
| `src/commands/delete_escalation_tests.rs` | Tests for the guard deciding whether deleting a checkpoint is worth an authentication prompt | Test-only; `super` resolves to `crate::commands`. Takes the database path as a parameter so it runs the same on a host with a system database and one without |
| `src/commands/fail_session_on_err_tests.rs` | Tests for `fail_session_on_err`, the helper that marks an aborted scan's history row Failed rather than orphaning it as running | Test-only; `super` resolves to `crate::commands` |
| `src/commands/compliance_source_tests.rs` | Tests for the compliance report's source selection | Test-only; `super` resolves to `crate::commands` |
| `src/commands/webhook_shape_tests.rs` | Tests that what the desktop writes to `[scheduler.notifications.webhooks]` is what `hardener-scheduler` reads back | Test-only; `super` resolves to `crate::commands`. This crate depends on both, so it is the only place the two shapes meet |

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
pub async fn run_rollback(checkpoint_id: String) -> Result<RollbackResult, String>
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
| `scripts/validate/validate_doc_attachment.py` | Loose doc comment validator: an undocumented free function beside a long doc block |
| `scripts/validate/validate_badges.py` | README badge validator |
| `scripts/validate/validate_changelog_headings.py` | CHANGELOG heading validator: no release entry repeats a change-type heading |
| `scripts/validate/validate_doc_links.py` | Markdown link validator: every link in a tracked `.md` must resolve for a reader who has only the repository, so a target that is missing or gitignored fails |
| `scripts/validate/validate_doc_targets.py` | Doc sync target validator |
| `scripts/validate/validate_file_map.py` | file-map.md accuracy validator |
| `scripts/validate/validate_policy_exception_sites.py` | Policy exception site registry |
| `scripts/validate/validate_srcinfo.py` | `.SRCINFO` validator: the AUR reads it and never the PKGBUILD beside it, so the two must agree |
| `scripts/validate/validate_last_updated.py` | Last Updated timestamp validator |
| `scripts/validate/validate_plugin_docs.py` | Plugin documentation validator |
| `scripts/validate/validate_tauri_docs.py` | Tauri integration documentation validator |
| `scripts/validate/validate_write_sites.py` | File-creation site registry: every plugin call site that creates a file is classified on two questions, `ensured` or `exempt` for its parent directory and `declared` or `exempt` for its plugin's pre-apply checkpoint, each with a written reason; the `cp` sites are additionally asserted to copy with both `-p` and `--no-dereference` |
| `scripts/validate/validate_unit_state_reads.py` | Unit state read registry: every `systemctl is-enabled` call site declares whether it judges systemd's word or its exit status and why, with the declared answer cross-checked against whether the enclosing function reads `output.success()` |
| `scripts/validate/validate_test_assertions.py` | Test assertion reachability: every test function must reach an assertion on every path through its body, so a test cannot exit 0 having asserted nothing while still counting towards the suite total. A `match` with every arm asserting, an `if`/`else` chain ending in a bare `else`, and a `for` over an array literal all satisfy it; an `if` with no `else` and a loop over a computed collection do not |
| `scripts/validate/update_all_docs.py` | Batch documentation updater |
| `scripts/release/release.sh` | Automated version bumping and release |
| `scripts/dev/tauri-dev.sh` | Tauri development launcher |
| `scripts/test/full-test-suite.sh` | Complete validation suite, 28 sections recording 149 checks on a booted container under `--apply`. `suite_section_sizes` declares what each section records and `require_expected_total` refuses a run of the wrong size |
| `scripts/test/differential-suite.sh` | Differential harness: applies hardening, then asks `sshd -T`, `chage -l` and `stat -c %a` what the system enforces and compares that against `scan` (`--self-test` runs anywhere) |
| `scripts/test/run-cross-distro-tests.sh` | Non-interactive cross-distro test orchestrator (`--differential` swaps in the differential suite) |
| `scripts/test/root-test-suite.sh` | 36 root-level privilege tests |
| `scripts/test/manual-verification-test.sh` | Interactive verification tests |
| `scripts/containers/create-container.sh` | systemd-nspawn test containers for all five distros (`arch`, `debian`, `fedora`, `rhel`, `opensuse`) |
| `scripts/test/verify-rollback.sh` | Rollback verification for nspawn containers, over four areas its own header names: kernel sysctl values plus config file content, `sshd_config` backup and content restoration, directory mode restoration, and `rollback --format json` producing a valid `RollbackResult` |

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

Unit tests sit beside the source file they exercise, in a `#[cfg(test)]` module of their own file rather than inside it: `foo.rs` is accompanied by `foo/tests.rs`, and a `foo/mod.rs` by `foo/tests.rs` in the directory it already owns. They are still child modules, so they still read private items; only their location changed. Integration tests, which see the public API only, remain in each crate's `tests/` directory. The **Unit Tests** column below names the source files under test, not the files the tests live in.

The counts below are `#[test]` and `#[tokio::test]` annotations counted in the
tree on **2026-08-04**, not a run total: a run also executes doctests and, for
`hardener-ui`, `wasm_bindgen_test` cases that no annotation count here covers.
Treat them as the size of each crate's declared test surface, and read the
workspace run itself for what passed.

| Crate | Unit Tests | Integration Tests | Annotations |
|-------|------------|-------------------|-------------|
| hardener-common | `error.rs`, `file_utils.rs`, `logging.rs`, `binary_utils.rs`, `vendor_config.rs`, `executor/mod.rs`, `executor/mock.rs` | `common_types.rs`, `error_tests.rs`, `file_utils_tests.rs`, `common/mod.rs` | 116 |
| hardener-compliance | `generator.rs`, `profiles.rs`, `frameworks/iso27001.rs`, and five of `output/`: `text.rs`, `json.rs`, `csv.rs`, `html.rs`, `pdf.rs` | `assessment_honesty.rs`, `config_tests.rs`, `framework_tests.rs`, `report_tests.rs` | 88 |
| hardener-state | `db.rs`, `hash_chain.rs`, `signing.rs`, `manager.rs` | `audit_tests.rs`, `checkpoint_system.rs`, `db_tests.rs`, `scan_manager_tests.rs`, `signing_tests.rs`, `common/mod.rs` | 102 |
| hardener-distro | `lib.rs`, `adapter.rs`, `package/mod.rs` | - | 16 |
| hardener-scheduler | `config.rs`, `db.rs`, `json_store.rs`, `runner.rs`, `daemon.rs`, `systemd.rs`, `notification/*.rs` | - | 104 |
| hardener-cli | `cli.rs`, `output.rs`, `ssh_config.rs`, and eleven of `commands/`: `apply.rs`, `batch.rs`, `checkpoint.rs`, `history.rs`, `plugin_filter.rs`, `privilege.rs`, `report.rs`, `report_wizard.rs`, `scan.rs`, `state.rs`, `systemd.rs` | `batch_ssh_integration.rs` (live-sshd, `#[ignore]`), `ssh_refusal.rs` (drives the built binary), `config_flag.rs` (drives the built binary), `quiet_output.rs` (drives the built binary), `output_artefacts.rs` (drives the built binary) | 226 |
| hardener-plugins | `lib.rs`, `strictness.rs`, `scan_outcome.rs`, and all eight plugin modules (`ssh/dropin.rs` and `ssh/include.rs` also carry their own) | `*_tests.rs` (8 files), `*_mock_tests.rs` (8 files), `ssh_integration_tests.rs`, `common/mod.rs` | 636 |
| hardener-core | `config.rs`, `config_loader.rs`, `config_validation.rs`, `plugin.rs`, `inventory.rs`, `executor/local.rs`, `executor/ssh.rs` | `config_tests.rs`, `context_tests.rs`, `mock_executor_tests.rs`, `plugin_manager_tests.rs`, `registry_tests.rs`, `ssh_executor_tests.rs` | 137 |
| hardener-types | `lib.rs`, `remote.rs`, `scheduler.rs` | - | 53 |
| hardener-ui | `utils/mod.rs`, `utils/theme.rs`, `pages/fleet_apply_page.rs`, `components/configure_section.rs`, `components/adhoc_host_input.rs` | - | 101 |

### Executor and Mock Test Files

Added with the executor abstraction in v0.3.0 and grown considerably since;
counts measured the same way and on the same date as the table above.

| File | Purpose | Annotations |
|------|---------|-------------|
| `hardener-core/tests/mock_executor_tests.rs` | MockExecutor unit tests | 15 |
| `hardener-core/tests/ssh_executor_tests.rs` | SshExecutor unit/integration tests | 14 |
| `hardener-plugins/tests/*_mock_tests.rs` | Mock-based plugin tests (8 files) | 375 |
| `hardener-plugins/tests/ssh_integration_tests.rs` | Plugin SSH integration tests | 11 |

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
| `gui-tests/tests/themes.spec.js` | T-THEME-01..07 (7 tests + 30 screenshots): 6 of the 7 themes (default/Midnight Teal, fortress, sentinel, command, guardian, daywatch; High Contrast has no coverage yet). The 30 are generated at collection time from 5 states x 6 themes |
| `gui-tests/tests/errors.spec.js` | T-ERR-01..04 (4 tests): error handling and dismiss |
| `gui-tests/tests/fleet.spec.js` | Fleet scan view (7 tests) |
| `gui-tests/tests/fleet-apply.spec.js` | Fleet Apply mode toggle, selection and confirm modal (9 tests) |
| `gui-tests/tests/remote.spec.js` | Single-host remote connect session (7 tests) |
| `gui-tests/tests/scheduler.spec.js` | Scheduler and notification configuration (6 tests) |

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

**Last Updated**: 2026-08-04
