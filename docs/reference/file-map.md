# Linux Hardener - File Map

**Last Updated**: 2026-08-28

This document lists all source files with their purpose and key exports.

---

## hardener-types (WASM-Compatible Shared Types)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/lib.rs` | All shared type definitions | `PluginId`, `Severity`, `FindingCategory`, `ComplianceFramework`, `ComplianceMapping`, `ControlStatus`, `FindingPolicyException`, `PluginMetadata`, `ScanResult`, `Finding`, `UncheckedCheck`, `ApplyResult`, `Change`, `ChangeType`, `ValidationReport`, `ValidationIssue`, `ComplianceReport`, `ControlResult`, `ComplianceSummary`, `ConfigSummary`, `FleetHostScan`, `FleetHostStatus`, `SeverityTallies`, `ComplianceProfile`, `profile_label()` |
| `src/checkpoint.rs` | Checkpoint and scan-session types shared by the Tauri backend and the Leptos frontend. Hand-mirrored in `hardener-ui/src/types.rs` until #157; two fields fell through that copy (`system_unreadable` in #156, `checkpoint_verified` in #157) because the mirror sat outside the tree `validate_gui_mock_fixtures.py` resolves | `CheckpointInfo`, `CheckpointList`, `CheckpointDetail`, `CheckpointFileInfo`, `ScanSessionInfo` |
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
pub struct FleetHostScan { host_name: String, status: FleetHostStatus, tallies: SeverityTallies, scan_results: Vec<ScanResult>, compliance: Vec<FleetFrameworkPosture>, profile: ComplianceProfile }
```

---

## hardener-cli (CLI Binary)

| File | Purpose | Key Exports/Functions |
|------|---------|----------------------|
| `src/main.rs` | Entry point, command routing | `main()` |
| `src/cli.rs` | Clap argument definitions | `Cli`, `Command`, `BatchAction`, `CheckpointAction`, `DaemonAction`, `ExceptionAction`, `HistoryAction`, `SystemdAction`, `OutputFormat` |
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
| `src/commands/systemd.rs` | Systemd unit file commands. `install` and `uninstall` go through `hardener-core`'s shared writer, so a unit file is replaced whole rather than rewritten in place and both directions file an audit entry: a timer running `hardener scan` as root is host state, and its removal is the direction that reports itself least. `generate --output-dir` is deliberately outside that, since it writes to a directory the operator named rather than to a unit path | `generate()`, `install()`, `uninstall()`, `status()`, `unit_audit()`, `unit_dir_for()`, `scope_name()` |
| `src/commands/history.rs` | Scan history commands | `list()`, `show()`, `export()`, `trends()`, `regressions()` |
| `src/commands/batch.rs` | Multi-host concurrent scan/report/apply/rollback commands | `run()`, `run_report()`, `run_apply()`, `run_rollback()`, `BatchOptions`, `BatchReportOptions`, `BatchApplyOptions`, `BatchRollbackOptions`, `resolve_and_scan()`, `run_on_all()` |
| `src/ssh_config.rs` | SSH connection config helper | `SshConnectionConfig` |
| `src/commands/state.rs` | Shared state initialisation (DB + signing key paths) | `get_checkpoint_manager()`, `get_audit_logger()`, `effective_user()` |
| `src/commands/privilege.rs` | Shared privilege probe for mutating commands; asks the executor session (`id -u` / `sudo -n`) so `--ssh` targets gate correctly | `is_privileged()` |
| `src/commands/exception.rs` | `hardener exception add`/`remove`: pins the value a live scan reports for a keyed finding, then writes or removes the exception table for it via `document`. `add` refuses a key the scan did not itself produce (`pin_from_findings`), so a crafted key over IPC can never reach the file. Also owns the writer every config write in the CLI goes through: `write_atomically` takes a `WriteAudit` and files the entry itself, so a caller cannot write `config.toml` without saying what to log | `AddOptions`, `RemoveOptions`, `WriteAudit`, `pin_from_findings()`, `add()`, `remove()`, `write_atomically()`, `exception_details()`. `add` and `remove` take their `AuditLogger` as a parameter: the no-argument pair they used to have was reached by five tests, which filed real exception entries into the audit log of whoever ran `cargo test` |
| `src/commands/exception/document.rs` | Pure TOML-text edits of one `[<section>.exceptions."<key>"]` table, `toml_edit`-based so an operator's comments, formatting and unrelated sections survive the write untouched (the reason `save_scheduler_config` at `src-tauri/src/commands.rs:1978` already gives). No file IO, no scanning, no clap: those live in `exception.rs`. A freshly created `exceptions` table is marked implicit, so it contributes no empty `[<section>.exceptions]` header of its own | `upsert_exception()`, `remove_exception()` |
| `src/commands/scope.rs` | `hardener scope exclude`/`include`: writes one `[compliance.not_applicable.<framework>."<control>"]` table through `toml_edit`, for the same reason `exception/document.rs` gives, and files one audit entry beside it. Validation runs before the write, because an exclusion raises a score by leaving its denominator: an unparseable framework id, an empty reason and, where a curated catalogue exists to check against, an unknown control id are all refused first. The verb exists for the audit entry rather than the write, since a hand edit of `config.toml` produces the same table and no record of who raised the score | `run_exclude()`, `run_exclude_to()`, `run_include()`, `run_include_to()`, `unknown_control_refusal()`, `inert_exclusion_advisory()`, `upsert_exclusion()`, `remove_exclusion()` |
| `src/cli/tests.rs` | Unit tests for `src/cli.rs`, 40 tests of argument parsing | Test-only; `super` resolves to `crate::cli`, so its imports carried across unchanged |
| `src/output/tests.rs` | Unit tests for `src/output.rs`, 41 tests of the renderers | Test-only; `super` resolves to `crate::output`, so its imports carried across unchanged |
| `src/ssh_config/tests.rs` | Unit tests for `src/ssh_config.rs` | Test-only; `super` resolves to `crate::ssh_config`, so its imports carried across unchanged |
| `src/commands/scan/tests.rs` | Unit tests for `src/commands/scan.rs` | Test-only; `super` resolves to `crate::commands::scan`, so its imports carried across unchanged |
| `src/commands/plugin_filter/tests.rs` | Unit tests for `src/commands/plugin_filter.rs` | Test-only; `super` resolves to `crate::commands::plugin_filter`, so its imports carried across unchanged |
| `src/commands/apply/tests.rs` | Unit tests for `src/commands/apply.rs` | Test-only; `super` resolves to `crate::commands::apply`, so its imports carried across unchanged |
| `src/commands/report/tests.rs` | Unit tests for `src/commands/report.rs` | Test-only; `super` resolves to `crate::commands::report`, so its imports carried across unchanged |
| `src/commands/systemd/tests.rs` | Unit tests for `src/commands/systemd.rs`, 20 tests: what `uninstall` reports, the status stream join, the five decisions the audit descriptor makes (the systemd instance, the unit-shaped target, install against uninstall at that same target, caller detail being added rather than replacing, and the unit directory following the mode, both answers now asserted whole against a home handed in rather than by suffix against the runner's own), a host with no home directory taking a system install and refusing a user one, and four on the privilege gate and the local-write guarantee: a system install without root refusing before the directory exists or systemd is asked anything, a `--user` install never needing root, the uninstall refusal naming its own verb, and the units reaching disk through `std::fs` while the executor is asked for `systemctl` alone, and one that the `LocalTarget` both verbs resolve is never a remote executor, two that drive `write_units` and `remove_units` against a temporary unit directory so a descriptor is observed reaching a write, and four that drive `install_with` and `uninstall_with` against a `MockExecutor` (reload before enable, a timer that would not start, a system install never reaching the user instance, and an uninstall proceeding past a timer that was never enabled) | Test-only; `super` resolves to `crate::commands::systemd`. `unit_dir_for`, the root check and `LocalExecutor` stay outside what is driven; `status` still spawns `systemctl` itself and only its stream join is asserted |
| `src/commands/report_wizard/tests.rs` | Unit tests for `src/commands/report_wizard.rs` | Test-only; `super` resolves to `crate::commands::report_wizard`, so its imports carried across unchanged |
| `src/commands/history/tests.rs` | Unit tests for `src/commands/history.rs` | Test-only; `super` resolves to `crate::commands::history`, so its imports carried across unchanged |
| `src/commands/batch/tests.rs` | Unit tests for `src/commands/batch.rs`, 86 tests | Test-only; `super` resolves to `crate::commands::batch`, so its imports carried across unchanged |
| `src/commands/checkpoint/tests.rs` | Unit tests for `src/commands/checkpoint.rs` | Test-only; `super` resolves to `crate::commands::checkpoint`, so its imports carried across unchanged |
| `src/commands/state/tests.rs` | Unit tests for `src/commands/state.rs` | Test-only; `super` resolves to `crate::commands::state`, so its imports carried across unchanged |
| `src/commands/privilege/tests.rs` | Unit tests for `src/commands/privilege.rs` | Test-only; `super` resolves to `crate::commands::privilege`, so its imports carried across unchanged |
| `src/commands/exception/document/tests.rs` | Unit tests for `src/commands/exception/document.rs`, 9 tests | Test-only; `super` resolves to `crate::commands::exception::document`, so its imports carried across unchanged |
| `src/commands/scope/tests.rs` | Unit tests for `src/commands/scope.rs`, 19 tests: the write preserving the rest of the file, `include` removing only the control it names, the five refusals (empty reason, unknown framework, unknown control under a curated catalogue, an unparseable `--review-by`, withdrawing a declaration that is not there), a failed write reaching the log too, the stderr advisory a derived-catalogue framework earns while still being written and audited, and what reaches the audit log in each case, granted and refused alike, read back out of the hash chain | Test-only; `super` resolves to `crate::commands::scope`. The tests drive the `_to` variants, which exist so the audit log and the config can be pointed at a temporary directory; `run_exclude`/`run_include` differ from them only in resolving those paths |
| `src/commands/exception/tests.rs` | Unit tests for `src/commands/exception.rs`, 13 tests: `pin_from_findings()`, `parse_expiry()` (including a malformed `--expires` refused before `add` ever scans or writes), `exception_details()`, the audit entry `add()` and `remove()` each file against a scratch log, and `add()`/`remove()` end to end against a temporary config and a `MockExecutor` scan, those three passing `None` for the logger because they are about the document rather than the entry, re-scanning afterwards to prove the pinned value is one the plugin's own comparison then accepts (one value-comparing plugin, one presence plugin) | Test-only; `super` resolves to `crate::commands::exception`, so its imports carried across unchanged |

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
| `src/config/scope.rs` | The `[compliance]` schema: controls declared not applicable to this system, so they leave the score's denominator rather than counting against it as `ManualReview`. Holds the review-interval table (twelve months for every framework, sourced per framework in the module header), the expiry arithmetic and the host-targeting predicate. Taking `ComplianceFramework` rather than an id string in `default_review_months` is deliberate: there is no wildcard arm, so an eleventh framework is a compile error instead of a silent default | `ScopeExclusion`, `ComplianceConfig`, `default_review_months()`, `review_deadline()`, `is_valid_on()`, `covers_host()` |
| `src/config_loader.rs` | Config loading and merging | `ConfigLoader` |
| `src/testing.rs` | MockPlugin builder for tests | `MockPlugin` |
| `src/config_validation.rs` | Config directive validation at load time | `validate_config()`, per-plugin validators (kernel, SSH, firewall, PAM, permissions) |
| `src/executor/mod.rs` | Re-exports executor abstraction from `hardener-common` | `SystemExecutor`, `CommandOutput`, `FileMetadata`, `MockExecutor` |
| `src/executor/local.rs` | Local file/command operations | `LocalExecutor` |
| `src/executor/ssh.rs` | SSH remote operations | `SshExecutor`, `SshConfig` |
| `src/inventory.rs` | Shared host-inventory persistence: the one definition of where `~/.config/linux-hardener/hosts.toml` lives, read and written by both the CLI `batch` command and the desktop backend. The `HostsConfig` it moves is defined in `hardener-types`, not here. Writing goes through `config_write`, so a host joining or leaving the fleet is atomic and recorded; the audit descriptor is mandatory because only the caller knows which it was | `default_path()`, `load()`, `save_audited()` |
| `src/config_write.rs` | The one way this project writes a configuration file, and the one place it decides where this host's audit trail lives. `write_atomically` takes a `WriteAudit` and files the entry itself, so a config write that records nothing does not compile. Behind the `system` feature, since the audit log and the effective user are. Lives here rather than in `hardener-cli` because that crate is a binary and the desktop backend writes configuration too | `WriteAudit`, `write_atomically()`, `write_file_atomically()`, `read_or_empty()`, `effective_user()`, `audit_logger()`, `get_audit_logger()`, `logger_at()` |
| `src/config/tests.rs` | Unit tests for `src/config.rs` | Test-only; `super` resolves to `crate::config` |
| `src/config/scope/tests.rs` | Unit tests for `src/config/scope.rs`, 17 tests: the review interval over `ComplianceFramework::ALL` rather than over id strings, the expiry arithmetic including the deadline day itself, the four ways a date is missing or unparseable (each of which makes the exclusion invalid rather than perpetual), the host predicate in both directions and case-insensitively, and the TOML round trip with and without the section present | Test-only; `super` resolves to `crate::config::scope` |
| `src/config_loader/tests.rs` | Unit tests for `src/config_loader.rs` | Test-only; `super` resolves to `crate::config_loader` |
| `src/config_validation/tests.rs` | Unit tests for `src/config_validation.rs` | Test-only; `super` resolves to `crate::config_validation` |
| `src/context/tests.rs` | Unit tests for `src/context.rs` | Test-only; `super` resolves to `crate::context`. `SystemInfo`'s detectors and `read_os_release` are private, so `tests/context_tests.rs` cannot reach them |
| `src/plugin/tests.rs` | Unit tests for `src/plugin.rs` | Test-only; `super` resolves to `crate::plugin` |
| `src/inventory/tests.rs` | Unit tests for `src/inventory.rs` | Test-only; `super` resolves to `crate::inventory` |
| `src/config_write/tests.rs` | Unit tests for `src/config_write.rs`, 13 tests: the mode preservation and new-file arms of the writer, both arms of `read_or_empty`, the entry a successful write files, the entry a failed write files while the cause still reaches the caller, a write with no logger still landing, and the two audit-directory tests that moved here from `hardener-cli` with the function they exercise | Test-only; `super` resolves to `crate::config_write` |
| `src/executor/local/tests.rs` | Unit tests for `src/executor/local.rs`, 19 of them | Test-only; `super` resolves to `crate::executor::local` |
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
    // No default body since #142: every plugin must answer, so a ninth cannot
    // inherit an empty vector, which every renderer reads as "everything
    // checkable came back".
    async fn divergences_after_rollback(&self, ctx: &Context, restored: &[PathBuf]) -> Vec<RollbackDivergence>;
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
| `src/text.rs` | Shortens text to a column's budget, ellipsis included in the count. Lived twice until 2026-08-25, and the two copies disagreed about whether the marker was charged against the budget, so a parameter named `max_chars` returned `max_chars + 3` in the PDF renderer | `truncate_string()` |
| `src/executor/mod.rs` | Executor abstraction (trait + types) | `SystemExecutor`, `CommandOutput`, `FileMetadata` |
| `src/executor/mock.rs` | Virtual filesystem for unit testing | `MockExecutor` |
| `src/vendor_config.rs` | Resolves configuration a distribution layers across `/etc` and `/usr/etc`. `/usr/etc` is consulted only on absence positively confirmed at `/etc`, because an `/etc` file that exists but cannot be read is still the file the system obeys, and answering with the vendor copy would report a configuration that is not in force | `ConfigLayer`, `LayeredRead`, `read_layered()`, `vendor_path_for()` |
| `src/error/tests.rs` | Unit tests for `src/error.rs` | Test-only; `super` resolves to `crate::error` |
| `src/binary_utils/tests.rs` | Unit tests for `src/binary_utils.rs` | Test-only; `super` resolves to `crate::binary_utils` |
| `src/text/tests.rs` | Unit tests for `src/text.rs`, including that no budget from 0 to 40 is ever exceeded | Test-only; `super` resolves to `crate::text` |
| `src/vendor_config/tests.rs` | Unit tests for `src/vendor_config.rs` | Test-only; `super` resolves to `crate::vendor_config` |
| `src/file_utils/tests.rs` | Unit tests for `src/file_utils.rs`, the first of the two test modules that file carried | Test-only; `super` resolves to `crate::file_utils` |
| `src/file_utils/global_scope_tests.rs` | The second, kept under its own name: that a directive written at global scope is not confused with the same directive inside an sshd `Match` block | Test-only; `super` resolves to `crate::file_utils` |
| `src/executor/tests.rs` | Unit tests for `src/executor/mod.rs`, 32 of them | Test-only; that file *is* the module `executor`, so its tests go in the directory it already owns |
| `src/executor/mock/tests.rs` | Unit tests for `src/executor/mock.rs`, 15 of them | Test-only; `super` resolves to `crate::executor::mock` |

**Note**: Core types (Severity, FindingCategory, etc.) are now defined in `hardener-types` and re-exported here for backwards compatibility. The executor abstraction (`SystemExecutor`, `CommandOutput`, `FileMetadata`, `MockExecutor`) relocated here from `hardener-core` and is re-exported from that crate for source compatibility.

---

## hardener-plugins (Security Plugins)

| File | Purpose | Plugin Struct |
|------|---------|---------------|
| `src/lib.rs` | Module exports, helpers | `create_checkpoint_for_apply()`, `create_checkpoint_metadata_only_for_apply()`, `checkpoint_change()` (shared `ChangeType::Checkpoint` bookkeeping change), `reconcile_plugins_after_rollback()` (returns `RollbackReconciliation`: reload rows, then divergence rows), `create_plugin_registry()`, `compliance_coverage()` |
| `src/macros.rs` | Plugin definition macro, `#[cfg(test)]` since #142 and compiled for this crate's own tests only, its sole caller. The `divergences_after_rollback` it generates returns an empty vector, which reads at every renderer as everything checkable came back, so a plugin written through the macro would publish that claim with nothing but a comment to warn its author. Gating the module is what withdraws it: `#[macro_export]` puts a macro at the crate root of every downstream build whatever the module's visibility | `define_plugin!` |
| `src/scan_outcome.rs` | What this crate hands a compliance report: `plugin_inventory()`, every registered plugin paired with the coverage it declares, and `failed_scan()`, the stand-in result for a plugin whose scan errored. The flatten that used to live here moved to `hardener-compliance::scan_evidence`, behind `ReportGenerator::generate`, because being in front of the generator made it something every caller had to remember and one of them did not | `plugin_inventory()`, `failed_scan()` |
| `src/strictness.rs` | The one definition of which direction counts as stricter for a configuration value, shared by the pam, ssh and kernel plugins. Comparing a host's value against the baseline for equality has no direction, so a stricter host reads as violating and apply writes the baseline over it; every variant here carries a direction, and there is deliberately no equality variant to give a directive added later. Also the single place an operator's directive override is clamped, so an override can tighten a target but never relax it | `Strictness` (`AtMost`, `AtLeast`, `NonZeroAtMost`, `Ranked`), `clamp_target()`, `violated_by()`, `resolved_target()` |
| `src/shell_config.rs` | Reads the last value a key is assigned in a shell-sourced configuration file, the format ufw's own init scripts and defaults files use: `.`-sourced by `ufw-init-functions`, so the last assignment wins and a commented-out line is not an assignment at all. Shared by the firewall plugin's ufw backend and its rollback divergence probe | `shell_value()` |

### Individual Plugins

| Plugin File | Category | Key Checks |
|-------------|----------|------------|
| `src/ssh/mod.rs` | Network | PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, MaxAuthTries, X11Forwarding, ClientAliveInterval, ClientAliveCountMax |
| `src/ssh/dropin.rs` | Network | Writes SSH hardening to `/etc/ssh/sshd_config.d/00-hardener.conf`, which sorts before the fragments distributions ship, so sshd takes this file's values first. Precedence is verified after writing by re-resolving, never assumed from the filename, and an empty directive set removes the file rather than leaving an empty one | `DROPIN_PATH`, `Directive`, `render()`, `write_dropin()` |
| `src/ssh/include.rs` | Network | Resolves `Include` directives in sshd's own order, so scan reports the value sshd will actually use and names the file supplying it. sshd takes the **first** value it obtains and distributions put the Include above everything this tool writes, so a drop-in silently won while the tool reported its own write |
| `src/ssh/divergence.rs` | Network | What an sshd rollback left running against a configuration it could not reload onto (#142). `reload_after_rollback` restarts sshd unconditionally and reports a failed restart only as its own `Err`, never through this probe, so a restart that could not take otherwise leaves nothing here to read. Classifies `systemctl is-active`/`is-enabled` for the unit three ways rather than two, so an unrunnable systemctl call is never read as a clean state, and reports `Diverged` only where the unit is both running and masked, the one state proving the restart was refused outright. Measured 2026-08-10 in a booted arch container: masking sshd before a rollback left it reporting active before and after the restart attempt, previously unreported; this probe now reports that state and a second run confirmed it fires. Marks no row `divergence_expected` (#152), pinned by a test: every row here is a reload that did not take. Report-only; writes nothing | `sshd_divergences()` |
| `src/kernel/mod.rs` | Kernel | ASLR, kptr_restrict, dmesg_restrict, ptrace_scope, suid_dumpable, rp_filter, tcp_syncookies |
| `src/kernel/persistence.rs` | Kernel | Reports a managed parameter that a file applied after `99-hardener.conf` sets looser than its target, so hardening that will not survive the next reboot is named rather than assumed to hold. Report-only; the apply writes nothing for it | `procfs_key()`, `boot_persistence()` |
| `src/kernel/divergence.rs` | Kernel | What a kernel rollback left running that its restored files do not name (#138). After the rollback's `sysctl --system`, compares each managed parameter's running value against every surviving configuration file; where nothing names it, judged by strictness against the plugin's own baseline rather than by an equality this path has no `PluginConfig` to check against. An unreadable `/proc/sys` entry and an unresolved configuration source are each reported `Unverifiable` rather than guessed at, and every unresolved source gets a row of its own naming the file. Marks a row naming no surviving file `divergence_expected` (#152: a rollback never writes `/proc/sys`); a row naming `/etc/sysctl.conf` specifically stays unmarked even though it fires on every rollback of a host carrying that file, because the value is lost at the next reboot rather than kept. Report-only; writes nothing | `sysctl_divergences()` |
| `src/firewall/mod.rs` | Network | Firewall enabled, baseline rules |
| `src/firewall/nftables.rs` | Network | nftables backend |
| `src/firewall/firewalld.rs` | Network | firewalld backend |
| `src/firewall/ufw.rs` | Network | UFW backend |
| `src/firewall/divergence.rs` | Network | What a firewall rollback left enforcing that its restored files do not ask for (#139). ufw only: reads `ufw status` itself after the rollback's reload and classifies on its status line exactly, against the restored `ENABLED` flag in `/etc/ufw/ufw.conf`. firewalld restores a directory its own daemon re-reads, so the reload already converges it; nftables is #97, closed by #106. Marks ufw enforcing over a restored `ENABLED=no` `divergence_expected` (#152: a rollback never stops a running firewall); the reverse stays unmarked. Report-only; writes nothing | `firewall_divergences()` |
| `src/pam/mod.rs` | Auth | Password complexity, aging, lockout |
| `src/pam/login_defs.rs` | Auth | Carries a `/usr/etc` configuration file into `/etc` before the managed directives are edited into it, with the vendor file's own permissions rather than the temporary file's | `mode_for_copy_of()` |
| `src/pam/layer_drift.rs` | Auth | Reports the keys an `/etc` file hides from its `/usr/etc` counterpart, for every layered file the plugin reads rather than for `login.defs` alone | `LAYERED_CONFS`, `masked_keys()`, `masked_keys_finding()` |
| `src/services/mod.rs` | Services | Unnecessary services (xinetd, cups, avahi, etc.) |
| `src/services/divergence.rs` | Services | What a service-minimisation rollback left running that its restored unit files do not name (#142). `reload_after_rollback` only runs `systemctl daemon-reload`; it never starts, stops or restarts anything, so a unit `apply` had stopped stays stopped once its files are put back. For each managed unit still installed, reads `systemctl is-enabled`/`is-active`'s printed word directly (never the exit status `is_service_enabled`/`is_service_active` use for the apply path), three-ways classified so a state the probe does not recognise, including the five non-`enabled` states `is-enabled` exits zero for, is Unverifiable rather than a guessed enabled/disabled claim. The reading is available on any booted host, but no container this project can build could force a real divergence: `bluetooth.service`, the one safe candidate, was measured 2026-08-10 to go `failed` rather than `active` when a forced start was attempted, so this probe has never fired against a real one. Marks enabled-but-stopped `divergence_expected` (#152: the reload never starts a unit); not-enabled-but-running stays unmarked. Report-only; writes nothing | `service_divergences()` |
| `src/permissions/mod.rs` | FileSystem | Critical paths, SUID/SGID, world-writable. Where `/etc` holds nothing at all, `scan` reads the `/usr/etc` copy through `vendor_path_for()` and reports a violating vendor mode as a finding keyed on the `/etc` path, so the id stays `perm--etc-sudoers` while the title names the file in force. The vendor file is never written, so that finding's remediation is an install into `/etc`; `apply` is unchanged and still leaves a path absent from `/etc` alone | `PermissionCheck::VendorOnly`, `check_vendor_layer_permissions()`, `effective_directive()` |
| `src/audit/mod.rs` | Audit | auditd rules for time, users, permissions |
| `src/audit/divergence.rs` | Audit | What an audit rollback left the kernel's loaded rule set disagreeing with, on a host where that can be read at all (#142). Loading a kernel audit rule set is host-global, like an LSM policy, and `auditctl` cannot run in any container this project builds, measured twice (booted and unbooted) on 2026-08-10; even where it could, the comparison against a restored rules file is not implemented. Always reports one `Unverifiable` row naming #18, never `Diverged` and never an empty vector. That row is marked `divergence_expected` (#152): a stated ceiling rather than a probe that failed. Reporting only: shells out to `auditctl -l`, which lists the loaded rule set; nothing here loads, deletes or alters a rule | `audit_divergences()` |
| `src/mac/mod.rs` | MAC | SELinux/AppArmor status |
| `src/mac/divergence.rs` | MAC | What a MAC rollback left enforcing that its restored files do not ask for, on a host where that can be read at all (#142). Loading an LSM policy is host-global, so no container on the development machine can be given MAC enforcement. A detected SELinux or AppArmor system reports one `Unverifiable` row naming #18, never `Diverged`: an empty vector means "everything checkable came back" in this codebase, and this probe has not earned that claim there. That row is marked `divergence_expected` too (#152). A host with no MAC system detected reports nothing at all, the same way `firewall/divergence.rs` treats no firewall backend installed: genuinely nothing installed is not a divergence | `mac_divergences()` |
| `src/tests.rs` | Tests | Unit tests for the crate root | Test-only; reached the crate through `crate::` already, so no import changed |
| `src/reload_tests.rs` | Tests | Unit tests for `reconcile_plugins_after_rollback()` in `src/lib.rs`, against four stub plugins rather than any real plugin's `scan`/`apply`/`validate` | Test-only; reached the crate through `crate::` already, so no import changed |
| `src/audit/tests.rs` | Tests | Unit tests for `src/audit/mod.rs` | Test-only; `super` resolves to `crate::audit` |
| `src/audit/divergence/tests.rs` | Tests | Unit tests for `src/audit/divergence.rs` | Test-only; `super` resolves to `crate::audit::divergence` |
| `src/firewall/tests.rs` | Tests | Unit tests for `src/firewall/mod.rs`, 77 of them | Test-only; `super` resolves to `crate::firewall` |
| `src/kernel/tests.rs` | Tests | Unit tests for `src/kernel/mod.rs` | Test-only; `super` resolves to `crate::kernel` |
| `src/kernel/persistence/tests.rs` | Tests | Unit tests for `src/kernel/persistence.rs` | Test-only; `super` resolves to `crate::kernel::persistence` |
| `src/kernel/divergence/tests.rs` | Tests | Unit tests for `src/kernel/divergence.rs` | Test-only; `super` resolves to `crate::kernel::divergence` |
| `src/firewall/divergence/tests.rs` | Tests | Unit tests for `src/firewall/divergence.rs` | Test-only; `super` resolves to `crate::firewall::divergence` |
| `src/shell_config/tests.rs` | Tests | Unit tests for `src/shell_config.rs` | Test-only; `super` resolves to `crate::shell_config` |
| `src/mac/tests.rs` | Tests | Unit tests for `src/mac/mod.rs` | Test-only; `super` resolves to `crate::mac` |
| `src/mac/divergence/tests.rs` | Tests | Unit tests for `src/mac/divergence.rs` | Test-only; `super` resolves to `crate::mac::divergence` |
| `src/pam/tests.rs` | Tests | Unit tests for `src/pam/mod.rs` | Test-only; `super` resolves to `crate::pam` |
| `src/pam/layer_drift/tests.rs` | Tests | Unit tests for `src/pam/layer_drift.rs` | Test-only; `super` resolves to `crate::pam::layer_drift` |
| `src/pam/login_defs/tests.rs` | Tests | Unit tests for `src/pam/login_defs.rs` | Test-only; `super` resolves to `crate::pam::login_defs` |
| `src/permissions/tests.rs` | Tests | Unit tests for `src/permissions/mod.rs` | Test-only; `super` resolves to `crate::permissions` |
| `src/services/tests.rs` | Tests | Unit tests for `src/services/mod.rs` | Test-only; `super` resolves to `crate::services` |
| `src/services/divergence/tests.rs` | Tests | Unit tests for `src/services/divergence.rs` | Test-only; `super` resolves to `crate::services::divergence` |
| `src/ssh/tests.rs` | Tests | Unit tests for `src/ssh/mod.rs` | Test-only; `super` resolves to `crate::ssh` |
| `src/ssh/dropin/tests.rs` | Tests | Unit tests for `src/ssh/dropin.rs` | Test-only; `super` resolves to `crate::ssh::dropin` |
| `src/ssh/include/tests.rs` | Tests | Unit tests for `src/ssh/include.rs` | Test-only; `super` resolves to `crate::ssh::include` |
| `src/ssh/divergence/tests.rs` | Tests | Unit tests for `src/ssh/divergence.rs` | Test-only; `super` resolves to `crate::ssh::divergence` |
| `src/strictness/tests.rs` | Tests | Unit tests for `src/strictness.rs` | Test-only; `super` resolves to `crate::strictness` |

### Plugin Constants (Examples)

**SSH (ssh/mod.rs):**
```rust
const SSH_DIRECTIVES: &[SshConfigDirective] = &[
    SshConfigDirective { ssh_directive_name: "PermitRootLogin", ssh_secure_value: "no", ... },
    SshConfigDirective { ssh_directive_name: "PasswordAuthentication", ssh_secure_value: "no", ... },
    // ... 7 total
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
| `src/manager/tests.rs` | Unit tests for `src/manager.rs`, 54 of them | Test-only; `super` resolves to `crate::manager`, so imports carried across unchanged |
| `src/checkpoint/tests.rs` | Unit tests for `FileState::restore_mode_string`, the mode a rollback hands to `chmod`, 4 of them | Test-only; `super` resolves to `crate::checkpoint`. Added 2026-08-27 to close a hole this crate could not see: narrowing the mask left all 146 of its tests green while every rollback stripped setuid, setgid and sticky |
| `src/hash_chain/tests.rs` | Unit tests for `src/hash_chain.rs` | Test-only; same shape |
| `src/audit/tests.rs` | Unit tests for `src/audit.rs` | Test-only; same shape. `recover_chain` and `QueryFilter::matches` are private, so `tests/audit_tests.rs` cannot reach them |
| `src/scan_manager/tests.rs` | Unit tests for `src/scan_manager.rs` | Test-only; same shape. `current_timestamp` is private, so `tests/scan_manager_tests.rs` cannot reach it |
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
| `src/generator.rs` | Report generation. `generate` takes raw per-plugin scan results and flattens them itself through `scan_evidence`, so a caller cannot hand it a pair it flattened by hand; the private `score` beside it is the scoring pass the framework tests exercise. `new` takes a `PluginInventory` rather than a coverage union, because naming the plugins that produced no evidence needs to know who is missing | `ReportGenerator`, `new()`, `for_host()`, `generate()` |
| `src/scan_evidence.rs` | The unassessed-plugin rule, behind the generator rather than in front of it. A plugin that contributed nothing gets an `UncheckedCheck` carrying its whole declared coverage, so its controls report `ManualReview` instead of passing on the silence its own absence caused. `flatten` is public for callers that publish the list rather than score it (`batch scan` emits it as JSON and builds no report); that cannot weaken the rule, since scoring is only reachable through `generate` | `flatten()`, `Unassessed` |
| `src/profiles.rs` | Report-time profile ID translation (sourced RHEL 10 STIG V1R1 / CIS v1.0.1 tables) | `translate()`, `translate_all()`, `resolve_profile()`, `profile_label()` (re-export; defined in `hardener-types` so the WASM frontend can reach it too) |
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
| `src/generator/tests.rs` | Unit tests for `src/generator.rs` | Test-only; `super` resolves to `crate::generator`, so its imports carried across unchanged. They call `score` rather than `generate`, being about the scoring rules: `generate` would flatten first and add a stand-in for the plugin that declared their synthetic coverage and produced no result |
| `src/scan_evidence/tests.rs` | Unit tests for `src/scan_evidence.rs`, 11 tests: the coverage an incomplete scan carries, a disabled plugin not reading as a failed one, a full scan contributing nothing, an absent plugin being reported unassessed, disabled against uncovered, the three blockers, a result from an unknown plugin, both directions of an unenumerable registry, and the assessed set being a deduplicated union | Test-only; ported from `hardener-plugins/src/scan_outcome/tests.rs` with the flatten. They build their inventory by hand, so the assertions do not move when the real eight plugins change what they declare |
| `src/profiles/tests.rs` | Unit tests for `src/profiles.rs` | Test-only; `super` resolves to `crate::profiles` |
| `src/frameworks/iso27001/tests.rs` | Unit tests for `src/frameworks/iso27001.rs` | Test-only; `super` resolves to `crate::frameworks::iso27001` |
| `src/output/test_support.rs` | Fixtures shared by the formatter test modules, split out of `src/output/mod.rs` | Test-only; that file *is* the module `output`, so this sits in the directory it already owns and the formatter tests still reach it as `crate::output::test_support` |
| `src/output/tests.rs` | Unit tests for `ReportFormatter`'s own two defaults, 4 of them | Test-only; `super` resolves to `crate::output`. Added 2026-08-27: every formatter reached the defaults and none asserted them, so putting `format_all_bytes` back to the single-report indexing its doc records as the defect it fixed left the whole workspace green at 2277. That single-report method, `format_bytes`, was deleted the same day: nothing called it |
| `src/output/text/tests.rs` | Unit tests for `src/output/text.rs` | Test-only; `super` resolves to `crate::output::text` |
| `src/output/json/tests.rs` | Unit tests for `src/output/json.rs` | Test-only; `super` resolves to `crate::output::json` |
| `src/output/csv/tests.rs` | Unit tests for `src/output/csv.rs` | Test-only; `super` resolves to `crate::output::csv` |
| `src/output/html/tests.rs` | Unit tests for `src/output/html.rs` | Test-only; `super` resolves to `crate::output::html` |
| `src/output/pdf/tests.rs` | Unit tests for `src/output/pdf.rs` | Test-only; `super` resolves to `crate::output::pdf` |

---

## hardener-distro (Distribution Detection)

| File | Purpose | Key Exports |
|------|---------|-------------|
| `src/lib.rs` | `/etc/os-release` parsing and family mapping; the whole of the crate | `Distribution`, `DistroFamily` |
| `src/tests.rs` | Unit tests for the crate root, split out of `lib.rs` | Test-only; a crate root cannot become a directory, so `super` here means this file and its `use super::*` became `use crate::*` |

The crate held a `package/` module (a `PackageManager` trait over apt, dnf,
pacman and zypper) and an `adapter.rs` defining `DistributionAdapter`. Both were
deleted under issue #127 after a reference search found no user of either
anywhere in the tree, dependent crates included. The two symbols above are what
`src-tauri`, `hardener-cli` and `hardener-compliance` actually import, and they
are the whole public surface now.

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
| `src/db/tests.rs` | Unit tests for `src/db.rs`, 15 tests over the host-aware scan history | Test-only; `super` resolves to `crate::db`, so its imports carried across unchanged |
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
| `src/types.rs` | Re-exports from hardener-types, and nothing else. It defined `CheckpointInfo`, `CheckpointList`, `ScanSessionInfo`, `CheckpointDetail` and `CheckpointFileInfo` by hand until #157; those five now come from `hardener-types/src/checkpoint.rs`, so no type in the UI is a copy of a backend one | `pub use hardener_types::*` (ApplyResult, Change, ChangeType, CheckpointDetail, CheckpointFileInfo, CheckpointInfo, CheckpointList, ComplianceFramework, ComplianceMapping, ComplianceReport, ComplianceSummary, ConfigSummary, ControlResult, ControlStatus, FileRestoreAction, FileRestoreResult, Finding, FindingCategory, FindingPolicyException, PluginId, PluginMetadata, RollbackResult, ScanResult, ScanSessionInfo, Severity, UncheckedCheck, ValidationIssue, ValidationReport, WrittenException), scheduler re-exports (SchedulerUiConfig, NotificationUiConfig, EmailUiConfig, WebhookUiConfig, TestNotificationResult) |
| `src/state/mod.rs` | Reactive state | `AppState` (23 signals), `unchecked_tally()`, `SchedulerForm` (the lifted Scheduler-page form bundle, imported by `pages/scheduler_page.rs` and `components/notification_section.rs`) |
| `src/tauri_bindings.rs` | Tauri command bindings | `tauri_available`, `invoke_scan`, `invoke_deep_scan`, `invoke_apply`, `invoke_apply_dry_run`, `invoke_generate_report`, `invoke_export_report`, `invoke_get_latest_scan`, `invoke_get_checkpoints`, `invoke_create_checkpoint`, `invoke_delete_checkpoint`, `invoke_get_scan_history`, `invoke_get_scan_session`, `invoke_get_checkpoint_detail`, `invoke_rollback`, `invoke_list_remote_hosts`, `invoke_save_remote_host`, `invoke_delete_remote_host`, `invoke_connect_remote`, `invoke_disconnect_remote`, `invoke_remote_scan`, `invoke_fleet_scan`, `invoke_fleet_apply`, `invoke_fleet_rollback`, `invoke_get_host_history`, `invoke_list_plugins`, `invoke_get_scheduler_config`, `invoke_save_scheduler_config`, `invoke_test_notification`, `invoke_validate_config`, `invoke_pick_config_file`, `invoke_add_policy_exception`, `invoke_remove_policy_exception` (both called from the finding row's Accept/Remove control in `components/findings_tab.rs`) |
| `src/keyboard.rs` | Global keyboard event handler | Ctrl+1-5 page nav (`/`, `/analysis`, `/hardening`, `/fleet`, `/scheduler`; Ctrl+4 navigates straight to `/fleet`, not through the retained `/remote` redirect - Fleet Apply and Settings have no shortcut yet), Ctrl+Shift+S scan from anywhere, Alt+T theme cycle, Escape priority chain, F11 fullscreen |
| `src/navigation.rs` | Navigation signal helpers | Page routing helpers for keyboard and UI nav |
| `src/utils/mod.rs` | Utils module exports and preview/apply helpers | `annotate_preview()`, `PreviewDecision`, `apply_change_summary()`, `is_auth_cancelled()`, `parse_rate_limit_wait_secs()`, `unchecked_honesty_line()`, `apply_written_exception()`, `clear_exception()`, `PluginFinding`, `profile_badge_label()` (suppresses the `Generic` default, otherwise delegates to `hardener_types::profile_label`); `theme` mod |
| `src/utils/theme.rs` | Shared theme metadata plus the single apply/persist side effects; the only writer of `<html data-theme>` and the `theme` localStorage key | `THEMES` (7 themes), `apply_theme()`, `get_stored_theme()`, `store_theme()` |
| `src/utils/tests.rs` | Unit tests for `src/utils/mod.rs` | Test-only; that file *is* the module `utils`, so its tests go in the directory it already owns |
| `src/utils/theme/tests.rs` | Unit tests for `src/utils/theme.rs` | Test-only; `super` resolves to `crate::utils::theme` |
| `src/pages/mod.rs` | Pages module exports | `DashboardPage`, `AnalysisPage`, `HardeningPage`, `HostsPage`, `SchedulerPage`, `SettingsPage`, `FleetApplyPage` |
| `src/components/mod.rs` | Components module exports | All component re-exports, `Card`, `HeadingLevel` |

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
| `src/components/findings_tab.rs` | Findings tab wrapper for Analysis page; each row's detail carries an Accept/Remove-exception control, keyed per plugin id + `finding_exception_key` so two plugins keying on the same word cannot collide | `FindingsTab` |
| `src/components/exception_modal.rs` | The form that writes one finding's policy exception: required reason, optional approved-by/ticket/expires, rendered through the shared `Modal` | `ExceptionModal`, `ExceptionDraft` |
| `src/components/compliance_tab.rs` | Compliance framework selection and reports with status feedback | `ComplianceTab` |
| `src/components/configure_section.rs` | Profile selection and plugin toggles | `ConfigureSection` |
| `src/components/configure_section/tests.rs` | Unit tests for `src/components/configure_section.rs` | Test-only; `super` resolves to `crate::components::configure_section` |
| `src/components/segmented_control.rs` | Reusable WAI-ARIA segmented control (roving-tabindex radiogroup); shared by the Fleet Apply mode toggle and the Hardening protection-level control | `SegmentedControl` |
| `src/components/history_section.rs` | Apply results and checkpoint management with refresh button | `HistorySection` |
| `src/components/modal.rs` | Shared modal shell used by every dialog: backdrop, Escape and backdrop-click dismissal, dialog ARIA, and focus-on-mount. Swallows Escape so dismissing a dialog cannot also advance the global `keyboard.rs` priority chain and discard a pending apply review | `Modal` |
| `src/components/rollback_modal.rs` | Rollback confirmation modal for the Hardening History timeline (confirm, restoring, and per-file result stages) | `RollbackModal` |
| `src/components/card.rs` | Reusable card container component | `Card`, `HeadingLevel` |
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
pub async fn invoke_get_checkpoints() -> Result<CheckpointList, String>;
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
| `src/commands.rs` | Tauri invoke handlers | `run_scan`, `run_deep_scan` (pkexec-elevated sibling of run_scan), `run_apply`, `run_apply_dry_run`, `run_rollback`, `get_checkpoints`, `create_checkpoint`, `delete_checkpoint`, `get_checkpoint_detail`, `generate_compliance_report`, `export_compliance_report`, `get_scan_history`, `get_scan_session`, `get_host_history`, `list_plugins`, `get_latest_scan`, `list_remote_hosts`, `save_remote_host`, `delete_remote_host`, `connect_remote`, `disconnect_remote`, `run_remote_scan`, `scan_with_executor` (shared scan helper), `scan_fleet` (bounded-concurrent orchestrator), `run_fleet_scan`/`run_fleet_apply`/`run_fleet_rollback` (#[tauri::command]), `run_fleet_mutation`/`build_batch_args`/`parse_outcomes` (fleet-mutation helpers), `get_scheduler_config`, `save_scheduler_config`, `test_notification`, `validate_config`, `pick_config_file`, `exception_add_args` (flag-construction helper), `add_policy_exception`, `remove_policy_exception` |
| `src/validation.rs` | IPC input validation layer | `validate_ipc_string()`, `validate_plugin_ids()`, `validate_checkpoint_id()`, `validate_checkpoint_name()`, `validate_privileged_config_path()`, `validate_user_config_path()`, `validate_output_path()`, `validate_ssh_key_path()` |
| `src/acl_tests.rs` | Tests for per-command Tauri ACL scoping (SAM-039) | `#[cfg(test)]` ACL coverage |
| `src/decoration_tests.rs` | Unit tests for `desktop_is_tiling()` in `src/main.rs` | Test-only; `main.rs` is the crate root, so this sits beside it exactly as `acl_tests.rs` does |
| `src/validation/tests.rs` | Unit tests for `src/validation.rs` | Test-only; `super` resolves to `crate::validation` |
| `src/commands/fleet_tests.rs` | Fleet command tests, the first of the three test modules `src/commands.rs` carried | Test-only; `super` resolves to `crate::commands` |
| `src/commands/delete_escalation_tests.rs` | Tests for the guard deciding whether deleting a checkpoint is worth an authentication prompt | Test-only; `super` resolves to `crate::commands`. Takes the database path as a parameter so it runs the same on a host with a system database and one without |
| `src/commands/checkpoint_host_tests.rs` | Tests for `restorable_here`, the rule narrowing the checkpoint list to this host | Test-only; `super` resolves to `crate::commands`. Generic in what travels beside the checkpoint, so the rule is exercised with no database and no executor |
| `src/commands/fail_session_on_err_tests.rs` | Tests for `fail_session_on_err`, the helper that marks an aborted scan's history row Failed rather than orphaning it as running | Test-only; `super` resolves to `crate::commands` |
| `src/commands/compliance_source_tests.rs` | Tests for the compliance report's source selection | Test-only; `super` resolves to `crate::commands` |
| `src/commands/webhook_shape_tests.rs` | Tests that what the desktop writes to `[scheduler.notifications.webhooks]` is what `hardener-scheduler` reads back | Test-only; `super` resolves to `crate::commands`. This crate depends on both, so it is the only place the two shapes meet |
| `src/commands/exception_args_tests.rs` | Tests for `exception_add_args`, the flag-construction helper behind `add_policy_exception`: an absent optional field must add no flag, not an empty one | Test-only; `super` resolves to `crate::commands` |
| `src/commands/config_write_detail_tests.rs` | Tests for the audit detail the desktop's three in-process config writes carry, 12 tests: what the scheduler entry names, the scheduler being turned off, recipient addresses and the webhook URL staying out of the log, the host endpoint and operation, host-key checking being turned off, a profile naming no user, and six that drive `write_scheduler_config`, `upsert_host` and `remove_host` against a temporary inventory and log so each descriptor is observed reaching the writer (a save, an upsert replacing rather than appending, a delete taking only the named host, and a name matching nothing still recorded). Ceiling: the six detail tests still pass on an entry that is never filed, and nothing here pins which path `writable_config_path` or `inventory_path` picks | Test-only; `super` resolves to `crate::commands` |
| `src/commands/config_summary_tests.rs` | Tests for what the config picker card reports about a file it just loaded, 9 tests. The enabled set is the one that will actually run: it read each section's own `enabled` flag alone until 2026-08-25, where the real gate `is_plugin_enabled` also honours `global.disabled_plugins` and the `global.enabled_plugins` allow list, so a file running one plugin was reported as running eight. `every_section_id_resolves_to_its_own_section` pins the second half: the ids were short names, and a short name falls through `get_plugin_config`'s empty default, which reports enabled whatever the file says, so correcting the predicate alone would have broken the one case that worked | Test-only; `super` resolves to `crate::commands` |
| `src/commands/checkpoint_detail_tests.rs` | Tests for `checkpoint_to_detail`, the mapping behind the history expander's file list, 6 tests. `file_permissions` holds the whole `st_mode`, and the expander printed it unmasked under a column headed "permissions" until 2026-08-26, so a file captured at 0644 read `100644` and a directory at 0755 read `40755`. The mode now comes from `FileState::restore_mode_string`, the same function the rollback's `chmod` argument comes from, and `the_listed_mode_is_the_mode_rollback_would_chmod` asserts the two agree rather than asserting either against a literal. `the_setuid_setgid_and_sticky_bits_are_kept` is the guard on masking too narrowly. It was the **only** test in the tree that failed when the mask dropped to `0o777`, with all 146 `hardener-state` tests staying green while a rollback silently stripped setuid from every restored binary; `checkpoint/tests.rs` closed that on 2026-08-27, so the crate that owns the function now fails on its own | Test-only; `super` resolves to `crate::commands` |
| `src/commands/test_notification_tests.rs` | Tests for `test_notification_verdict`, the one line the settings pane shows after a test send, 6 tests. `send_test` returns one result per channel and this command is its only non-test consumer, so there is no CLI rendering to disagree with and the reference is the results themselves. Two things were dropped out of them until 2026-08-26: the `channel` each verdict belonged to, so a host with email and three webhooks read `Failed: connection refused` and could not tell which of the four, and any failure whose `error` was `None`, because the reasons came from a `filter_map` that drops a row it cannot describe. The second is unreachable today, `NotificationResult::failed` being the only constructor that sets `success: false` and always recording a reason, but the fields are `pub` and the failing direction reports a channel that did not deliver as one that did | Test-only; `super` resolves to `crate::commands` |
| `src/commands/export_destination_tests.rs` | Tests for `export_destination`, where a compliance export is written and when the path is refused, 7 tests. `hardener report` has refused an `--output` path whose extension names a different document since `refuse_extension_that_contradicts` was added; the desktop reached the same fork in-process and wrote the bytes, so choosing PDF and typing `audit.json` produced a PDF named `audit.json` and reported it saved. Both decide through `OutputFormat::contradicted_by` now, and only the decision is shared: the CLI's sentence names `--output` and a desktop operator has no flag to correct, which `the_refusal_names_no_command_line_flag` pins. `a_dated_stem_is_left_exactly_as_typed` guards the other direction, `q3.2026.08` having extension `08`, which names no document. The five-by-five sweep asserts 25 pairs and exactly 5 accepted outside its loop, because the per-pair assertion alone passes over a shortened array | Test-only; `super` resolves to `crate::commands` |
| `src/commands/apply_args_tests.rs` | Tests for `apply_args`, the argv `run_apply` and `run_apply_dry_run` share, 5 tests. The two commands built the same vector twice and differed in `--dry-run`, so after the merge that one flag is all that stands between a preview and a real modification of the host, and `dry_run_adds_the_flag_and_a_real_apply_does_not` is the test that goes red when it is dropped. The rest pin the verb and format both forms ask for, one repeated `--plugin` per id in order (`apply` drops an unmatched plugin name silently), an empty selection emitting no flag at all, and `--config` appearing only when there is one | Test-only; `super` resolves to `crate::commands` |
| `src/commands/history_limit_tests.rs` | Tests for `scan_history_rows`, the row count `get_scan_history` asks the database for, 5 tests. The command passed its `i32` argument to SQL's `LIMIT` untouched while its sibling `get_host_history` had clamped since it was written, so the one command with no ceiling was also the one that could be asked to remove it: `LIMIT -1` is unbounded in SQLite, and the argument that looks like the smallest possible request asks for every row in the table. A negative is refused rather than clamped, because reading it as 1 or as the default would turn an obviously wrong argument into a plausible answer. Zero is allowed and pinned, so the refusal is not read as a refusal of everything unhelpful, and `a_modest_request_is_passed_through` is what stops the clamp being satisfiable by a constant | Test-only; `super` resolves to `crate::commands` |
| `src/commands/scan_selection_tests.rs` | Tests for `scan_selection_refusal`, the refusal `run_scan` owes when the config disables every plugin the operator selected, 6 tests. `hardener scan` has always bailed on that state and said how to leave it; the desktop's local scan returned an empty result set, which the Analysis tab renders as "No findings yet. Run a Security Scan above", so an operator who had just run one was told to run one. The deep-scan button a few pixels away shells out to the CLI and inherited the refusal, so one host answered two ways. Three tests pin the refusal and its wording, which is the CLI's verbatim so the two messages read as one condition; three pin the states that must NOT be refused, including `scanned == 0` with nothing disabled, since an empty registry and a filter matching no plugin land there and have a different remedy. Both halves proved by mutation: dropping the config term reddens one, refusing never reddens the other three |

### Tauri Commands
```rust
pub async fn add_policy_exception(plugin_id: String,
    exception_key: String,
    reason: String,
    approved_by: Option<String>,
    ticket: Option<String>,
    expires: Option<String>,) -> Result<hardener_types::WrittenException, String>
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
pub async fn get_checkpoints() -> Result<CheckpointList, String>
pub async fn get_host_history(host: String,
    limit: Option<u32>,) -> Result<Vec<HostSessionInfo>, String>
pub async fn get_latest_scan() -> Result<Option<Vec<ScanResult>>, String>
pub async fn get_scan_history(limit: Option<i32>) -> Result<Vec<ScanSessionInfo>, String>
pub async fn get_scan_session(session_id: String) -> Result<Vec<ScanResult>, String>
pub async fn get_scheduler_config() -> Result<hardener_types::scheduler::SchedulerUiConfig, String>
pub async fn list_plugins() -> Result<Vec<PluginMetadata>, String>
pub async fn list_remote_hosts() -> Result<Vec<RemoteHostProfile>, String>
pub async fn pick_config_file(app: tauri::AppHandle) -> Result<Option<String>, String>
pub async fn remove_policy_exception(plugin_id: String,
    exception_key: String,) -> Result<(), String>
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
| `packaging/linux-hardener.spec` | RPM (Fedora/RHEL/openSUSE) spec file |
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
| `scripts/lib/common.sh` | Shared colours, box-banner helper, `resolve_target_dir`, the distro/container name tables sourced by the test runners and container tooling, and the three binary-identity questions (`workspace_version`, `binary_version_line`, `first_source_newer_than`) that the release-readiness and CLI walk runners both ask before trusting a container's output |
| `scripts/lib/parallel.sh` | Shared bounded-concurrency job pool for the `--parallel` cross-distro and Web UI GUI test runners |
| `scripts/screenshots/build.py` | Assembles the screenshot harness's `serve/` directory: a copy of the prebuilt `crates/hardener-ui/dist`, plus `gui-tests/tauri-mock.js` injected ahead of the WASM module so `is_tauri_available()` sees a runtime, plus an animation/transition killer so headless virtual time settles on a deterministic frame. Refuses when `dist/` is absent rather than serving an empty directory, since it cannot build the frontend and a missing one otherwise looks like a broken page |
| `scripts/screenshots/serve.py` | Localhost SPA server on port 8137 for that directory: unknown paths fall back to `index.html`, so the Leptos client-side router resolves `/analysis`, `/fleet-apply` and the rest |
| `scripts/screenshots/shoot.py` | Captures the seven static routes through `chromium --headless --screenshot`, trimmed to content height. Cannot reach a state behind a click, which is why `capture-docs.js` exists beside it |
| `scripts/screenshots/capture-docs.js` | Drives all 23 states `docs/assets/screenshots/` documents, at a fixed 1920x1080, with Playwright out of `gui-tests/node_modules`. Each shot names a `ready` selector that exists ONLY in the state it claims and fails when it never appears: twelve of the first run's twenty-three failed on selectors guessed from the previous corpus, and a capture step that clicked and hoped would have written a plausible PNG of the wrong screen |
| `scripts/screenshots/mock-scan.json` | Curated demo `get_latest_scan` payload, wire-shaped like `hardener_types::ScanResult`. Used by `shoot.py`'s route shots; `tauri-mock.js` answers that command itself for `capture-docs.js` |
| `scripts/screenshots/mock-reports.json` | Curated `generate_compliance_report` payload, real `ComplianceReport` JSON, regenerable with `hardener report --scenario all --report-format json --quiet` |
| `scripts/screenshots/README.md` | How to run the harness, and why its IPC fixture is `gui-tests/tauri-mock.js` rather than a copy of its own |
| `scripts/validate/validate_naming.py` | Naming convention validator |
| `scripts/validate/validate_all.py` | Master validation orchestrator |
| `scripts/validate/validate_cli_docs.py` | CLI command documentation validator |
| `scripts/validate/validate_compliance_docs.py` | Compliance framework documentation validator. Holds each `ComplianceFramework` variant to being the **subject** of a table row, its marker in the row's first cell, rather than appearing anywhere in the joined text of every pipe-carrying line |
| `scripts/validate/validate_cross_document_facts.py` | Cross-document fact validator: holds a fact stated in more than one document to the site that owns it, with the canonical source named per fact rather than always the evidence ledger. Of its six registered facts, only the GUI Playwright test count came from a confirmed survivor of the `crosscheck.py` sweep, which lives outside this repository; the compliance framework count predates that sweep, added from an earlier throwaway probe. The third, the GUI Playwright call-site count, was registered on 2026-08-20 for a different reason: the test count is sourced from the very document it validates, so it can only check that the consumers agree with the row and never that the row is true, and three documents called 156 current for two days after the suite reached 157 with this validator green throughout. Counting `test()` call sites in `gui-tests/tests/*.spec.js` puts the TREE behind the paragraph that states both numbers. It does not verify the case count and one shape defeats it, a parameterised site gaining cases without any call site moving. **That shape arrived on 2026-08-21**, when the theme sweep gained a sixth state and the suite went 158 to 165 with call sites unchanged at 117 and four documents stale, this validator green throughout. The fourth and fifth facts answer it where it is cheap to answer: `theme sweep states` counts the `STATES` array in `themes.spec.js`, and `theme sweep screenshots` multiplies it by the `THEMES` array in `helpers.js`, so it moves when either factor does. Together they hold eleven sites across four files. They do NOT give the case count a tree definition, and a differently parameterised site would still slip past; what they close is the ordinary way this particular sweep grows. The sixth, `registered sites`, is the only one whose canonical source is this file rather than the tree or a document: it sums the registry and holds the `All N registered sites` line in the Example Output block of `scripts/README.md`, which had gone stale at 4 sites and again at 6. It is deliberately self-referential, so registering it moved the number it reports from 17 to 18 in the same edit and turned itself red on the first run. Dated readings are deliberately never registered |
| `scripts/validate/validate_doc_attachment.py` | Loose doc comment validator: an undocumented free function beside a long doc block |
| `scripts/validate/validate_badges.py` | README badge validator |
| `scripts/validate/validate_changelog_headings.py` | CHANGELOG heading validator: no release entry repeats a change-type heading |
| `scripts/validate/validate_doc_links.py` | Markdown link validator: every link in a tracked `.md` must resolve for a reader who has only the repository, so a target that is missing or gitignored fails |
| `scripts/validate/validate_doc_targets.py` | Doc sync target validator |
| `scripts/validate/validate_file_map.py` | file-map.md accuracy validator |
| `scripts/validate/validate_policy_exception_sites.py` | Policy exception site registry |
| `scripts/validate/validate_gui_mock_fixtures.py` | GUI mock fixtures: every payload `gui-tests/tauri-mock.js` returns matches the Rust type the frontend deserialises it into, field for field, with enum-valued fields checked against the real variants. Obtained by running the mock rather than parsing it. A drift here empties a view and reads as a stale Playwright selector |
| `scripts/validate/validate_persisted_finding_fields.py` | Persisted finding fields: every field of the `Finding` rebuilt by `ScanHistoryManager::get_result_findings` must be read from its database row, not given a hardcoded default, unless a comment above it gives the reason. A dropped field compiles and passes any test that does not assert on it |
| `scripts/validate/validate_documented_exception_keys.py` | Documented exception keys: every key `docs/reference/configuration.md` names as one an operator types must exist as a string literal in `crates/hardener-plugins/src`. An exception whose key matches nothing never fires, so the host is hardened against a documented deviation and nothing reports it |
| `scripts/validate/validate_evidence_ledger.py` | Evidence ledger validator: every path `docs/reference/evidence-ledger.md` cites must exist, wherever in the file it sits, the Command and Ceiling cells and the prose included rather than the Evidence column alone. A row whose file was renamed or deleted keeps asserting coverage that is gone. The citations are also cross-checked against the ledger's structure, every capability row having to cite at least one path, because any non-empty count passes an existence test and a gutted table would otherwise report a smaller healthy number |
| `scripts/validate/validate_srcinfo.py` | `.SRCINFO` validator: the AUR reads it and never the PKGBUILD beside it, so the two must agree |
| `scripts/validate/validate_last_updated.py` | Last Updated timestamp validator |
| `scripts/validate/validate_plugin_docs.py` | Plugin documentation validator |
| `scripts/validate/validate_tauri_docs.py` | Tauri integration documentation validator |
| `scripts/validate/validate_write_sites.py` | File-creation site registry: every plugin call site that creates a file is classified on two questions, `ensured` or `exempt` for its parent directory and `declared` or `exempt` for its plugin's pre-apply checkpoint, each with a written reason; the `cp` sites are additionally asserted to copy with both `-p` and `--no-dereference` |
| `scripts/validate/validate_unit_state_reads.py` | Unit state read registry: every `systemctl is-enabled` call site declares whether it judges systemd's word or its exit status and why, with the declared answer cross-checked against whether the enclosing function reads `output.success()` |
| `scripts/validate/validate_test_assertions.py` | Test assertion reachability across the whole tree: every test function must reach an assertion on every path through its body, so a test cannot exit 0 having asserted nothing while still counting towards the suite total. A `match` with every arm asserting, an `if`/`else` chain ending in a bare `else`, and a `for` over a table written at the site (in the header, or bound just above by a non-`mut` `let` or `const`) all satisfy it; an `if` with no `else`, a loop over a `let mut` binding, and a loop over a table declared in another file do not |
| `scripts/validate/validate_contrast.py` | Colour contrast validator: the static half of contrast checking. Weighs every foreground and background pair `crates/hardener-ui/styles.css` declares together in one rule, across all seven themes, translucent fills included, each `rgba()` composited over every opaque `--bg-*` surface the theme declares and scored on the best of those ratios so that a failure holds whatever the real ancestor turns out to be. `--explain <selector>` prints every theme's figure for one pair instead of validating, and for an alpha background prints the spread from worst surface to best with each named, so a rendered reading from the browser half can be compared against what this file actually computes rather than against a number quoted from prose. Deliberately not every token against every surface. Disjoint from `gui-tests/tests/contrast.spec.js` only for OPAQUE declared fills, which this file weighs alone because they are fully determined on paper; a translucent fill is weighed by both, this one reporting the best surface available and the browser the one that actually painted. The boundary is `browserOwnsPairing` in `gui-tests/tests/contrast-math.js` |
| `scripts/validate/update_all_docs.py` | Batch documentation updater |
| `scripts/release/release.sh` | Automated version bumping and release |
| `scripts/dev/tauri-dev.sh` | Tauri development launcher |
| `scripts/test/full-test-suite.sh` | Complete validation suite, 28 sections recording 149 checks on a booted container under `--apply`. `suite_section_sizes` declares what each section records and `require_expected_total` refuses a run of the wrong size |
| `scripts/test/differential-suite.sh` | Differential harness: applies hardening, then asks `sshd -T`, `chage -l` and `stat -c %a` what the system enforces and compares that against `scan` (`--self-test` runs anywhere) |
| `scripts/test/run-cross-distro-tests.sh` | Non-interactive cross-distro test orchestrator (`--differential` swaps in the differential suite) |
| `scripts/test/root-test-suite.sh` | 36 root-level privilege tests |
| `scripts/test/manual-verification-test.sh` | Interactive verification tests |
| `scripts/containers/create-container.sh` | systemd-nspawn test containers for all six distros (`arch`, `debian`, `ubuntu`, `fedora`, `rhel`, `opensuse`) |
| `scripts/test/verify-rollback.sh` | Rollback verification for nspawn containers, in fourteen tests (TESTs 1-14; the 26-check reading below predates TESTs 10-14 and TEST 10 and TEST 11 need a booted pass): `sysctl.d` config file content, `sshd_config` backup and content restoration, directory mode restoration, `rollback --format json` producing a valid `RollbackResult`, multi-plugin checkpoint ordering, where two applies leave two checkpoints and a selective rollback has to be paired with its own apply rather than with whichever checkpoint is newest, and a pam directive (`PASS_MAX_DAYS` in `/etc/login.defs`, seeded to shadow's 99999 so the plugin's `AtMost 90` has to move it) read back by value and by file hash after the rollback, and the firewall, asked of whichever backend the plugin selects (ufw, nftables or firewalld) rather than an assumed one, covering both that backend's configuration and what the host is actually enforcing. The firewall arm asserts that a rollback never leaves the host less protected than it found it, which is the plugin's documented rule, rather than that the live state returns: where it does not return, that is #139, and TEST 8 asserts that the rollback's own JSON now reports it as a divergence rather than staying silent. TEST 8 removes TEST 1's baseline drop-in specifically so a surviving file does not name the seeded kernel parameter, then requires `rollback_divergences` to carry it as `Diverged`; and it reports the row count broken down by state so a real divergence and an unanswerable probe are never one number. TEST 9 is the ninth arm and the #140 case: it names a managed parameter in `/etc/sysctl.conf` with no drop-in surviving and requires the row to stay `Diverged` while saying that the rollback's own `sysctl --system` reads that file and the boot applier does not, rather than that no file names the parameter; it unlinks the path before writing its fixture and then restores whatever it found, link or file, because a redirect follows a symlink and would otherwise destroy a drop-in's content while backing up only the link, and would put the parameter in a directory the boot applier reads and so exercise a different branch of `sysctl_divergences` with all three assertions still passing (#144); and it skips by name where `/usr/lib/systemd/systemd-sysctl` is absent, because there the row is `Unverifiable` by design, a gate that asks about the machine the shell runs on while the probe asks about the machine the binary targets, which are the same machine only because no arm passes `--ssh` (#147). TEST 9 calls the counting helper three times, so the suite is 26 checks rather than 24; read green against the arch container on 2026-08-08, 26 of 26 with none failed and none skipped, replacing the 23-of-23 reading TEST 8 was added at. The first of those also reads one runtime kernel parameter, gated on a measured write probe because `/proc/sys` is the host's and read-only without a private network namespace; its runner passes `--private-network`, which makes the arm askable, and where it is absent the arm reports a named skip rather than a pass and the script exits 2 rather than 0 |
| `scripts/test/cli-walk/walk-lib.sh` | Capture library: `run_recipe` records argv, stdout, stderr and exit code per invocation, `walk_skip` records what could not be attempted so an omission never reads as a pass, `walk_write_index` renders the index, and `walk_write_diff_pointer` names which distributions disagree with arch after `walk_normalise` blanks paths and timestamps. The one total check is that a `--format json` recipe produced parseable JSON, and it flags rather than fails |
| `scripts/test/cli-walk/recipes.sh` | Data only: every invocation, tagged with the minimum tier it needs (`unprivileged`, `root`, `booted`, `ssh`) and whether it is safe to repeat across phases. `RUNTIME_ID`, `RUNTIME_SESSION`, `RUNTIME_OUT` and `RUNTIME_SSH` are sentinels the runners substitute |
| `scripts/test/cli-walk/coverage.sh` | Recurses `--help` and fails if any discovered command has neither a recipe nor a written skip, so a new subcommand cannot be added and walked past |
| `scripts/test/cli-walk/selftest.sh` | Proves the capture machinery before a walk trusts it: files written, a failing command captured rather than swallowed, a timeout recorded as 124, a literal pipe escaped in the index, and the diff pointer naming a real difference while ignoring paths and timestamps |
| `scripts/test/cli-walk/cli-walk-host.sh` | Runs the `unprivileged` tier against this host and refuses every other tier structurally, because `apply` on the development host is the one unrecoverable action available here |
| `scripts/test/cli-walk/cli-walk-inner.sh` | Runs inside one container as root across the five phases (`pristine`, `mutate`, `applied`, `restore`, `restored`), resolving runtime ids between them from the CLI's own JSON |
| `scripts/test/cli-walk/cli-walk-container.sh` | Recreates and walks all six containers with a bounded job pool, then runs the `ssh` tier last and alone against the booted fixture, and writes the cross-distribution diff pointer |
| `scripts/test/release-readiness-root.sh` | One root invocation for every suite an unprivileged session cannot start: the polkit matrix, then the cross-distro, differential, packaging and Web UI suites and the rollback readback. All six containers are destroyed and rebuilt before each suite that runs inside one, and the run refuses to start unless the musl binary matches the working tree by version, commit and modification time |

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
| `docs/reference/evidence-ledger.md` | Per-capability evidence: what each claim's tests actually ask, the command that reproduces the reading, and the ceiling on what it can show |
| `docs/reference/coverage-baseline.md` | Measured line coverage per crate and per file, what no test reaches at all, and the limitations of the measurement itself |
| `docs/reference/what-is-not-proven.md` | The release's stated limits, written for an operator: where this tool may well be correct and nothing has ever checked |

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
tree on **2026-08-28**, not a run total: a run also executes doctests and, for
`hardener-ui`, `wasm_bindgen_test` cases that no annotation count here covers.
Treat them as the size of each crate's declared test surface, and read the
workspace run itself for what passed.

The table covers the ten crates under `crates/` and sums to 2155. The eleventh
workspace member, `src-tauri`, carries 187 more, which is why the tree total the
evidence ledger records is 2342 and not this table's sum.

| Crate | Unit Tests | Integration Tests | Annotations |
|-------|------------|-------------------|-------------|
| hardener-common | `error.rs`, `file_utils.rs`, `binary_utils.rs`, `text.rs`, `vendor_config.rs`, `executor/mod.rs`, `executor/mock.rs` | `common_types.rs`, `error_tests.rs`, `file_utils_tests.rs`, `common/mod.rs` | 134 |
| hardener-compliance | `generator.rs`, `profiles.rs`, `frameworks/iso27001.rs`, `output/mod.rs`, and five of `output/`: `text.rs`, `json.rs`, `csv.rs`, `html.rs`, `pdf.rs` | `assessment_honesty.rs`, `config_tests.rs`, `framework_tests.rs`, `report_tests.rs` | 136 |
| hardener-state | `db.rs`, `hash_chain.rs`, `signing.rs`, `manager.rs`, `checkpoint.rs` | `audit_tests.rs`, `checkpoint_system.rs`, `db_tests.rs`, `scan_manager_tests.rs`, `signing_tests.rs`, `common/mod.rs` || 150 |
| hardener-distro | `lib.rs` | - | 5 |
| hardener-scheduler | `config.rs`, `db.rs`, `json_store.rs`, `runner.rs`, `daemon.rs`, `systemd.rs`, `notification/*.rs` | - | 107 |
| hardener-cli | `cli.rs`, `output.rs`, `ssh_config.rs`, and thirteen of `commands/`: `apply.rs`, `batch.rs`, `checkpoint.rs`, `exception.rs`, `exception/document.rs`, `history.rs`, `plugin_filter.rs`, `privilege.rs`, `report.rs`, `report_wizard.rs`, `scan.rs`, `scope.rs`, `state.rs`, `systemd.rs` | `batch_ssh_integration.rs` (live-sshd, `#[ignore]`), `ssh_refusal.rs` (drives the built binary), `config_flag.rs` (drives the built binary), `quiet_output.rs` (drives the built binary), `output_artefacts.rs` (drives the built binary), `scope_tests.rs` (drives the built binary) | 328 |
| hardener-plugins | `lib.rs`, `strictness.rs`, `scan_outcome.rs`, `shell_config.rs`, and all eight plugin modules (`ssh/dropin.rs`, `ssh/include.rs`, `kernel/divergence.rs`, `firewall/divergence.rs`, `ssh/divergence.rs`, `mac/divergence.rs`, `services/divergence.rs` and `audit/divergence.rs` also carry their own) | `*_tests.rs` (8 files), `*_mock_tests.rs` (8 files), `ssh_integration_tests.rs`, `common/mod.rs` | 853 |
| hardener-core | `config.rs`, `config/scope.rs`, `config_loader.rs`, `config_validation.rs`, `plugin.rs`, `inventory.rs`, `executor/local.rs`, `executor/ssh.rs` | `config_env_precedence.rs`, `config_tests.rs`, `context_tests.rs`, `inventory_shared_path.rs`, `mock_executor_tests.rs`, `plugin_manager_tests.rs`, `registry_tests.rs`, `ssh_executor_tests.rs` | 243 |
| hardener-types | `lib.rs`, `remote.rs`, `scheduler.rs` | - | 66 |
| hardener-ui | `utils/mod.rs`, `utils/theme.rs`, `pages/fleet_apply_page.rs`, `components/configure_section.rs`, `components/adhoc_host_input.rs` | - | 133 |

### Executor and Mock Test Files

Added with the executor abstraction in v0.3.0 and grown considerably since;
counts measured the same way and on the same date as the table above.

| File | Purpose | Annotations |
|------|---------|-------------|
| `hardener-core/tests/inventory_shared_path.rs` | `load`/`save` against the shared inventory path | 2 |
| `hardener-core/tests/mock_executor_tests.rs` | MockExecutor unit tests | 15 |
| `hardener-core/tests/ssh_executor_tests.rs` | SshExecutor unit/integration tests | 17 |
| `hardener-plugins/tests/*_mock_tests.rs` | Mock-based plugin tests (8 files) | 439 |
| `hardener-plugins/tests/ssh_integration_tests.rs` | Plugin SSH integration tests | 14 |

---

## GUI Tests (Playwright + Desktop)

**157 Playwright tests target the Web UI across every distro in `DISTRO_ORDER`, green on all six at 157 of 157 on 2026-08-20** against `hardener 1.5.1 (2bc8bd76)`, none failed, none skipped, none flaky, in 2.9 to 4.5 minutes each, one worker and no name filter. The readings behind that figure follow, and this paragraph led with the superseded 114 until 2026-08-16. The suite was previously green on all six on 2026-08-08, 114 of 114 each, in 1.7 to 2.4 minutes against the 600 s ceiling the whole investigation began with the suite exceeding. That reading replaces a 113 figure from 2026-06-29 which had gone stale in both directions: the suite had been rewritten, and it failed on all six on 2026-08-07 for reasons that were environmental rather than about the interface. Those are recorded in [distribution-validation.md](distribution-validation.md#gui-test-suite-2026-08-08) and in issue #48. **The 114 figure is itself now stale.** `gui-tests/tests/settings.spec.js` (T-SET-01..08, 8 tests) and the `gui-tests/output-dir.js` helper landed later, in `dddb7651`, and `hardening.spec.js` gained its `T-DIVG-*` divergence tests (`3b3dc293`) after the 2026-08-08 reading as well. `npx playwright test --list` reports **157 tests in 11 files**, which is the count the 2026-08-20 run executed; it supersedes the 156 of 2026-08-18, the 154 of 2026-08-16, the 114-of-114 result above and the 152-of-152 reading of 2026-08-15. The one added since is `T-DASH-11`, on the excluded annotation; the two before it were `T-FLEET-10` and `T-SCHED-07`, written on 2026-08-18 and run for the first time the same day. Separately from the Web UI suite, **89 desktop checks validate the Tauri app** through `scripts/test/run-desktop-tests.sh`, 43 in `tauri-ux-test.sh` and 46 in `tauri-functional-test.sh`, and **`gui-tests/run-tests.mjs` carries 29 checks** over keyboard navigation, themes, ARIA, clipboard and the TabBar. Those three figures are counts of distinct check names in the sources, not readings: unlike the 157, **no dated run of any of them is recorded anywhere in this repository**. They read 95 and 21 until 2026-08-16, and nothing had ever checked them. The `tauri-ux-test.sh` row in the table below read 49 until 2026-08-16, contradicting the 43 here and the 89 both figures sum to: that correction reached this paragraph and not the row.

**The per-file rows in the table below no longer sum to the measured total.** Adding the id ranges each row states, with `themes.spec.js`'s 35 generated screenshots and `T-DIVG-03`'s two widths counted, gave 149 against the 154 of 2026-08-16 and gives 151 against the 156 of 2026-08-18. The 154 is the measured figure and the rows are hand-written, so it is the rows that have drifted, not the total. **Which rows is not recorded here because it was not measured**: re-derive them from `npx playwright test --list` rather than by arithmetic.

### Test Files

| File | Purpose |
|------|---------|
| `gui-tests/package.json` | npm dependencies (Playwright) |
| `gui-tests/playwright.config.js` | Playwright configuration (base URL, browser, timeouts) |
| `gui-tests/tauri-mock.js` | Tauri IPC mock (`window.__TAURI__`) covering all IPC commands |
| `gui-tests/spa-server.py` | SPA-aware HTTP server (port 8787, client-side routing) |
| `gui-tests/run-tests.mjs` | Node.js Playwright test orchestrator (29 checks: keyboard nav, themes, ARIA, clipboard, TabBar). Runs headed against a live dev server on `127.0.0.1:1420`, so it is not part of the container suite and no dated run of it is recorded |
| `scripts/test/gui/tauri-functional-test.sh` | Hyprland-based functional tests (46 tests: scan, apply, checkpoints, scheduler, remote, themes) |
| `scripts/test/gui/tauri-ux-test.sh` | Hyprland-based UX tests (43 tests: keyboard nav, tab bars, detail panels, fullscreen, skip link) |
| `gui-tests/debug-tabs.mjs` | Tab system debugging helper |
| `gui-tests/tests/helpers.js` | Shared test helpers and utilities |
| `gui-tests/tests/dashboard.spec.js` | T-DASH-01..09 (9 tests): score, scan trigger, navigation, activity |
| `gui-tests/tests/analysis.spec.js` | T-FIND-01..11, T-COMP-01..08, T-EXC-01..05 (24 tests): findings, compliance and finding-row exception authoring |
| `gui-tests/tests/hardening.spec.js` | T-CONF-01..10, T-HIST-01..06, T-APPLY-01..04, T-DIVG-01..05 (26 tests): configure, history, what an executed apply produces, and the rollback modal's divergence section. T-DIVG-03 is parameterized over two widths (`-wide`, `-narrow`), so the five DIVG ids run as 6 tests |
| `gui-tests/tests/themes.spec.js` | T-THEME-01..09 (9 tests + 42 screenshots): all 7 themes. T-THEME-08 covers High Contrast and reads `body`'s computed colours as well as the attribute, because a beaten cascade renders as no theme and still carries the attribute; T-THEME-09 holds the selector's option list against this file's own list, so the next theme added cannot arrive uncovered. The 42 are generated at collection time from 6 states x 7 themes, the sixth being the rollback modal so that `.modal` is weighed in every theme rather than in one |
| `gui-tests/tests/errors.spec.js` | T-ERR-01..04 (4 tests): error handling and dismiss |
| `gui-tests/tests/contrast.spec.js` | T-CONTRAST (7 tests, one per theme): the computed-cascade half of contrast checking (#158). Asks the page which rules matched a rendered element, reads the real colour and the real backdrop off `getComputedStyle`, and weighs those, so it reaches the rules whose background comes from an ancestor that `validate_contrast.py` still cannot resolve. Compositing is no longer what separates the two halves: the static file composites an `rgba()` fill over every opaque `--bg-*` surface the theme declares and takes the best of those ratios, where this one resolves the one real ancestor off the computed cascade. Since 2026-08-20 its scope is colour-only rules AND rules whose declared fill renders translucent, the latter being where the static file has only a ceiling; opaque declared fills stay out of reach here by design. Carries a second vacuity guard for that widening, because the colour-only pairings alone clear `MINIMUM_PAIRS`. Drives 13 routes, 11 of them into a state the default fixture does not produce (a scan, an apply under `apply_mode=mixed`, a failed export under `error_mode=export`, a failed exception write under `error_mode=exception`, two fleet states, three fleet-apply states, a rollback modal and a fleet scan held mid-flight by `fleet_scan=hold`, which is the only way to reach the live-progress glyphs `host_row.rs:86` draws while `scanning` is true). This cell said FIVE from the day five was right until 2026-08-21, through three separate route additions, because a count in prose had no tree definition; it is registered in `validate_cross_document_facts.py` as of 2026-08-21 and the tree now turns it red. The twelfth is the executed ROLLBACK of the fleet apply page, added because `.fleet-glyph-ok` had been recorded as reasoned-about rather than measured on the assumption that reaching it needed a third host in the fixture: `fleet_rollback_cells` reaches it on the default two, since the mock's rollback handler fails no host. Two routes open a modal, the first to do so, and are the only ones carrying a `scope` that confines the sweep to `.modal`, since `.modal-backdrop` is an overlay and not an ancestor, so the dimmed page behind a dialog would otherwise be measured as though undimmed; both are in `MUST_REACH`, since coverage bought with a flag is coverage a flag can silently remove. The selector list is derived from the stylesheet at run time rather than curated; failures are reported every run and only those absent from `DEFERRED` fail, matching the static file's precedent |
| `gui-tests/tests/contrast-math.js` | The WCAG arithmetic behind `contrast.spec.js`: relative luminance, contrast ratio, source-over compositing of a translucent backdrop stack, which it no longer holds alone now that `validate_contrast.py` composites against declared surfaces, and the large-text threshold. Also holds `browserOwnsPairing`, the rule dividing the two contrast checks, which lives here for the same reason the arithmetic does: the spec it serves runs only inside nspawn, so a boundary asserted there could not be checked on a development host. Split out so it can be proved without a browser; `node gui-tests/tests/contrast-math.js` runs a self-check whose oracle is #158's own hand measurements |
| `gui-tests/tests/fleet.spec.js` | T-FLEET-01..10 (10 tests): Fleet scan view, including the expanded host's persisted history rail |
| `gui-tests/tests/fleet-apply.spec.js` | T-FAPPLY-01..09 (9 tests): Fleet Apply mode toggle, selection and confirm modal |
| `gui-tests/tests/remote.spec.js` | T-REMOTE-01..03 (3 tests): the `/remote` redirect, the saved host list, the Add Host form |
| `gui-tests/tests/scheduler.spec.js` | T-SCHED-01..07 (7 tests): Scheduler and notification configuration, and the two notes shown only while scheduled scanning is off |
| `gui-tests/tests/settings.spec.js` | T-SET-01..08 (8 tests): the Settings page, the Appearance theme swatch grid (`ThemePicker`'s roving-tabindex keyboard nav and `aria-checked` state), and the About block's version/build identity |
| `gui-tests/output-dir.js` | Per-distro output/report path helper (`test-results/<distro>`, `test-reports/<distro>.json`), required by `playwright.config.js` and `tests/helpers.js` so the two do not disagree about the path |

### Runner Scripts

| File | Purpose |
|------|---------|
| `scripts/test/gui/run-gui-tests.sh` | Host orchestrator for Web UI tests across all distros |
| `scripts/test/gui/gui-test-inner.sh` | Container inner script (SPA server + headless Playwright, no X server); dynamically generates `index.html` at serve-time by stripping SRI `integrity` attributes and injecting `tauri-mock.js` into the built `dist/index.html` |
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

**Last Updated**: 2026-08-28
