# Plugin authoring guide

**Last Updated**: 2026-07-19

How to write a new hardening plugin. The 8 existing plugins in
`crates/hardener-plugins/src/` are the best worked examples; this page
explains the contract they all follow, so a new plugin fits the engine, the
CLI, the desktop app, remote (SSH) targets, and the compliance reports
without special-casing.

---

## The HardeningPlugin trait

Every plugin implements `HardeningPlugin`
(`crates/hardener-core/src/plugin.rs`). It is an `async_trait` behind the
`system` feature, and implementations must be `Send + Sync`:

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

The lifecycle is: registration, dependency resolution (dependencies are
topologically ordered and processed first), `scan()`, `validate()` (dry-run),
`apply()`, and `rollback()` when a restore is requested.

Per-method contract:

- **`metadata()`**: returns `PluginMetadata` (`plugin_id`, `plugin_name`,
  `plugin_version`, `plugin_description`, `plugin_category`). The
  `define_plugin!` macro in `crates/hardener-plugins/src/macros.rs` generates
  the struct, `metadata()`, and `dependencies()` from a declaration block, so
  new plugins only hand-write the four async methods.
- **`dependencies()`**: plugin IDs that must run before this one. Most
  plugins return an empty list.
- **`scan()`**: read-only. Must never modify the system. Returns a
  `ScanResult` with the list of findings; set `scan_success` and populate
  `scan_error` instead of returning `Err` for degraded-but-usable outcomes.
  When a check cannot be evaluated (privilege-blocked, such as a root-only
  file, or not applicable on this host), emit an `UncheckedCheck` into
  `scan_unchecked` rather than a false finding: the CLI renders these dimmed
  and deduplicated under the plugin name with a sudo hint, `--format json`
  carries them in an `unchecked` array, and compliance maps a
  covered-but-unchecked control to ManualReview instead of a false Pass or
  Fail.
- **`validate()`**: the dry-run. Reports what apply would change without
  touching anything.
- **`apply()`**: creates a checkpoint first (see below), then makes changes.
  Each change is recorded as a `Change` entry in the `ApplyResult`;
  `apply_success` should reflect whether every real change succeeded. Apply
  is state-aware and idempotent: a setting already at its target is recorded
  as a `ChangeType::Skipped` no-op (no backup, no config rewrite, no service
  restart), and the pre-apply checkpoint is a `ChangeType::Checkpoint`
  bookkeeping entry. The `ApplyResult` count helpers
  (`applied_change_count`, `failed_change_count`, `skipped_change_count`)
  exclude both, so "N change(s) applied" only ever counts genuine hardening
  successes and a no-op plugin reads "no changes needed".
- **`rollback()`**: restores the plugin's files from the given checkpoint.
  The shared helper `hardener_plugins::rollback_files_from_checkpoint`
  handles the common restore-files pattern; add service restarts after it if
  the subsystem needs them.

## Always go through the executor

Plugins must never touch the filesystem or spawn processes directly. All
system access goes through `ctx.executor()`, which returns the context's
`SystemExecutor` (`hardener-common`, re-exported from
`hardener_core::executor`):

```rust
let content = ctx.executor().read_file(Path::new("/etc/ssh/sshd_config")).await?;
let out = ctx.executor().execute_command("sysctl", &["-n", "kernel.sysrq"]).await?;
```

The trait offers `read_file`, `read_file_optional`, `write_file`,
`path_exists`, `file_metadata`, `read_dir`, `execute_command`, and
`command_exists`. Because the executor is the only system boundary, the same
plugin code runs locally (`LocalExecutor`), against remote `--ssh` targets
(`SshExecutor`), and in unit tests (`MockExecutor`) with zero changes. A
direct `std::fs` call would silently read the local machine while scanning a
remote host: that is the bug this rule exists to prevent.

## Checkpoints before changes

`apply()` must capture state before writing, using the shared helper:

```rust
let checkpoint_id =
    crate::create_checkpoint_for_apply(ctx, "my-plugin-pre-apply", &paths).await?;
```

The checkpoint name **must** be `{plugin_id}-pre-apply`: `hardener batch
rollback` derives the name from the plugin ID to select the checkpoint, and a
mismatch makes fleet rollback a silent no-op for that plugin. The helper
returns `Ok(None)` when no checkpoint manager is configured (some test
contexts); record the returned ID in `apply_checkpoint_id`, and append the
bookkeeping entry with
`changes.extend(crate::checkpoint_change(&checkpoint_id))` so the admin sees a
rollback point exists. That entry is typed `ChangeType::Checkpoint`, which the
count helpers exclude, so capturing a checkpoint never inflates the
applied-change total. For plugins that only change modes or ownership,
`create_checkpoint_metadata_only_for_apply` captures mode/uid/gid without
file contents.

## Graceful skip for absent subsystems

If the subsystem a plugin manages is not present on the host, `apply()` must
skip successfully, not fail. The MAC plugin
(`crates/hardener-plugins/src/mac/mod.rs`) is the reference: when neither
SELinux nor AppArmor is detected it records a `ChangeType::Skipped` "nothing
to configure (skipped)" change with `change_success: true` and returns
`apply_success: true`, because many distributions legitimately ship without a
MAC system. `ChangeType::Skipped` keeps the no-op out of the applied-change
count, so the plugin honestly reads "no changes needed". Reserve
`apply_success: false` for a subsystem that is present but genuinely broken.

## Policy exceptions

Before enforcing a check in `apply()`, honour configured exceptions:

```rust
if let Some(exception) = config.has_valid_exception("selinux-enforcing") {
    // record a skipped Change mentioning exception.reason
}
```

`has_valid_exception` already filters out `allowed = false` and expired
entries. See the [configuration reference](../reference/configuration.md)
for the user-facing format.

## Compliance coverage

Each plugin module exports a free function:

```rust
pub fn coverage() -> Vec<ComplianceMapping> { ... }
```

listing every `(framework, control_id)` the plugin's findings can assess.
`hardener_plugins::compliance_coverage()` aggregates and deduplicates all
plugin coverage and is injected into the report generator: a control present
there can report Pass/Fail, one absent is reported as ManualReview rather
than fabricated as passing. Two consequences for authors:

- If your findings map to a framework control, declare it in `coverage()` and
  attach the same mapping to the findings (`finding_compliance`), or reports
  will show ManualReview for a control you actually assess.
- Never declare coverage you do not scan: that would turn an unassessed
  control into a false Pass.

Plugins keep canonical control IDs (RHEL 8 STIG V-IDs, distribution-neutral
CIS numbering); profile-specific translation (for example RHEL 10) happens at
report time in `hardener-compliance`, not in plugins.

## Naming conventions

Struct fields carry their type as a prefix, enforced by
`scripts/validate/validate_naming.py`: `Finding` fields are `finding_id`,
`finding_severity`, `finding_title`, `finding_current_value`,
`finding_recommended_value`, `finding_remediation_steps`, and so on;
`ScanResult` fields are `scan_*`, `ApplyResult` fields `apply_*`, `Change`
fields `change_*`. Plugin IDs are kebab-case (`kernel-hardening`,
`service-minimisation`). Full rules:
[naming conventions](../reference/naming-conventions.md).

## Registration

Add the plugin to `create_plugin_registry()` in
`crates/hardener-plugins/src/lib.rs`, alongside a `pub use` for the type and
its `coverage()` entry in `compliance_coverage()`. The registry is the single
factory used by the CLI, the Tauri backend, and tests, so one registration
makes the plugin visible everywhere (`hardener plugins`, scan, apply, the
desktop plugin list). Also give the plugin a config section: a field on
`HardenerConfig` plus its mapping in `get_plugin_config()`
(`crates/hardener-core/src/config.rs`), and document the section in the
[configuration reference](../reference/configuration.md).

## Tests

Each plugin ships two integration test files in
`crates/hardener-plugins/tests/`:

- **`<plugin>_mock_tests.rs`**: deterministic unit-style tests using
  `MockExecutor` (`hardener-common`). Seed virtual files and command outputs,
  run the plugin against a `Context::with_executor(Arc::new(mock))`, and
  assert on findings and on the executor's call log:

  ```rust
  let executor = MockExecutor::new()
      .with_file("/etc/ssh/sshd_config", "PermitRootLogin no\n")
      .with_command("systemctl", &["is-enabled", "sshd"], CommandOutput {
          stdout: "enabled\n".into(),
          stderr: String::new(),
          exit_code: 0,
      });
  ```

- **`<plugin>_tests.rs`**: tests against the real local system, restricted to
  read-only behaviour or guarded so they are safe outside containers.

Destructive apply/rollback verification belongs in the containerised suites
(`scripts/test/root-test-suite.sh` inside an nspawn container), not in
`cargo test`. Before submitting: `cargo fmt --all`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`, and the validators in `scripts/validate/`
(see [testing](testing.md) and [documentation](documentation.md)).
