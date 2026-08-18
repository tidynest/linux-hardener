# Plugin authoring guide

**Last Updated**: 2026-08-18

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
    async fn scan(&self, ctx: &Context, config: &PluginConfig) -> Result<ScanResult>;
    async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult>;
    fn reloads_for_path(&self, path: &Path) -> bool { false }
    async fn reload_after_rollback(&self, ctx: &Context) -> Result<Option<String>> { Ok(None) }
    async fn divergences_after_rollback(&self, ctx: &Context, restored: &[PathBuf]) -> Vec<RollbackDivergence>;
    async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport>;
}
```

The lifecycle is: registration, dependency resolution (dependencies are
topologically ordered and processed first), `scan()`, `validate()` (dry-run),
`apply()`, and then, after a checkpoint restore, `reload_after_rollback()`
when the restore touched one of this plugin's paths, followed by
`divergences_after_rollback()`, which is asked of every plugin whether the
restore touched its paths or not. There is no plugin-level rollback method:
restoring files is `CheckpointManager::rollback`'s job (see
`docs/reference/data-flow.md`), and a plugin only re-enters the picture to
tell the running system to pick the restored files back up, and to say what
picking them back up did not fix.

Per-method contract:

- **`metadata()`**: returns `PluginMetadata` (`plugin_id`, `plugin_name`,
  `plugin_version`, `plugin_description`, `plugin_category`). All eight
  plugins hand-write it, along with `dependencies()`, `scan()`, `apply()`,
  `validate()` and `divergences_after_rollback()`; `reloads_for_path()` and
  `reload_after_rollback()` are the only opt-in overrides with defaults. The
  `define_plugin!` macro in `crates/hardener-plugins/src/macros.rs`, which
  used to generate the struct, `metadata()` and `dependencies()` from a
  declaration block, is `#[cfg(test)]` since #142 and generates this crate's
  test plugins only: the `divergences_after_rollback` it writes returns an
  empty vector, which is exactly the unearned "everything checkable came
  back" that deleting the trait default was meant to stop a plugin claiming
  by accident. Gating the module is what withdraws it, because
  `#[macro_export]` would otherwise put the macro at the crate root of every
  downstream build regardless of the module's visibility.
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
  Fail. A file missing from `/etc` is neither of those things until the vendor
  layer has been asked as well (see "Read the layer that is in force" below).
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
  **A step that fails after the first change is recorded sets
  `change_success: false` on that step and carries on building the result; it
  does not return `Err`.** This is the same rule `scan()` has above, and it is
  written here because it was not: the firewall plugin propagated a failed
  enable with `?` and left no `ApplyResult` at all, so the checkpoint id, the
  change list and every exception the operator had declared went with it. `Err`
  is for a failure that reaches the caller before any change exists, such as the
  pre-apply checkpoint, where there is nothing to report and nothing to roll
  back to. Where a failure makes the remaining work impossible rather than
  merely failed, record the one cause and return the result early: a list of
  failures for steps that were never reached says the wrong thing.
- **`reloads_for_path()`**: answers whether a rollback that restored `path`
  needs this plugin to reload. Defaults to `false`. Implement it when the
  plugin owns a file a running service only re-reads on request, so the
  restored bytes and the running configuration would otherwise disagree
  until the next reboot.
- **`reload_after_rollback()`**: re-reads configuration this plugin owns,
  after a rollback restored it, and returns what was done for the operator
  (`Some("sshd restarted")`); `None` means there was nothing to reload.
  Defaults to `Ok(None)`. Six plugins implement both methods (kernel, ssh,
  firewall, audit, services, mac); pam and permissions take the defaults,
  because their changes take effect immediately and there is nothing left to
  reload. `hardener_plugins::reconcile_plugins_after_rollback` is the caller:
  it maps a rollback's successfully restored paths onto plugins via
  `reloads_for_path()`, reloads each matching plugin once, and returns a
  `RollbackReconciliation` (`reloads`, `divergences`) the caller writes onto
  `RollbackResult`.
- **`divergences_after_rollback()`**: asks this plugin's own subsystem, after
  its reload has run, what still disagrees with the configuration the
  rollback just restored. Returns a `Vec<RollbackDivergence>`, one row per
  subject examined. **It has no default and every plugin must implement it**
  (#142): a trait default returning `Vec::new()` is indistinguishable at
  every renderer from a plugin that looked and found everything in order,
  which is the meaning an empty vector already carries, so six plugins used
  to report that claim without having made it. Scoping is the
  implementation's job, not the caller's: `restored` is the list of paths the
  rollback put back, and a plugin returns an empty vector when none of them
  are its business. All eight plugins now answer it: kernel and firewall
  first (#138, #139), then ssh, pam, audit, mac, services and permissions
  (#142). Two of those eight answer with a ceiling rather than a clean
  reading. `mac-hardening` and `audit-hardening` return `Unverifiable` rows
  because loading an LSM policy and loading a kernel audit rule set are both
  host-global, so no container this project builds can carry either: those
  rows are honestly unmeasured, not measured-and-fine, and #18 is what turns
  them into a measurement on a real VM. The one case where `mac-hardening`
  returns an empty vector instead is a host with no MAC system detected at
  all (`MacDetection::Absent`), where there is no restored configuration and
  no enforced policy for either to disagree with, which is the same answer
  `firewall/divergence.rs` gives for a host with no firewall backend
  installed. Two contract rules bind an implementation:
  - **It must not change system state.** This is reporting, not
    reconciliation: no rollback behaviour, exit code, or `rollback_success`
    value may depend on what this method returns, and it must not restart,
    stop, enable or write anything itself.
  - **A probe that cannot answer reports an `Unverifiable` row rather than
    saying nothing.** A `RollbackDivergence` carries a `divergence_state` of
    either `Diverged` (measured: the running system disagrees with the
    restored configuration) or `Unverifiable` (the probe could not tell, not
    a claim that anything is wrong). There is no third, `Converged`, variant
    on purpose: an empty `Vec` means everything checkable came back and
    everything uncheckable still carries its own `Unverifiable` row, so
    silence never stands for "nobody looked". Asked of every plugin, and
    asked independently of whether there was anything to reload: a plugin can
    have nothing to reload and diverge anyway (the kernel probe's whole
    reason to exist, since a rollback never writes `/proc/sys`). The dispatch
    gated this on `reloads_for_path()` until #142, which meant the two
    plugins that override that predicate for no path could never be asked at
    all.
  - **Every row also says whether it was expected** (`divergence_expected:
    Option<String>`, #152). `Some(reason)` means the row is the designed
    consequence of this plugin's own `apply()` plus a `reload_after_rollback()`
    that never starts, stops or writes anything live; `None` is the loud
    default, and an unmarked row sorts to the top of every surface that renders
    this list. The field carries no `Default`, so a new plugin's own
    construction site must supply one or the other explicitly rather than
    inherit an answer nobody gave. The test is direction, not frequency:
    expected means the rollback left the host stronger than the configuration
    it just restored asks for; unexpected means weaker, or means the rollback
    did not reach what it should have. A row that fires on every rollback of a
    particular host is not thereby expected, and one that fires rarely is not
    thereby unexpected. The comparison carries a time dimension as well as a
    present-tense one: a row correct right now and weaker only from the next
    boot onward is still unexpected, which is why the kernel plugin's
    `/etc/sysctl.conf` rows stay unexpected rather than joining the
    `/proc/sys` rows beside them. **Expected is not a lesser severity.** An
    expected row can still be `Diverged`; the field says the row was
    predictable, not that it is unimportant, and no renderer hides or drops
    it because of this
    field. The CLI and the desktop rollback modal print the rows nothing in
    the design produces first, then the rest under an "Expected, by design:"
    heading carrying the reason; the fleet `batch rollback` summary changes
    only the order.

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
`path_exists`, `file_metadata`, `read_dir`, `read_link`, `execute_command`,
`command_exists` and `link_target_as_writer`, alongside `description`,
`legacy_description` and `is_remote`, which describe the executor rather than
reach the system. `read_link`, `link_target_as_writer` and `command_exists` are
provided rather than required, and their default bodies still route through this
executor's own `execute_command`, so local and remote cannot come to ask
different questions: `read_link` shells out to `readlink` where a local-only
`std::fs::read_link` would answer "not a symlink" for every path on a remote
host it never looked at. Because the executor is the only system boundary, the
same plugin code runs locally (`LocalExecutor`), against remote `--ssh` targets
(`SshExecutor`), and in unit tests (`MockExecutor`) with zero changes. A
direct `std::fs` call would silently read the local machine while scanning a
remote host: that is the bug this rule exists to prevent.

## Read the layer that is in force

A distribution may keep the same setting in either of two directories. openSUSE
(Leap 15.6+, Tumbleweed, MicroOS) ships its vendor configuration under
`/usr/etc` and reserves `/etc` for administrator overrides, and Fedora is moving
the same way. The override is whole-file rather than per directive: the first
file found wins entirely. So a plugin that reads only `/etc` reports on a file
the system may not be obeying, and a plugin that reads nothing there at all
concludes there is no setting to assess.

Read through `hardener_common::vendor_config`, never by hand:

```rust
use hardener_common::vendor_config::{ConfigLayer, LayeredRead, read_layered};

// `ctx.executor()` hands back an `Arc`, so the call takes `.as_ref()`.
match read_layered(ctx.executor().as_ref(), "/etc/login.defs").await {
    // `path` names the file in force, `layer` says whose it is.
    LayeredRead::Found { path, layer, content } => {
        let from_vendor = layer == ConfigLayer::Vendor;
    }
    // Confirmed absent at BOTH layers: only here is silence the whole truth.
    LayeredRead::Absent => {}
    // A layer that could not be read: unchecked, never absent.
    LayeredRead::Unreadable { path, reason, permission_denied } => {}
}
```

`/etc` is tried first and `/usr/etc` only on a *confirmed* absence. An admin file
that exists but cannot be read is `Unreadable`, and must never fall through to
the vendor copy: it is still the file the system obeys, so answering with the
vendor content would report a configuration that is not in force. That is the
false pass the module exists to remove, and it is the mistake a plausible
implementation makes. `vendor_path_for`, in the same module, gives the `/usr/etc`
counterpart of an `/etc` path or `None`, and it refuses to invent one for
anything outside `/etc` or for `/etc` itself, so paths like `/root` and `/boot`
correctly have none.

**The permissions plugin is the worked example, and it was the last plugin blind
to this.** ssh and pam had both grown a layered read while permissions had no
reference to `/usr/etc` at all, and the cost was measured on the openSUSE test
container: `/etc/sudoers` does not exist there, `/usr/etc/sudoers` does at mode
0444 against a directive requiring 0440 at Critical severity, so the file in
force disclosed the sudo policy to every account on the host and the plugin
reported neither a finding nor an unchecked check. A confirmed absence from
`/etc` had been treated as there being nothing to report, which made a CIS
control pass on evidence nobody had collected. Four rules came out of the fix,
and a new plugin should follow all four:

- **Only absence at both layers is silence.** A confirmed absence at the admin
  layer is the reason to ask the vendor layer, not a reason to stop. An errored
  probe is not an absence either, and is reported as unchecked.
- **A violation you can see but must not fix is still a finding.** The mode was
  read and it does violate, so what is missing is a remediation this tool may
  perform, not the evidence. `permissions` gives that state its own
  `PermissionCheck::VendorOnly` variant, reported as a `Finding`, rather than
  folding it into the `Unverifiable` variant that means "nothing could be read".
- **Never write the vendor layer.** It is package-owned, so a package update
  would revert the change, and the layering exists so that `/etc` is where an
  administrator states a deviation. The remediation is therefore a copy into
  `/etc` at the required mode (`install -o root -g root -m 0440
  /usr/etc/sudoers /etc/sudoers`), never a `chmod` of the vendor file. `apply()`
  is unchanged by any of this and still does nothing for a path absent from
  `/etc`, which is why the state is reported through `scan()` rather than
  previewed as a pending change by `validate()`. A plugin that cannot remediate
  something must still report it.
- **Key the finding on the `/etc` path.** The control is about the setting
  wherever a distribution keeps it, and the compliance mappings, the report and
  the differential suite all ask by that one id, so keying a vendor finding on
  the vendor path would need a special case in each of them. Name the vendor file
  in the title and explanation instead, so the operator can see which file is in
  force.

One further consequence worth copying: whatever resolves a config override for
the admin path must be the same code that resolves it for the vendor path.
`permissions` moved that into a single `effective_directive` helper for exactly
this reason, because two copies come to disagree about an override for precisely
the paths where only one of the two layers holds the file.

The argument does not stop at the two layers. `apply` and `validate` each carried
an inline copy of the same resolution for a while, and those were collapsed into
the helper as well, so every caller now asks one function. They were
behaviour-equivalent at the point they were collapsed rather than already
divergent, and that is the point: a duplicated rule is worth removing before it
diverges, not after. Prove such a collapse by mutating the surviving
implementation and watching every caller's test fail, which is the evidence that
each one really routes through it.

The differential suite learned the same lesson at the same time, and its
`PERMISSION_CHECKS` oracle now consults `/usr/etc` too. For a vendor row its
first assertion records the mode rather than demanding compliance, since this
tool cannot correct a vendor file and requiring compliance there would leave the
suite permanently red against a tool behaving exactly as designed; the assertion
that can fail is whether `scan` reported the violation. If a new plugin gains a
layered read, its oracle needs the same treatment (see
[testing](testing.md#differential-suite-ask-the-system-not-the-tool)).

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

**What you declare decides how strictly it is captured.** A regular file named
in `paths` must be captured completely: if it exists and its content cannot be
read, the capture fails, the error names the path, and `apply()` returns that
error before writing anything. A file reached by recursing into a declared
*directory* is best effort: an unreadable one is stored with no content and
logged at warn level, and the capture succeeds. Metadata-only checkpoints read
no content at all, so the distinction does not arise for them.

So declaring `/etc/foo.conf` and declaring `/etc` are not two spellings of the
same intent. Declare the individual files the plugin writes, so an unreadable
one stops the apply rather than producing a checkpoint that cannot restore it.
Declare a directory to record what was there, accepting that one odd file
inside it will not fail the run: PAM declares `/etc/pam.d` on exactly that
basis, since it refuses to auto-edit anything in the authentication stack. A
plugin that declares a parent directory and then writes files inside it has
the weakest guarantee of the three, and should declare those files as well.

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

Before enforcing a check in `apply()`, honour configured exceptions. Match on
the value the system actually holds, not on the mere presence of an exception:

```rust
// `actual` is the value you just read from the system.
if let Some(exception) = config.matching_exception("selinux-enforcing", actual) {
    // record a skipped Change mentioning exception.reason
}

// Permission modes compare numerically, so "644" and "0644" both match:
if let Some(exception) = config.matching_mode_exception("/etc/shadow", actual_mode) {
    // record a skipped Change mentioning exception.reason
}
```

**Do not reach for `has_valid_exception` on its own.** It checks only that the
entry is allowed and unexpired, so an exception describing a deviation the host
does not actually have would still suppress hardening, leaving a genuinely
insecure setting in place and reporting it as an accepted deviation. That was a
real defect, fixed in `7a29f7d`; `matching_exception` and
`matching_mode_exception` are the same check plus the value comparison, and they
are what `[ssh]`, `[kernel]`, `[pam]` and `[permissions]` use.

`matching_exception` and `matching_mode_exception` (and the `has_valid_exception`
they build on) stay correct for the **apply and validate paths**, and only
those: both want the plain "did it apply" answer, an `Option` that is `Some`
when the exception covers what is actually there and `None` otherwise, and
neither has any use for the *reason* a `None` came back.

`scan()` wants that reason, so it does not use these three at all. A scan-side
finding is built from one of three `exception_outcome*` methods, each handing
back an owned `ExceptionOutcome` rather than an `Option`:

```rust
// A check with a host value to compare: ssh, pam, kernel.
finding_exception: config.exception_outcome(param_name, &actual_value),

// A permission mode: compares octal numerically, so "644" and "0644"
// both match, exactly as matching_mode_exception does for apply.
finding_exception: config.exception_outcome_for_mode(directive.permission_path, current_mode),

// A present-or-absent check with no value to compare: services, mac,
// audit, firewall. Can only ever decline on expiry, never on a value
// mismatch, because there is no observed value to mismatch against.
finding_exception: config.exception_outcome_for_presence(directive.service_name),
```

`ExceptionOutcome` is `NotConfigured`, `Applied(..)` or `Declined(..)`.
`NotConfigured` and `Declined` are both live violations; only `Applied` excuses
the finding from its compliance control. Picking the right method matters
because a check that has a host value to compare and is scanned with
`exception_outcome_for_presence` can never report `ValueMismatch`, only
`Expired`, silently losing the case where the exception simply documents the
wrong value. See the [configuration reference](../reference/configuration.md)
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
`crates/hardener-plugins/src/lib.rs`, alongside a `pub use` for the type and a
row pairing its plugin id with its `coverage()` in **`coverage_table()`**, in
the same file. That table is where the per-plugin rows live, not
`compliance_coverage()`, which reads them: `compliance_coverage` and
`coverage_for` both fold over the one table so they can never disagree about
which plugin assesses which control. The table's return type is a fixed-size
array, `[(&'static str, Vec<ComplianceMapping>); 8]`, so a ninth plugin has to
widen the arity as well as add the row; the compiler says so, and the
`every_registered_plugin_declares_its_coverage` test fails for a plugin
registered without one. The registry is the single
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
