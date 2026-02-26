# Trait Refactor: Config to PluginConfig — Implementation Plan

**Status:** Implemented (2026-02-22) — commits `81c13ad`, `d029629`, `b87fb1c`

**Goal:** Replace the empty `Config` unit struct with `PluginConfig` in the `HardeningPlugin` trait, and wire SSH as a proof-of-concept that consumes directives and exceptions.

**Architecture:** Delete the empty `Config` struct. Update trait signatures to accept `&PluginConfig`. Callers extract per-plugin config from `HardenerConfig`. SSH plugin reads directives and exceptions; remaining 7 plugins ignore the parameter (identical behaviour to today).

**Tech Stack:** Rust, async_trait, hardener-core/hardener-plugins crates

**Design doc:** `docs/plans/2026-02-22-trait-refactor-design.md`

---

## Task 1: Add `has_valid_exception()` helper to PluginConfig

**Files:**
- Modify: `crates/hardener-core/src/config.rs:46-67`
- Test: `crates/hardener-core/src/config.rs:149-242` (inline tests)

**Step 1: Write the failing test**

Add to the `mod tests` block in `crates/hardener-core/src/config.rs` (after line 233, before the closing `}`):

```rust
#[test]
fn test_has_valid_exception_found() {
    let mut plugin = PluginConfig::default();
    plugin.exceptions.insert(
        "PermitRootLogin".to_string(),
        PolicyException {
            value: "yes".to_string(),
            allowed: true,
            reason: "Legacy server".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );
    assert!(plugin.has_valid_exception("PermitRootLogin").is_some());
    assert!(plugin.has_valid_exception("X11Forwarding").is_none());
}

#[test]
fn test_has_valid_exception_expired() {
    let mut plugin = PluginConfig::default();
    plugin.exceptions.insert(
        "PermitRootLogin".to_string(),
        PolicyException {
            value: "yes".to_string(),
            allowed: true,
            reason: "Temporary".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: Some("2020-01-01".to_string()),
        },
    );
    assert!(plugin.has_valid_exception("PermitRootLogin").is_none());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p hardener-core test_has_valid_exception`
Expected: FAIL — `has_valid_exception` method does not exist

**Step 3: Write minimal implementation**

Add to `crates/hardener-core/src/config.rs` after the `impl Default for PluginConfig` block (after line 67), before the `PolicyException` struct:

```rust
impl PluginConfig {
    /// Returns a valid, non-expired exception for the given key, if one exists.
    pub fn has_valid_exception(&self, key: &str) -> Option<&PolicyException> {
        self.exceptions.get(key).filter(|e| e.is_valid())
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p hardener-core test_has_valid_exception`
Expected: PASS (both tests)

**Step 5: Commit**

```bash
git add crates/hardener-core/src/config.rs
git commit -m "feat(config): add has_valid_exception() helper to PluginConfig"
```

---

## Task 2: Update trait signature and delete Config struct

**Files:**
- Modify: `crates/hardener-core/src/plugin.rs:29-83`
- Modify: `crates/hardener-core/src/lib.rs:33`
- Modify: `crates/hardener-core/src/testing.rs:5-8, 121, 140`

**Step 1: Delete `Config` struct and update trait**

In `crates/hardener-core/src/plugin.rs`:

- Delete lines 29-31 (the `Config` struct):
  ```rust
  // DELETE these 3 lines:
  #[cfg(feature = "system")]
  #[derive(Default)]
  pub struct Config;
  ```

- Add import for `PluginConfig` at the top of the file (after line 8):
  ```rust
  #[cfg(feature = "system")]
  use crate::config::PluginConfig;
  ```

- Line 76: change `config: &Config` to `config: &PluginConfig`
- Line 82: change `config: &Config` to `config: &PluginConfig`

**Step 2: Update lib.rs re-exports**

In `crates/hardener-core/src/lib.rs` line 33, remove `Config` from the re-export:

```rust
// Before:
pub use plugin::{Checkpoint, CheckpointId, CheckpointManager, Config, HardeningPlugin};

// After:
pub use plugin::{Checkpoint, CheckpointId, CheckpointManager, HardeningPlugin};
```

**Step 3: Update MockPlugin in testing.rs**

In `crates/hardener-core/src/testing.rs`:

- Line 6: change import from `Config` to `PluginConfig` in the use statement:
  ```rust
  // Before:
  use crate::{
      ApplyResult, Checkpoint, Config, Context, HardeningPlugin, PluginMetadata, ScanResult,
      ValidationReport,
  };

  // After:
  use crate::{
      ApplyResult, Checkpoint, Context, HardeningPlugin, PluginConfig, PluginMetadata,
      ScanResult, ValidationReport,
  };
  ```

- Line 121: change `_config: &Config` to `_config: &PluginConfig`
- Line 140: change `_config: &Config` to `_config: &PluginConfig`

**Step 4: Verify core crate compiles**

Run: `cargo check -p hardener-core`
Expected: SUCCESS (the downstream crates will fail — that's expected, we fix them next)

**Step 5: Commit**

```bash
git add crates/hardener-core/src/plugin.rs crates/hardener-core/src/lib.rs crates/hardener-core/src/testing.rs
git commit -m "refactor(core): replace Config with PluginConfig in HardeningPlugin trait"
```

---

## Task 3: Update PluginManager to accept HardenerConfig

**Files:**
- Modify: `crates/hardener-core/src/plugin_manager.rs:7-14, 247-262, 295`

**Step 1: Update imports**

In `crates/hardener-core/src/plugin_manager.rs` lines 7-14, change the import:

```rust
// Before:
use crate::{
    ApplyResult,
    // Checkpoint,
    Config,
    Context,
    PluginRegistry,
    ScanResult,
};

// After:
use crate::{
    ApplyResult,
    // Checkpoint,
    Context,
    HardenerConfig,
    PluginRegistry,
    ScanResult,
};
```

**Step 2: Update `execute_apply()` signature and body**

In `crates/hardener-core/src/plugin_manager.rs`:

- Update the doc comment example (lines 250-256):
  ```rust
  /// ```ignore
  /// # use hardener_core::{PluginManager, PluginRegistry, Context, HardenerConfig};
  /// let mut manager = PluginManager::new(PluginRegistry::new());
  /// manager.resolve_dependencies()?;
  /// let mut ctx = Context::new();
  /// let config = HardenerConfig::default();
  /// let results = manager.execute_apply(&mut ctx, &config, &[]).await?;
  /// # Ok::<(), anyhow::Error>(())
  /// ```
  ```

- Update the signature (line 258-263):
  ```rust
  // Before:
  pub async fn execute_apply(
      &self,
      ctx: &mut Context,
      config: &Config,
      plugin_ids: &[PluginId],
  ) -> Result<Vec<ApplyResult>> {

  // After:
  pub async fn execute_apply(
      &self,
      ctx: &mut Context,
      config: &HardenerConfig,
      plugin_ids: &[PluginId],
  ) -> Result<Vec<ApplyResult>> {
  ```

- Update the `plugin.apply()` call (line 295) to extract per-plugin config:
  ```rust
  // Before:
  match plugin.apply(ctx, config).await {

  // After:
  let plugin_config = config.get_plugin_config(plugin_id.as_str());
  match plugin.apply(ctx, plugin_config).await {
  ```

**Step 3: Verify core crate compiles**

Run: `cargo check -p hardener-core`
Expected: SUCCESS

**Step 4: Commit**

```bash
git add crates/hardener-core/src/plugin_manager.rs
git commit -m "refactor(plugin-manager): accept HardenerConfig, extract per-plugin config"
```

---

## Task 4: Update CLI apply command

**Files:**
- Modify: `crates/hardener-cli/src/commands/apply.rs:5, 57, 109, 122`

**Step 1: Update import**

In `crates/hardener-cli/src/commands/apply.rs` line 5:

```rust
// Before:
use hardener_core::{Config, ConfigLoader, Context, HardenerConfig, SystemExecutor};

// After:
use hardener_core::{ConfigLoader, Context, HardenerConfig, PluginConfig, SystemExecutor};
```

**Step 2: Remove `let config = Config;` and extract per-plugin config in the loop**

- Delete line 57: `let config = Config;`

- Line 92 (inside the loop, after `let id_str = plugin_id.as_str();`), add:
  ```rust
  let plugin_config = hardener_config.get_plugin_config(id_str);
  ```

- Line 109: change `plugin.validate(&ctx, &config)` to `plugin.validate(&ctx, plugin_config)`
- Line 122: change `plugin.apply(&mut ctx, &config)` to `plugin.apply(&mut ctx, plugin_config)`

**Step 3: Verify CLI crate compiles**

Run: `cargo check -p hardener-cli`
Expected: SUCCESS

**Step 4: Commit**

```bash
git add crates/hardener-cli/src/commands/apply.rs
git commit -m "refactor(cli): pass per-plugin PluginConfig to apply and validate"
```

---

## Task 5: Update all 7 non-SSH plugin signatures

**Files (import line + apply + validate for each):**

| Plugin | Import line | `apply()` line | `validate()` line |
|--------|-------------|----------------|-------------------|
| `audit/mod.rs` | 21 | 530 | 735 |
| `firewall/mod.rs` | 19 | 281 | 368 |
| `kernel/mod.rs` | 19 | 273 | 436 |
| `mac/mod.rs` | 17 | 354 | 470 |
| `pam/mod.rs` | 15 | 191 | 418 |
| `permissions/mod.rs` | 19 | 294 | 354 |
| `services/mod.rs` | 16 | 236 | 409 |

**Step 1: For each of the 7 plugins, apply three changes:**

1. **Import**: replace `Config` with `PluginConfig` in the `use hardener_core::{...}` block
2. **apply()**: change `_config: &Config` to `_config: &PluginConfig`
3. **validate()**: change `_config: &Config` to `_config: &PluginConfig`

Example for `audit/mod.rs`:

```rust
// Import (line 21):
// Before: ApplyResult, Change, ChangeType, Checkpoint, Config, ValidationIssue, ValidationReport,
// After:  ApplyResult, Change, ChangeType, Checkpoint, PluginConfig, ValidationIssue, ValidationReport,

// apply() (line 530):
// Before: async fn apply(&self, ctx: &mut Context, _config: &Config) -> Result<ApplyResult> {
// After:  async fn apply(&self, ctx: &mut Context, _config: &PluginConfig) -> Result<ApplyResult> {

// validate() (line 735):
// Before: async fn validate(&self, ctx: &Context, _config: &Config) -> Result<ValidationReport> {
// After:  async fn validate(&self, ctx: &Context, _config: &PluginConfig) -> Result<ValidationReport> {
```

Repeat identically for firewall, kernel, mac, pam, permissions, services.

**Step 2: Verify plugins crate compiles**

Run: `cargo check -p hardener-plugins`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add crates/hardener-plugins/src/*/mod.rs
git commit -m "refactor(plugins): update 7 plugin signatures from Config to PluginConfig"
```

---

## Task 6: Update SSH plugin to consume PluginConfig

**Files:**
- Modify: `crates/hardener-plugins/src/ssh/mod.rs:21, 306, 380-421, 506`

**Step 1: Update import and apply() signature**

In `crates/hardener-plugins/src/ssh/mod.rs`:

- Line 21: replace `Config` with `PluginConfig` in the import
- Line 306: change `_config: &Config` to `config: &PluginConfig` (remove the underscore — SSH now uses it)
- Line 506: change `_config: &Config` to `_config: &PluginConfig` (validate stays unused for now)

**Step 2: Modify the directive loop to check exceptions and directive overrides**

Replace the directive loop body in `apply()` (lines 381-421) with:

```rust
for directive in SSH_DIRECTIVES {
    // Check for a valid exception — skip this directive if exempted
    if let Some(exception) = config.has_valid_exception(directive.ssh_directive_name) {
        info!(
            "Skipping {} — exception: {}",
            directive.ssh_directive_name, exception.reason
        );
        changes.push(Change {
            change_description: format!(
                "{}: skipped (exception: {})",
                directive.ssh_directive_name, exception.reason
            ),
            change_type: ChangeType::ConfigFile,
            change_success: true,
            change_error: None,
        });
        continue;
    }

    // Determine target value: user directive override or hardcoded baseline
    let target_value = config
        .directives
        .get(directive.ssh_directive_name)
        .map(|s| s.as_str())
        .unwrap_or(directive.ssh_secure_value);

    let original_value = parse_config_value(
        &config_content,
        directive.ssh_directive_name,
        ConfigFormat::SpaceSeparated,
        false,
    );

    let needs_change = match &original_value {
        Some(value) => value != target_value,
        None => true,
    };

    if needs_change {
        config_content = set_config_directive(
            &config_content,
            directive.ssh_directive_name,
            target_value,
            ConfigFormat::SpaceSeparated,
            false,
        );

        changes.push(Change {
            change_description: format!(
                "{}: {} -> {}",
                directive.ssh_directive_name,
                original_value.unwrap_or_else(|| "not set".to_string()),
                target_value
            ),
            change_type: ChangeType::ConfigFile,
            change_success: true,
            change_error: None,
        });

        info!(
            "Applied SSH directive: {} = {}",
            directive.ssh_directive_name, target_value
        );
    }
}
```

**Step 3: Verify compilation**

Run: `cargo check -p hardener-plugins`
Expected: SUCCESS

**Step 4: Commit**

```bash
git add crates/hardener-plugins/src/ssh/mod.rs
git commit -m "feat(ssh): consume PluginConfig directives and exceptions"
```

---

## Task 7: Update all test files

**Files to update** (35 locations across 16 test files):

### Group A: Tests that use `use hardener_core::{Config, ...}` and `let config = Config;`

These tests import `Config` alongside other types. Change `Config` to `PluginConfig` in the import, and `let config = Config;` to `let config = PluginConfig::default();`.

| File | Import line | `let config` lines |
|------|------------|-------------------|
| `tests/ssh_tests.rs` | 2 | 74, 116 |
| `tests/kernel_tests.rs` | 2 | 68, 109 |
| `tests/firewall_tests.rs` | — (find Config import) | 66, 86 |
| `tests/pam_tests.rs` | 3 | 65, 109 |
| `tests/audit_tests.rs` | 3 | 84, 145 |
| `tests/mac_tests.rs` | 3 | 92, 138 |
| `tests/permissions_tests.rs` | 3 | 87, 133 |
| `tests/services_tests.rs` | 3 | 93, 155 |

For each:
```rust
// Import: Config → PluginConfig
// Usage: let config = Config; → let config = PluginConfig::default();
```

### Group B: Tests that use `let config = hardener_core::Config;`

These tests use fully-qualified paths. Change to `hardener_core::PluginConfig::default()`.

| File | Lines |
|------|-------|
| `tests/ssh_mock_tests.rs` | 170, 183, 218 |
| `tests/kernel_mock_tests.rs` | 229, 254, 275 |
| `tests/firewall_mock_tests.rs` | (search for same pattern) |
| `tests/mac_mock_tests.rs` | 304, 316 |
| `tests/pam_mock_tests.rs` | 285 |
| `tests/audit_mock_tests.rs` | 265, 279 |
| `tests/permissions_mock_tests.rs` | 292 |
| `tests/services_mock_tests.rs` | 275, 295 |
| `tests/ssh_integration_tests.rs` | 119, 212 |

For each:
```rust
// Before: let config = hardener_core::Config;
// After:  let config = hardener_core::PluginConfig::default();
```

### Group C: plugin_manager_tests

| File | Import line | `let config` line |
|------|------------|-------------------|
| `crates/hardener-core/tests/plugin_manager_tests.rs` | 6 | 273 |

```rust
// Import: Config → HardenerConfig
// Usage: let config = Config; → let config = HardenerConfig::default();
```

(PluginManager now accepts `&HardenerConfig`, not `&PluginConfig`)

**Step 1: Apply all changes across the test files**

Work through each file: update import, update `let config = ...` lines.

**Step 2: Run full test suite**

Run: `cargo test --workspace`
Expected: All tests PASS

**Step 3: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: No warnings

**Step 4: Run WASM check**

Run: `cargo check -p hardener-ui --target wasm32-unknown-unknown`
Expected: SUCCESS

**Step 5: Commit**

```bash
git add crates/hardener-plugins/tests/*.rs crates/hardener-core/tests/*.rs
git commit -m "test: update all tests from Config to PluginConfig/HardenerConfig"
```

---

## Task 8: Final verification and documentation

**Files:**
- Modify: `docs/plans/2026-02-22-trait-refactor-design.md` (mark status as Implemented)
- Verify: `docs/COMPREHENSIVE_AUDIT_REPORT.md` (if trait refactor was tracked there)

**Step 1: Full verification suite**

```bash
cargo check --workspace
cargo check -p hardener-ui --target wasm32-unknown-unknown
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

Expected: All pass with zero warnings.

**Step 2: Update design doc status**

In `docs/plans/2026-02-22-trait-refactor-design.md`, change line 4:

```markdown
// Before: **Status:** Approved
// After:  **Status:** Implemented
```

**Step 3: Commit**

```bash
git add docs/plans/2026-02-22-trait-refactor-design.md
git commit -m "docs: mark trait refactor design as implemented"
```

---

## Summary of Changes

| Task | Scope | Commits |
|------|-------|---------|
| 1 | `has_valid_exception()` helper | 1 |
| 2 | Delete Config, update trait + MockPlugin | 1 |
| 3 | PluginManager accepts HardenerConfig | 1 |
| 4 | CLI passes per-plugin config | 1 |
| 5 | 7 non-SSH plugin signatures | 1 |
| 6 | SSH plugin consumes config | 1 |
| 7 | All test files | 1 |
| 8 | Docs + final verification | 1 |
| **Total** | | **8 commits** |

## Behaviour Guarantees

- **No config file**: `PluginConfig::default()` has `enabled: true`, empty directives/exceptions. All hardcoded baselines apply. Identical to current behaviour.
- **Directives set**: SSH apply uses user value instead of hardcoded baseline.
- **Exception set**: SSH apply skips that directive with a logged audit trail.
- **Other 7 plugins**: Ignore `_config: &PluginConfig` — zero behaviour change.
