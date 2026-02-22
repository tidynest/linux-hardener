# Trait Refactor: Config → PluginConfig

**Date:** 2026-02-22
**Status:** Approved

## Problem

The `HardeningPlugin` trait accepts an empty `Config` unit struct in `apply()` and `validate()`. Every plugin ignores this parameter. Meanwhile, a rich `HardenerConfig` (with per-plugin directives, exceptions, and enabled flags) is loaded separately but never reaches plugins through the trait.

## Decision

Replace `Config` with `PluginConfig` in the trait signature. Wire up the SSH plugin as a proof-of-concept that consumes directives and exceptions. The remaining 7 plugins get the new type but continue ignoring it until individually wired up.

## Design

### Trait Change

```rust
// Before
async fn apply(&self, ctx: &mut Context, config: &Config) -> Result<ApplyResult>;
async fn validate(&self, ctx: &Context, config: &Config) -> Result<ValidationReport>;

// After
async fn apply(&self, ctx: &mut Context, config: &PluginConfig) -> Result<ApplyResult>;
async fn validate(&self, ctx: &Context, config: &PluginConfig) -> Result<ValidationReport>;
```

Delete the empty `Config` struct. `PluginConfig` (already in `config.rs`) has: `enabled`, `directives`, `custom_directives`, `exceptions`.

### Caller Updates

**CLI `apply.rs`**: Delete `let config = Config;`. Extract per-plugin config in the loop via `hardener_config.get_plugin_config(id_str)`. Pass to `apply()` and `validate()`.

**`PluginManager::execute_apply()`**: Accept `&HardenerConfig` instead of `&Config`. Extract `config.get_plugin_config(plugin_id.as_str())` per plugin in the loop.

**Tauri commands**: No change needed (shells out to CLI via pkexec).

**Tests**: Replace `&Config` with `&PluginConfig::default()` (enabled=true, empty directives/exceptions — identical behaviour).

### SSH Plugin Pilot

SSH `apply()` behaviour with the new config:

1. **Hardcoded baseline stays** as the security floor (unchanged defaults)
2. **Directives override**: if `config.directives` has a key matching a baseline directive, use the user's value instead
3. **Exceptions skip**: if `config.exceptions` has a valid, non-expired exception for a key, skip that directive and log it

Helper method on `PluginConfig`:

```rust
pub fn has_valid_exception(&self, key: &str) -> Option<&PolicyException> {
    self.exceptions.get(key).filter(|e| e.is_valid())
}
```

### Behaviour Guarantees

- **No config file** → all hardcoded baselines apply (identical to current behaviour)
- **Directives set** → user can tighten values beyond baseline
- **Exception set** → user can exempt specific settings with an auditable trail
- **PluginConfig::default()** produces identical behaviour to the old empty `Config`

## Scope

| Component | Change |
|-----------|--------|
| `hardener-core/src/plugin.rs` | Delete `Config`, update trait signatures |
| `hardener-core/src/config.rs` | Add `has_valid_exception()` helper |
| `hardener-core/src/plugin_manager.rs` | Accept `&HardenerConfig`, extract per-plugin config |
| `hardener-cli/src/commands/apply.rs` | Remove `Config`, pass `PluginConfig` from loader |
| `hardener-plugins/src/*/mod.rs` (all 8) | Update `impl` signatures, SSH consumes config |
| `hardener-plugins/tests/*.rs` | Replace `&Config` with `&PluginConfig::default()` |

## Out of Scope

- Wiring up the remaining 7 plugins to consume directives/exceptions (follow-up, one at a time)
- Changing `scan()` to accept config (scan is read-only, doesn't need per-plugin config)
- GUI changes (Tauri shells out to CLI)
