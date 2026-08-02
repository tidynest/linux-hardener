#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. See `tests.rs` for
// why the marker is here anyway.

//! Unit tests for `reload_plugins_after_rollback`.
//!
//! Four stub plugins exercise the dispatch on its own terms, independent of
//! any real plugin's `scan`/`apply`/`validate`, which none of these tests
//! call.

use super::*;
use hardener_common::error::{HardeningError, Result};
use hardener_common::executor::MockExecutor;
use hardener_common::types::{FindingCategory, PluginId};
use hardener_core::plugin::{
    ApplyResult, HardeningPlugin, PluginMetadata, ScanResult, ValidationReport,
};
use hardener_core::{Context, PluginConfig, PluginRegistry};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Builds the metadata every stub plugin below shares, save for its id.
fn stub_metadata(id: &str) -> PluginMetadata {
    PluginMetadata {
        plugin_category: FindingCategory::FileSystem,
        plugin_description: "Stub plugin for reload dispatch tests.".to_string(),
        plugin_id: PluginId::from(id),
        plugin_name: id.to_string(),
        plugin_version: "0.1.0".to_string(),
    }
}

/// Claims `/etc/alpha` and reports a successful reload.
#[derive(Default)]
struct AlphaPlugin;

#[async_trait::async_trait]
impl HardeningPlugin for AlphaPlugin {
    fn metadata(&self) -> PluginMetadata {
        stub_metadata("alpha")
    }

    fn dependencies(&self) -> Vec<PluginId> {
        Vec::new()
    }

    async fn scan(&self, _ctx: &Context, _config: &PluginConfig) -> Result<ScanResult> {
        unimplemented!("not exercised by the reload dispatch tests")
    }

    async fn apply(&self, _ctx: &mut Context, _config: &PluginConfig) -> Result<ApplyResult> {
        unimplemented!("not exercised by the reload dispatch tests")
    }

    async fn validate(&self, _ctx: &Context, _config: &PluginConfig) -> Result<ValidationReport> {
        unimplemented!("not exercised by the reload dispatch tests")
    }

    fn reloads_for_path(&self, path: &Path) -> bool {
        path.starts_with("/etc/alpha")
    }

    async fn reload_after_rollback(&self, _ctx: &Context) -> Result<Option<String>> {
        Ok(Some("alpha reloaded".to_string()))
    }
}

/// Claims `/etc/beta`. Present so the dispatch has a second plugin to prove
/// it does *not* reload: its own `reload_after_rollback` is never expected to
/// run in these tests.
#[derive(Default)]
struct BetaPlugin;

#[async_trait::async_trait]
impl HardeningPlugin for BetaPlugin {
    fn metadata(&self) -> PluginMetadata {
        stub_metadata("beta")
    }

    fn dependencies(&self) -> Vec<PluginId> {
        Vec::new()
    }

    async fn scan(&self, _ctx: &Context, _config: &PluginConfig) -> Result<ScanResult> {
        unimplemented!("not exercised by the reload dispatch tests")
    }

    async fn apply(&self, _ctx: &mut Context, _config: &PluginConfig) -> Result<ApplyResult> {
        unimplemented!("not exercised by the reload dispatch tests")
    }

    async fn validate(&self, _ctx: &Context, _config: &PluginConfig) -> Result<ValidationReport> {
        unimplemented!("not exercised by the reload dispatch tests")
    }

    fn reloads_for_path(&self, path: &Path) -> bool {
        path.starts_with("/etc/beta")
    }

    async fn reload_after_rollback(&self, _ctx: &Context) -> Result<Option<String>> {
        unimplemented!("beta owns nothing restored in these tests, so this must never run")
    }
}

/// Claims `/etc/failing` and always refuses to reload.
#[derive(Default)]
struct FailingPlugin;

#[async_trait::async_trait]
impl HardeningPlugin for FailingPlugin {
    fn metadata(&self) -> PluginMetadata {
        stub_metadata("failing")
    }

    fn dependencies(&self) -> Vec<PluginId> {
        Vec::new()
    }

    async fn scan(&self, _ctx: &Context, _config: &PluginConfig) -> Result<ScanResult> {
        unimplemented!("not exercised by the reload dispatch tests")
    }

    async fn apply(&self, _ctx: &mut Context, _config: &PluginConfig) -> Result<ApplyResult> {
        unimplemented!("not exercised by the reload dispatch tests")
    }

    async fn validate(&self, _ctx: &Context, _config: &PluginConfig) -> Result<ValidationReport> {
        unimplemented!("not exercised by the reload dispatch tests")
    }

    fn reloads_for_path(&self, path: &Path) -> bool {
        path.starts_with("/etc/failing")
    }

    async fn reload_after_rollback(&self, _ctx: &Context) -> Result<Option<String>> {
        Err(HardeningError::Plugin("reload refused".to_string()))
    }
}

/// Claims `/etc/silent` and reports there was nothing to do.
#[derive(Default)]
struct SilentPlugin;

#[async_trait::async_trait]
impl HardeningPlugin for SilentPlugin {
    fn metadata(&self) -> PluginMetadata {
        stub_metadata("silent")
    }

    fn dependencies(&self) -> Vec<PluginId> {
        Vec::new()
    }

    async fn scan(&self, _ctx: &Context, _config: &PluginConfig) -> Result<ScanResult> {
        unimplemented!("not exercised by the reload dispatch tests")
    }

    async fn apply(&self, _ctx: &mut Context, _config: &PluginConfig) -> Result<ApplyResult> {
        unimplemented!("not exercised by the reload dispatch tests")
    }

    async fn validate(&self, _ctx: &Context, _config: &PluginConfig) -> Result<ValidationReport> {
        unimplemented!("not exercised by the reload dispatch tests")
    }

    fn reloads_for_path(&self, path: &Path) -> bool {
        path.starts_with("/etc/silent")
    }

    async fn reload_after_rollback(&self, _ctx: &Context) -> Result<Option<String>> {
        Ok(None)
    }
}

/// Two stub plugins, one claiming /etc/alpha and one claiming /etc/beta, so a
/// restored path exercises the mapping and nothing else.
fn registry_with_alpha_and_beta() -> PluginRegistry {
    let registry = PluginRegistry::new();
    registry
        .register(Box::new(AlphaPlugin))
        .expect("alpha registers cleanly into an empty registry");
    registry
        .register(Box::new(BetaPlugin))
        .expect("beta registers cleanly alongside alpha");
    registry
}

#[tokio::test]
async fn the_plugin_owning_a_restored_path_is_reloaded() {
    let ctx = Context::with_executor(Arc::new(MockExecutor::new()));
    let registry = registry_with_alpha_and_beta();
    let restored = vec![PathBuf::from("/etc/alpha/config")];

    let results = reload_plugins_after_rollback(&ctx, &registry, &restored).await;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].reload_plugin_id, "alpha");
    assert!(results[0].reload_success);
    assert_eq!(results[0].reload_action, "alpha reloaded");
}

#[tokio::test]
async fn a_plugin_owning_no_restored_path_is_not_reloaded() {
    let ctx = Context::with_executor(Arc::new(MockExecutor::new()));
    let registry = registry_with_alpha_and_beta();
    let restored = vec![PathBuf::from("/etc/alpha/config")];

    let results = reload_plugins_after_rollback(&ctx, &registry, &restored).await;

    assert!(
        results.iter().any(|r| r.reload_plugin_id == "alpha"),
        "alpha owns the restored path and must be reloaded, or this test passes vacuously"
    );
    assert!(
        !results.iter().any(|r| r.reload_plugin_id == "beta"),
        "beta owns nothing that was restored and must not be reloaded"
    );
}

#[tokio::test]
async fn a_plugin_matching_three_restored_paths_reloads_once() {
    let ctx = Context::with_executor(Arc::new(MockExecutor::new()));
    let registry = registry_with_alpha_and_beta();
    let restored = vec![
        PathBuf::from("/etc/alpha/one"),
        PathBuf::from("/etc/alpha/two"),
        PathBuf::from("/etc/alpha/three"),
    ];

    let results = reload_plugins_after_rollback(&ctx, &registry, &restored).await;

    assert_eq!(results.len(), 1, "one reload per plugin, not per path");
}

#[tokio::test]
async fn a_failing_reload_is_recorded_rather_than_dropped() {
    let ctx = Context::with_executor(Arc::new(MockExecutor::new()));
    let registry = PluginRegistry::new();
    registry
        .register(Box::new(FailingPlugin))
        .expect("failing registers cleanly into an empty registry");
    let restored = vec![PathBuf::from("/etc/failing/config")];

    let results = reload_plugins_after_rollback(&ctx, &registry, &restored).await;

    assert_eq!(results.len(), 1);
    assert!(!results[0].reload_success);
    assert_eq!(
        results[0].reload_error.as_deref(),
        Some(
            HardeningError::Plugin("reload refused".to_string())
                .to_string()
                .as_str()
        ),
        "the reload dispatch writes the same Display every other *_error field in this tree writes, prefix included"
    );
}

/// A plugin returning Ok(None) said there was nothing to do, so it earns no
/// row: an operator reading the output should see reloads that happened.
#[tokio::test]
async fn a_plugin_with_nothing_to_reload_produces_no_row() {
    let ctx = Context::with_executor(Arc::new(MockExecutor::new()));
    let registry = PluginRegistry::new();
    registry
        .register(Box::new(SilentPlugin))
        .expect("silent registers cleanly into an empty registry");
    let restored = vec![PathBuf::from("/etc/silent/config")];

    let results = reload_plugins_after_rollback(&ctx, &registry, &restored).await;

    assert!(results.is_empty());
}

/// A registry that cannot be listed has nothing to reload, but an empty
/// `Vec` reads exactly like a rollback that had nothing left to reload:
/// `RollbackResult::reloads_ok` cannot tell the two apart. This must come
/// back as a recorded failure instead, or a poisoned registry lock reports a
/// clean rollback.
#[test]
fn a_registry_that_cannot_be_listed_reports_a_failed_reload_not_a_clean_one() {
    let listed: Result<Vec<PluginMetadata>> = Err(HardeningError::Plugin(
        "Failed to acquire read lock: poisoned".to_string(),
    ));

    let outcome = plugins_or_reload_failure(listed);

    let failure = outcome.expect_err("a registry that cannot be listed did not report a clean run");
    assert!(!failure.reload_success);
    assert_eq!(failure.reload_plugin_id, "plugin-registry");
}

/// A plugin the listing just named but that `get` could not produce (a
/// poisoned lock, or an id the listing named a moment before it vanished)
/// must be recorded as a failed reload, not skipped as though it were never
/// a candidate.
#[test]
fn a_plugin_the_listing_named_but_get_could_not_find_reports_a_failed_reload() {
    let ghost_id = PluginId::from("ghost");
    let fetched: Result<Option<Arc<dyn HardeningPlugin>>> = Ok(None);

    let outcome = plugin_or_reload_failure(fetched, &ghost_id);

    let failure = match outcome {
        Err(failure) => failure,
        Ok(_) => panic!("a plugin the listing named but get could not find was silently skipped"),
    };
    assert!(!failure.reload_success);
    assert_eq!(failure.reload_plugin_id, "ghost");
}
