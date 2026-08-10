#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. See `tests.rs` for
// why the marker is here anyway.

//! Unit tests for `reconcile_plugins_after_rollback`.
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
use hardener_types::{DivergenceState, RollbackDivergence};
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

/// A plugin that reloads nothing and diverges anyway. This is #138's shape:
/// `reload_after_rollback` returning `Ok(None)` is `continue`d past by the
/// dispatch, so a divergence carried on the reload's return value would have
/// nowhere to live.
struct SilentButDivergedPlugin;

#[async_trait::async_trait]
impl HardeningPlugin for SilentButDivergedPlugin {
    fn metadata(&self) -> PluginMetadata {
        stub_metadata("diverged-plugin")
    }

    fn dependencies(&self) -> Vec<PluginId> {
        Vec::new()
    }

    async fn scan(&self, _ctx: &Context, _config: &PluginConfig) -> Result<ScanResult> {
        unreachable!("the dispatch never scans")
    }

    async fn apply(&self, _ctx: &mut Context, _config: &PluginConfig) -> Result<ApplyResult> {
        unreachable!("the dispatch never applies")
    }

    async fn validate(&self, _ctx: &Context, _config: &PluginConfig) -> Result<ValidationReport> {
        unreachable!("the dispatch never validates")
    }

    fn reloads_for_path(&self, path: &Path) -> bool {
        path == Path::new("/etc/diverged.conf")
    }

    async fn reload_after_rollback(&self, _ctx: &Context) -> Result<Option<String>> {
        Ok(None)
    }

    async fn divergences_after_rollback(
        &self,
        _ctx: &Context,
        _restored: &[PathBuf],
    ) -> Vec<RollbackDivergence> {
        vec![RollbackDivergence {
            divergence_plugin_id: "diverged-plugin".to_string(),
            divergence_subject: "a subject".to_string(),
            divergence_state: DivergenceState::Diverged,
            divergence_detail: "the running system disagrees".to_string(),
        }]
    }
}

/// One stub, registered the way `registry_with_alpha_and_beta` registers its
/// two.
fn registry_with_diverged() -> PluginRegistry {
    let registry = PluginRegistry::new();
    registry
        .register(Box::new(SilentButDivergedPlugin))
        .expect("the stub registers cleanly into an empty registry");
    registry
}

/// A stub whose `divergences_after_rollback` reports a row only if its own
/// `reload_after_rollback` already ran. Finding 6 (final review): nothing
/// pinned this order despite the dispatch's own doc comment calling it
/// load-bearing, so a future edit that swapped the two statements in
/// `reconcile_plugins_after_rollback` would compile and pass every other test
/// in this file. This one turns that swap into a failing assertion.
#[derive(Default)]
struct OrderSensitivePlugin {
    reloaded: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl HardeningPlugin for OrderSensitivePlugin {
    fn metadata(&self) -> PluginMetadata {
        stub_metadata("order-sensitive")
    }

    fn dependencies(&self) -> Vec<PluginId> {
        Vec::new()
    }

    async fn scan(&self, _ctx: &Context, _config: &PluginConfig) -> Result<ScanResult> {
        unreachable!("the dispatch never scans")
    }

    async fn apply(&self, _ctx: &mut Context, _config: &PluginConfig) -> Result<ApplyResult> {
        unreachable!("the dispatch never applies")
    }

    async fn validate(&self, _ctx: &Context, _config: &PluginConfig) -> Result<ValidationReport> {
        unreachable!("the dispatch never validates")
    }

    fn reloads_for_path(&self, path: &Path) -> bool {
        path == Path::new("/etc/order.conf")
    }

    async fn reload_after_rollback(&self, _ctx: &Context) -> Result<Option<String>> {
        self.reloaded
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(Some("order-sensitive reloaded".to_string()))
    }

    async fn divergences_after_rollback(
        &self,
        _ctx: &Context,
        _restored: &[PathBuf],
    ) -> Vec<RollbackDivergence> {
        if !self.reloaded.load(std::sync::atomic::Ordering::SeqCst) {
            return Vec::new();
        }
        vec![RollbackDivergence {
            divergence_plugin_id: "order-sensitive".to_string(),
            divergence_subject: "order proof".to_string(),
            divergence_state: DivergenceState::Diverged,
            divergence_detail: "reload_after_rollback had already run when this was asked"
                .to_string(),
        }]
    }
}

fn registry_with_order_sensitive() -> PluginRegistry {
    let registry = PluginRegistry::new();
    registry
        .register(Box::new(OrderSensitivePlugin::default()))
        .expect("the stub registers cleanly into an empty registry");
    registry
}

/// A stub that scopes itself the way every real probe must: it reports only
/// when a restored path is its own. This is the other half of
/// `an_unmatched_plugin_is_still_asked_what_diverged`, which on its own is
/// satisfied by a dispatch that asks everyone and a probe that answers
/// regardless of what was restored.
struct SelfScopingPlugin;

#[async_trait::async_trait]
impl HardeningPlugin for SelfScopingPlugin {
    fn metadata(&self) -> PluginMetadata {
        stub_metadata("self-scoping")
    }

    fn dependencies(&self) -> Vec<PluginId> {
        Vec::new()
    }

    async fn scan(&self, _ctx: &Context, _config: &PluginConfig) -> Result<ScanResult> {
        unreachable!("the dispatch never scans")
    }

    async fn apply(&self, _ctx: &mut Context, _config: &PluginConfig) -> Result<ApplyResult> {
        unreachable!("the dispatch never applies")
    }

    async fn validate(&self, _ctx: &Context, _config: &PluginConfig) -> Result<ValidationReport> {
        unreachable!("the dispatch never validates")
    }

    fn reloads_for_path(&self, path: &Path) -> bool {
        path == Path::new("/etc/scoped.conf")
    }

    async fn reload_after_rollback(&self, _ctx: &Context) -> Result<Option<String>> {
        Ok(None)
    }

    async fn divergences_after_rollback(
        &self,
        _ctx: &Context,
        restored: &[PathBuf],
    ) -> Vec<RollbackDivergence> {
        if !restored.iter().any(|path| self.reloads_for_path(path)) {
            return Vec::new();
        }
        vec![RollbackDivergence {
            divergence_plugin_id: "self-scoping".to_string(),
            divergence_subject: "a scoped subject".to_string(),
            divergence_state: DivergenceState::Diverged,
            divergence_detail: "a restored path was this plugin's own".to_string(),
        }]
    }
}

fn registry_with_self_scoping() -> PluginRegistry {
    let registry = PluginRegistry::new();
    registry
        .register(Box::new(SelfScopingPlugin))
        .expect("the stub registers cleanly into an empty registry");
    registry
}

/// **Order is fixed: reload first, probe second.** Swap the two statements
/// in `reconcile_plugins_after_rollback` and this stub's own reload never
/// runs before it is asked what diverged, so the row disappears and this
/// assertion fails.
#[tokio::test]
async fn the_reload_runs_before_the_divergence_probe() {
    let registry = registry_with_order_sensitive();
    let ctx = Context::with_executor(Arc::new(MockExecutor::new()));

    let outcome =
        reconcile_plugins_after_rollback(&ctx, &registry, &[PathBuf::from("/etc/order.conf")])
            .await;

    assert_eq!(
        outcome.divergences.len(),
        1,
        "the probe must run after the reload, so it should see the reload having already \
         happened: {:?}",
        outcome.divergences
    );
}

/// The two questions are independent. A plugin with nothing to reload is
/// still asked what it left diverged.
#[tokio::test]
async fn a_plugin_with_nothing_to_reload_is_still_asked_what_diverged() {
    let registry = registry_with_diverged();
    let ctx = Context::with_executor(Arc::new(MockExecutor::new()));

    let outcome =
        reconcile_plugins_after_rollback(&ctx, &registry, &[PathBuf::from("/etc/diverged.conf")])
            .await;

    assert!(
        outcome.reloads.is_empty(),
        "nothing was reloaded, so no reload row is produced"
    );
    assert_eq!(
        outcome.divergences.len(),
        1,
        "and the divergence is still reported"
    );
}

/// A plugin no restored path matched is asked what diverged anyway.
///
/// The reload predicate answers "does restoring this path oblige me to
/// reload?". The divergence question needs "is this path my business?", and
/// the two come apart for exactly the plugins that have no reload:
/// `permissions-hardening` and `pam-hardening` override neither, so under the
/// old gate they could never be asked and their answer could never be
/// measured. Scoping now belongs to the probe, which already receives
/// `restored` for the purpose.
#[tokio::test]
async fn an_unmatched_plugin_is_still_asked_what_diverged() {
    let registry = registry_with_diverged();
    let ctx = Context::with_executor(Arc::new(MockExecutor::new()));

    let outcome =
        reconcile_plugins_after_rollback(&ctx, &registry, &[PathBuf::from("/etc/other.conf")])
            .await;

    assert!(
        outcome.reloads.is_empty(),
        "no restored path matched, so nothing is reloaded"
    );
    assert_eq!(
        outcome.divergences.len(),
        1,
        "but the probe is asked, and this stub reports without consulting `restored`"
    );
}

/// The probe declines when nothing restored was its own, and reports when
/// something was. Both halves, because the empty half alone is satisfied by a
/// probe that can never report anything at all.
#[tokio::test]
async fn a_self_scoping_probe_declines_paths_that_are_not_its_own() {
    let ctx = Context::with_executor(Arc::new(MockExecutor::new()));

    let unrelated = reconcile_plugins_after_rollback(
        &ctx,
        &registry_with_self_scoping(),
        &[PathBuf::from("/etc/other.conf")],
    )
    .await;
    assert!(
        unrelated.divergences.is_empty(),
        "no restored path was this plugin's own"
    );

    let owned = reconcile_plugins_after_rollback(
        &ctx,
        &registry_with_self_scoping(),
        &[PathBuf::from("/etc/scoped.conf")],
    )
    .await;
    assert_eq!(
        owned.divergences.len(),
        1,
        "and the same probe reports when a restored path was its own"
    );
}

#[tokio::test]
async fn the_plugin_owning_a_restored_path_is_reloaded() {
    let ctx = Context::with_executor(Arc::new(MockExecutor::new()));
    let registry = registry_with_alpha_and_beta();
    let restored = vec![PathBuf::from("/etc/alpha/config")];

    let results = reconcile_plugins_after_rollback(&ctx, &registry, &restored)
        .await
        .reloads;

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

    let results = reconcile_plugins_after_rollback(&ctx, &registry, &restored)
        .await
        .reloads;

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

    let results = reconcile_plugins_after_rollback(&ctx, &registry, &restored)
        .await
        .reloads;

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

    let results = reconcile_plugins_after_rollback(&ctx, &registry, &restored)
        .await
        .reloads;

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

    let results = reconcile_plugins_after_rollback(&ctx, &registry, &restored)
        .await
        .reloads;

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
