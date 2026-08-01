//! Integration tests for File Permissions Hardening plugin

use hardener_core::{Context, PluginConfig, plugin::HardeningPlugin};
use hardener_plugins::PermissionsHardeningPlugin;

#[test]
fn test_permissions_plugin_metadata() {
    let plugin = PermissionsHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id.to_string(), "permissions-hardening");
    assert_eq!(metadata.plugin_name, "File Permissions Hardening");
    assert_eq!(metadata.plugin_version, env!("CARGO_PKG_VERSION"));
    assert!(metadata.plugin_description.contains("permissions"));
}

#[test]
fn test_permissions_plugin_has_no_dependencies() {
    let plugin = PermissionsHardeningPlugin::new();
    let dependencies = plugin.dependencies();

    assert_eq!(
        dependencies.len(),
        0,
        "Permissions plugin should have no dependencies"
    );
}

/// Declared environment smoke test: `Context::new()` is wired to the local
/// executor, so this runs against whatever host executes the suite and may
/// therefore assert only what holds on every host. That is the call returning
/// `Ok`, the result naming its own plugin, and a duration having been recorded.
///
/// Everything about the findings themselves is a property of the permissions
/// the running machine happens to carry, so the deterministic coverage lives in
/// `permissions_mock_tests.rs`, where a `MockExecutor` decides what `/etc` looks
/// like. The per-finding checks that used to sit inside a `for` over
/// `scan_findings` are gone because that loop asserts nothing at all on a host
/// with no violations, which is the "passing by skipping" shape this suite is
/// not allowed to have.
#[tokio::test]
async fn permissions_scan_runs_against_the_host_smoke_test() {
    let plugin = PermissionsHardeningPlugin::new();
    let context = Context::new();

    let scan_result = plugin
        .scan(&context, &PluginConfig::default())
        .await
        .expect("scan over the local executor should succeed");

    assert_eq!(
        scan_result.scan_plugin_id.to_string(),
        "permissions-hardening"
    );
    assert!(
        scan_result.scan_duration_us > 0,
        "Scan duration should be captured"
    );
}

/// Declared environment smoke test under the same limits as the scan above: it
/// runs against the executing host, so `Ok` and the plugin id are the only
/// host-invariants available to it. A `ValidationReport` carries no duration.
///
/// The removed assertions claimed the report is always valid with no issues
/// "because the permissions plugin doesn't have config dependencies". Validity
/// has nothing to do with config here: `validate` raises a High issue for any
/// critical path whose existence the executor could not determine, and
/// `validation_report_is_valid` is precisely "no High issue". Those two
/// assertions were therefore asserting that the developer's `/etc` was entirely
/// stat-able. Both outcomes are pinned against a mock executor in
/// `permissions_mock_tests.rs`.
#[tokio::test]
async fn permissions_validate_runs_against_the_host_smoke_test() {
    let plugin = PermissionsHardeningPlugin::new();
    let context = Context::new();
    let config = PluginConfig::default();

    let validation_report = plugin
        .validate(&context, &config)
        .await
        .expect("validation over the local executor should succeed");

    assert_eq!(
        validation_report.validation_report_plugin_id.to_string(),
        "permissions-hardening"
    );
}

/// Ignored, so it runs only when a maintainer deliberately runs it as root.
/// That is exactly why the failure arm panics: a test nobody watches must not
/// be able to report success for having done nothing, and the empty `Err(_)`
/// arm that used to sit here made "apply blew up" and "apply worked"
/// indistinguishable. The per-change assertions that used to hide inside a
/// `for` over `apply_changes` are in `permissions_mock_tests.rs`, where the
/// changes are guaranteed to exist.
#[tokio::test]
#[ignore = "Requires root privileges and modifies system file permissions"]
async fn test_permissions_apply_requires_root() {
    let plugin = PermissionsHardeningPlugin::new();
    let mut context = Context::new();
    let config = PluginConfig::default();

    let result = plugin.apply(&mut context, &config).await;

    match result {
        Ok(apply_result) => {
            assert_eq!(
                apply_result.apply_plugin_id.to_string(),
                "permissions-hardening"
            );
        }
        Err(e) => {
            panic!("Apply failed: {e}");
        }
    }
}
