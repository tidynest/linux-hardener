//! Integration tests for MAC (Mandatory Access Control) Hardening plugin

use hardener_core::{Context, PluginConfig, plugin::HardeningPlugin};
use hardener_plugins::MacHardeningPlugin;

#[test]
fn test_mac_plugin_metadata() {
    let plugin = MacHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id.to_string(), "mac-hardening");
    assert_eq!(metadata.plugin_name, "MAC System Hardening");
    assert_eq!(metadata.plugin_version, env!("CARGO_PKG_VERSION"));
    assert!(metadata.plugin_description.contains("SELinux"));
    assert!(metadata.plugin_description.contains("AppArmor"));
}

#[test]
fn test_mac_plugin_has_no_dependencies() {
    let plugin = MacHardeningPlugin::new();
    let dependencies = plugin.dependencies();

    assert_eq!(
        dependencies.len(),
        0,
        "MAC plugin should have no dependencies"
    );
}

/// Declared environment smoke test: `Context::new()` is wired to the local
/// executor, so this runs against whatever host executes the suite and may
/// therefore assert only what holds on every host. That is the call returning
/// `Ok`, the result naming its own plugin, and a duration having been recorded.
/// The old name promised detection, which it never checked.
///
/// Whether a MAC system is present, and what a finding about it says, is a
/// property of the machine, so the deterministic coverage lives in
/// `mac_mock_tests.rs`, which pins SELinux enforcing, permissive and disabled,
/// AppArmor enforcing and complain, and the no-MAC host. The per-finding checks
/// that used to sit inside a `for` over `scan_findings` are gone because that
/// loop asserts nothing whatsoever on a host that returns no findings.
#[tokio::test]
async fn mac_scan_runs_against_the_host_smoke_test() {
    let plugin = MacHardeningPlugin::new();
    let context = Context::new();

    let scan_result = plugin
        .scan(&context, &PluginConfig::default())
        .await
        .expect("scan over the local executor should succeed");

    assert_eq!(scan_result.scan_plugin_id.to_string(), "mac-hardening");
    assert!(
        scan_result.scan_duration_us > 0,
        "Scan duration should be captured"
    );
}

/// Declared environment smoke test, and a deliberately thin one: it exists only
/// to prove that `validate` survives a round trip over the real local executor,
/// which no mock can show, since a `MockExecutor` never spawns `sestatus` or
/// `aa-status`. A `ValidationReport` carries no duration, so `Ok` and the plugin
/// id are the whole of what is host-invariant here.
///
/// It says nothing about validation itself on purpose. What validate decides is
/// pinned against fixed executors in `mac_mock_tests.rs`, for a host with
/// SELinux, a host with no MAC system at all, and a host whose detection
/// failed.
#[tokio::test]
async fn mac_validate_runs_against_the_host_smoke_test() {
    let plugin = MacHardeningPlugin::new();
    let context = Context::new();
    let config = PluginConfig::default();

    let validation_report = plugin
        .validate(&context, &config)
        .await
        .expect("validation over the local executor should succeed");

    assert_eq!(
        validation_report.validation_report_plugin_id.to_string(),
        "mac-hardening"
    );
}

/// Ignored, so it runs only when a maintainer deliberately runs it as root.
/// That is exactly why the failure arm panics: a test nobody watches must not
/// be able to report success for having done nothing, and the empty `Err(_)`
/// arm that used to sit here made "apply blew up" and "apply worked"
/// indistinguishable. The per-change assertions that used to hide inside a
/// `for` over `apply_changes` are in `mac_mock_tests.rs`, where the changes are
/// guaranteed to exist.
#[tokio::test]
#[ignore = "Requires root privileges and modifies MAC system configuration"]
async fn test_mac_apply_requires_root() {
    let plugin = MacHardeningPlugin::new();
    let mut context = Context::new();
    let config = PluginConfig::default();

    let result = plugin.apply(&mut context, &config).await;

    match result {
        Ok(apply_result) => {
            assert_eq!(apply_result.apply_plugin_id.to_string(), "mac-hardening");
        }
        Err(e) => {
            panic!("Apply failed: {e}");
        }
    }
}
