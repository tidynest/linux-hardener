//! Integration tests for Service Minimisation plugin.
//!
//! The scan and validate tests here run against whichever host executes the
//! suite, so they may assert only what holds on every host: the call came
//! back, it named its own plugin, and it timed itself. Which services are
//! installed, whether systemd answers at all, and what a finding looks like
//! are host state, and are pinned deterministically in
//! `services_mock_tests.rs` where a `MockExecutor` supplies that state.

use hardener_core::{Context, PluginConfig, plugin::HardeningPlugin};
use hardener_plugins::ServicesHardeningPlugin;

#[test]
fn test_services_plugin_metadata() {
    let plugin = ServicesHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id.to_string(), "service-minimisation");
    assert_eq!(metadata.plugin_name, "Service Minimisation");
    assert_eq!(metadata.plugin_version, env!("CARGO_PKG_VERSION"));
    assert!(metadata.plugin_description.contains("systemd services"));
}

#[test]
fn test_services_plugin_has_no_dependencies() {
    let plugin = ServicesHardeningPlugin::new();
    let dependencies = plugin.dependencies();

    assert_eq!(
        dependencies.len(),
        0,
        "Services plugin should have no dependencies"
    );
}

/// Success is deliberately not asserted: a host whose unit listing fails
/// reports an unsuccessful scan on purpose, so demanding success here would
/// fail the suite for doing the right thing. Both verdicts are driven from
/// mocks instead.
#[tokio::test]
async fn services_scan_on_the_host_smoke_test() {
    let plugin = ServicesHardeningPlugin::new();
    let context = Context::new();

    let scan_result = plugin
        .scan(&context, &PluginConfig::default())
        .await
        .expect("scan must return Ok even where systemctl is absent");

    assert_eq!(
        scan_result.scan_plugin_id.to_string(),
        "service-minimisation"
    );
    assert!(
        scan_result.scan_duration_us > 0,
        "the scan must record how long it took"
    );
}

/// Validity is deliberately not asserted, in either direction: it tracks
/// whether the executing host has systemctl. Both answers, and the wording of
/// the missing-systemctl issue, are covered from mocks.
#[tokio::test]
async fn services_validate_on_the_host_smoke_test() {
    let plugin = ServicesHardeningPlugin::new();
    let context = Context::new();
    let config = PluginConfig::default();

    let validation_report = plugin
        .validate(&context, &config)
        .await
        .expect("validate must return Ok even where systemctl is absent");

    assert_eq!(
        validation_report.validation_report_plugin_id.to_string(),
        "service-minimisation"
    );
}

#[tokio::test]
#[ignore = "Requires root privileges and modifies system services"]
async fn test_services_apply_requires_root() {
    let plugin = ServicesHardeningPlugin::new();
    let mut context = Context::new();
    let config = PluginConfig::default();

    let result = plugin.apply(&mut context, &config).await;

    match result {
        Ok(apply_result) => {
            assert_eq!(
                apply_result.apply_plugin_id.to_string(),
                "service-minimisation"
            );

            // A privileged run that could not carry out its own plan is the
            // outcome this test exists to catch. The empty `Err` arm this
            // replaces swallowed exactly that, so the test passed by having
            // asserted nothing.
            assert!(
                apply_result.apply_success,
                "all changes should succeed with root privileges"
            );
            assert!(
                apply_result.apply_error.is_none(),
                "should not have overall error"
            );
        }
        Err(e) => panic!("Apply failed: {e}"),
    }
}
