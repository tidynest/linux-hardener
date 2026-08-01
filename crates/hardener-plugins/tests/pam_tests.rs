//! Integration tests for PAM hardening plugin

use hardener_core::{Context, PluginConfig, plugin::HardeningPlugin};
use hardener_plugins::PamHardeningPlugin;

#[test]
fn test_pam_plugin_metadata() {
    let plugin = PamHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id.to_string(), "pam-hardening");
    assert_eq!(metadata.plugin_name, "PAM Authentication Hardening");
    assert_eq!(metadata.plugin_version, env!("CARGO_PKG_VERSION"));
    assert!(metadata.plugin_description.contains("PAM"));
}

#[test]
fn test_pam_plugin_has_no_dependencies() {
    let plugin = PamHardeningPlugin::new();
    let dependencies = plugin.dependencies();

    assert_eq!(
        dependencies.len(),
        0,
        "PAM plugin should have no dependencies"
    );
}

#[tokio::test]
async fn pam_scan_on_this_host_smoke_test() {
    let plugin = PamHardeningPlugin::new();
    let context = Context::new();

    // A declared environment smoke test, and named so nobody grows it back: it
    // scans whatever `/etc/pam.d` and `/etc/security` the host executing it
    // happens to have, so the only things it may assert are the ones true on
    // every host. What the scan finds in a known configuration is settled
    // deterministically in `pam_mock_tests.rs`, where the executor is a fixture
    // instead of a machine. An unprivileged run here finds seven findings on an
    // Arch host that loads neither pam_pwquality nor pam_pwhistory, and none on
    // a host configured otherwise, which is precisely why no count belongs here.
    let scan_result = plugin
        .scan(&context, &PluginConfig::default())
        .await
        .expect("the pam scan reports an incomplete run through ScanResult, never as Err");

    assert_eq!(scan_result.scan_plugin_id.to_string(), "pam-hardening");
    assert!(
        scan_result.scan_duration_us > 0,
        "scan duration should be captured"
    );

    // Deliberately NOT asserted here: that `scan_success` and `scan_error` stay
    // distinguishable. `pam/mod.rs` builds its one and only `ScanResult` with
    // both written as literals, `scan_success: true` beside `scan_error: None`,
    // so that comparison is `true == true` on every host there will ever be. It
    // reads like an invariant and is a check that cannot fail, which is the same
    // fault as the conditional assertions this test was rewritten to remove.
}

#[tokio::test]
async fn test_pam_validate_checks_config_files() {
    let plugin = PamHardeningPlugin::new();
    let context = Context::new();
    let config = PluginConfig::default();

    // Run validation
    let result = plugin.validate(&context, &config).await;

    assert!(
        result.is_ok(),
        "Validation should succeed: {:?}",
        result.err()
    );

    let validation_report = result.unwrap();
    assert_eq!(
        validation_report.validation_report_plugin_id.to_string(),
        "pam-hardening"
    );

    // Validate examines every PAM directive and files each into exactly one of
    // pending / already-compliant / issues, so their total is non-zero on any
    // host. (It is not "estimated_changes must be non-empty": a fully compliant
    // host legitimately has zero pending changes, with every directive counted
    // in validation_report_compliant_count instead.)
    let examined = validation_report.validation_report_estimated_changes.len()
        + validation_report.validation_report_compliant_count
        + validation_report.validation_report_issues.len();
    assert!(examined > 0, "validate should examine the PAM directives");
}

#[tokio::test]
#[ignore = "Requires root privileges and modifies system PAM configuration"]
async fn test_pam_apply_requires_root() {
    let plugin = PamHardeningPlugin::new();
    let mut context = Context::new();
    let config = PluginConfig::default();

    // Run only under `--ignored` as root, so a failure here is a real failure
    // rather than a missing privilege. The `Err` arm used to swallow it with a
    // note about not running as root, which made the one run that is supposed
    // to exercise apply exit 0 having asserted nothing at all.
    let result = plugin.apply(&mut context, &config).await;

    match result {
        Ok(apply_result) => {
            assert_eq!(apply_result.apply_plugin_id.to_string(), "pam-hardening");
            assert!(
                !apply_result.apply_changes.is_empty(),
                "Should have made changes"
            );
        }
        Err(e) => {
            panic!("PAM apply failed: {e}");
        }
    }
}
