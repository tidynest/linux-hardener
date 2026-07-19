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
async fn test_pam_scan_reads_configuration() {
    let plugin = PamHardeningPlugin::new();
    let context = Context::new();

    // Run scan
    let result = plugin.scan(&context).await;

    // Should succeed even if files don't exist (graceful degradation)
    assert!(result.is_ok(), "Scan should succeed: {:?}", result.err());

    let scan_result = result.unwrap();
    assert!(
        scan_result.scan_success,
        "Scan should be marked as successful"
    );
    assert_eq!(scan_result.scan_plugin_id.to_string(), "pam-hardening");

    // Verify timing is captured
    assert!(
        scan_result.scan_duration_us > 0,
        "Scan duration should be captured"
    );
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

    // This will fail without root, or succeed with root
    let result = plugin.apply(&mut context, &config).await;

    match result {
        Ok(apply_result) => {
            assert_eq!(apply_result.apply_plugin_id.to_string(), "pam-hardening");
            assert!(
                !apply_result.apply_changes.is_empty(),
                "Should have made changes"
            );
        }
        Err(_) => {
            // This is expected if not running as root
        }
    }
}
