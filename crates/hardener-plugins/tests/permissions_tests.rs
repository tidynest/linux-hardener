//! Integration tests for File Permissions Hardening plugin

use hardener_core::{PluginConfig, Context, plugin::HardeningPlugin};
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

#[tokio::test]
async fn test_permissions_scan_checks_paths() {
    let plugin = PermissionsHardeningPlugin::new();
    let context = Context::new();

    // Run scan
    let result = plugin.scan(&context).await;

    // Should succeed
    assert!(result.is_ok(), "Scan should succeed: {:?}", result.err());

    let scan_result = result.unwrap();
    assert!(
        scan_result.scan_success,
        "Scan should be marked as successful"
    );
    assert_eq!(
        scan_result.scan_plugin_id.to_string(),
        "permissions-hardening"
    );

    // Should check critical paths
    println!(
        "Permissions scan found {} findings",
        scan_result.scan_findings.len()
    );

    // Verify timing is captured
    assert!(
        scan_result.scan_duration_us > 0,
        "Scan duration should be captured"
    );

    // If findings exist, verify their structure
    for finding in &scan_result.scan_findings {
        assert!(
            !finding.finding_id.is_empty(),
            "Finding ID should not be empty"
        );
        assert!(
            !finding.finding_title.is_empty(),
            "Finding title should not be empty"
        );
        assert!(
            !finding.finding_description.is_empty(),
            "Finding description should not be empty"
        );
        assert!(
            !finding.finding_remediation_steps.is_empty(),
            "Should have remediation steps"
        );
    }
}

#[tokio::test]
async fn test_permissions_validate() {
    let plugin = PermissionsHardeningPlugin::new();
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
        "permissions-hardening"
    );

    println!(
        "Validation valid: {}",
        validation_report.validation_report_is_valid
    );
    println!(
        "Issues found: {}",
        validation_report.validation_report_issues.len()
    );
    println!(
        "Estimated changes: {}",
        validation_report.validation_report_estimated_changes.len()
    );

    // Validation should succeed (permissions plugin doesn't have config dependencies)
    assert!(
        validation_report.validation_report_is_valid,
        "Validation should be valid"
    );
    assert!(
        validation_report.validation_report_issues.is_empty(),
        "Valid validation should have no issues"
    );
}

#[tokio::test]
#[ignore = "Requires root privileges and modifies system file permissions"]
async fn test_permissions_apply_requires_root() {
    let plugin = PermissionsHardeningPlugin::new();
    let mut context = Context::new();
    let config = PluginConfig::default();

    // This will fail without root, or succeed with root
    let result = plugin.apply(&mut context, &config).await;

    match result {
        Ok(apply_result) => {
            println!("Permissions apply succeeded (running as root)");
            println!("Changes made: {}", apply_result.apply_changes.len());

            assert_eq!(
                apply_result.apply_plugin_id.to_string(),
                "permissions-hardening"
            );

            // Print all changes for manual verification
            for change in &apply_result.apply_changes {
                println!(
                    "  - [{}] {}",
                    if change.change_success { "✓" } else { "✗" },
                    change.change_description
                );
            }

            // Verify change structure if any changes were made
            for change in &apply_result.apply_changes {
                assert!(
                    !change.change_description.is_empty(),
                    "Change description should not be empty"
                );
            }
        }
        Err(e) => {
            println!("Permissions apply failed (likely not root): {:?}", e);
            // This is expected if not running as root
        }
    }
}
