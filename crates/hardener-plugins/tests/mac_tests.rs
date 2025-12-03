//! Integration tests for MAC (Mandatory Access Control) Hardening plugin

use hardener_core::{Config, Context, plugin::HardeningPlugin};
use hardener_plugins::MacHardeningPlugin;
use tokio;

#[test]
fn test_mac_plugin_metadata() {
    let plugin = MacHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id.to_string(), "mac-hardening");
    assert_eq!(metadata.plugin_name, "MAC System Hardening");
    assert_eq!(metadata.plugin_version, "0.1.0");
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

#[tokio::test]
async fn test_mac_scan_detects_system() {
    let plugin = MacHardeningPlugin::new();
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
    assert_eq!(scan_result.scan_plugin_id.to_string(), "mac-hardening");

    // Should detect MAC system status
    println!(
        "MAC scan found {} findings",
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

        println!(
            "Finding: {} - {}",
            finding.finding_id, finding.finding_title
        );
        println!("  Current: {}", finding.finding_current_value);
        println!("  Recommended: {}", finding.finding_recommended_value);
    }
}

#[tokio::test]
async fn test_mac_validate() {
    let plugin = MacHardeningPlugin::new();
    let context = Context::new();
    let config = Config::default();

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
        "mac-hardening"
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

    // Print any validation issues
    for issue in &validation_report.validation_report_issues {
        println!("  Issue: {}", issue.validation_issue_message);
    }

    // Print estimated changes
    for change in &validation_report.validation_report_estimated_changes {
        println!("  Estimated change: {}", change);
    }
}

#[tokio::test]
#[ignore = "Requires root privileges and modifies MAC system configuration"]
async fn test_mac_apply_requires_root() {
    let plugin = MacHardeningPlugin::new();
    let mut context = Context::new();
    let config = Config::default();

    // This will fail without root, or succeed with root
    let result = plugin.apply(&mut context, &config).await;

    match result {
        Ok(apply_result) => {
            println!("MAC apply succeeded (running as root)");
            println!("Changes made: {}", apply_result.apply_changes.len());

            assert_eq!(apply_result.apply_plugin_id.to_string(), "mac-hardening");

            // Print all changes for manual verification
            for change in &apply_result.apply_changes {
                println!(
                    "  - [{}] {}",
                    if change.change_success { "✓" } else { "✗" },
                    change.change_description
                );
                if let Some(ref error) = change.change_error {
                    println!("    Error: {}", error);
                }
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
            println!("MAC apply failed (likely not root): {:?}", e);
            // This is expected if not running as root
        }
    }
}
