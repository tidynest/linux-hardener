//! Integration tests for Service Minimisation plugin

use hardener_core::{Config, Context, plugin::HardeningPlugin};
use hardener_plugins::ServicesHardeningPlugin;
use tokio;

#[test]
fn test_services_plugin_metadata() {
    let plugin = ServicesHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id.to_string(), "service-minimisation");
    assert_eq!(metadata.plugin_name, "Service Minimisation");
    assert_eq!(metadata.plugin_version, "0.1.0");
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

#[tokio::test]
async fn test_services_scan_detects_services() {
    let plugin = ServicesHardeningPlugin::new();
    let context = Context::new();

    // Run scan
    let result = plugin.scan(&context).await;

    // Should succeed even if systemctl isn't available (graceful degradation)
    assert!(result.is_ok(), "Scan should succeed: {:?}", result.err());

    let scan_result = result.unwrap();
    assert!(
        scan_result.scan_success,
        "Scan should be marked as successful"
    );
    assert_eq!(
        scan_result.scan_plugin_id.to_string(),
        "service-minimisation"
    );

    // Should have findings if any unnecessary services are enabled
    // (Most systems will have at least some of these services)
    println!(
        "Services scan found {} findings",
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
        assert_eq!(
            finding.finding_remediation_steps.len(),
            3,
            "Should have 3 remediation steps (stop, disable, mask)"
        );
    }
}

#[tokio::test]
async fn test_services_validate_checks_systemctl() {
    let plugin = ServicesHardeningPlugin::new();
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
        "service-minimisation"
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

    // If systemctl is available, should be valid
    if validation_report.validation_report_is_valid {
        assert!(
            validation_report.validation_report_issues.is_empty(),
            "Valid validation should have no issues"
        );
        // Estimated changes might be empty if no services need disabling
        println!(
            "Services to be disabled: {}",
            validation_report.validation_report_estimated_changes.len()
        );
    } else {
        // If systemctl is not available, should have a critical issue
        assert!(
            !validation_report.validation_report_issues.is_empty(),
            "Invalid validation should have issues"
        );
        assert!(
            validation_report
                .validation_report_issues
                .iter()
                .any(|i| i.validation_issue_message.contains("systemctl")),
            "Should mention systemctl in issues"
        );
    }
}

#[tokio::test]
#[ignore = "Requires root privileges and modifies system services"]
async fn test_services_apply_requires_root() {
    let plugin = ServicesHardeningPlugin::new();
    let mut context = Context::new();
    let config = Config::default();

    // This will fail without root, or succeed with root
    let result = plugin.apply(&mut context, &config).await;

    match result {
        Ok(apply_result) => {
            println!("Services apply succeeded (running as root)");
            println!("Changes made: {}", apply_result.apply_changes.len());

            assert_eq!(
                apply_result.apply_plugin_id.to_string(),
                "service-minimisation"
            );

            // Print all changes for manual verification
            for change in &apply_result.apply_changes {
                println!(
                    "  - [{}] {}",
                    if change.change_success { "" } else { "" },
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
            println!("Services apply failed (likely not root): {:?}", e);
            // This is expected if not running as root
        }
    }
}
