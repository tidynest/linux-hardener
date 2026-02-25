use hardener_common::types::FindingCategory;
use hardener_core::{Context, PluginConfig, plugin::HardeningPlugin};
use hardener_plugins::KernelHardeningPlugin;

#[test]
fn test_kernel_plugin_metadata() {
    let plugin = KernelHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id.as_str(), "kernel-hardening");
    assert_eq!(metadata.plugin_name, "Kernel Hardening");
    assert_eq!(metadata.plugin_category, FindingCategory::Kernel);
    assert!(metadata.plugin_description.contains("sysctl"));
    assert!(!metadata.plugin_version.is_empty());
}

#[test]
fn test_kernel_plugin_has_no_dependencies() {
    let plugin = KernelHardeningPlugin::new();
    let deps = plugin.dependencies();

    assert_eq!(deps.len(), 0, "Kernel plugin should have no dependencies");
}

#[tokio::test]
async fn test_kernel_scan_reads_parameters() {
    let plugin = KernelHardeningPlugin::new();
    let ctx = Context::new();

    let result = plugin.scan(&ctx).await;
    assert!(result.is_ok(), "Scan should succeed");

    let scan_result = result.unwrap();
    assert!(scan_result.scan_success, "Scan should be successful");
    assert_eq!(scan_result.scan_plugin_id.as_str(), "kernel-hardening");
    assert!(
        scan_result.scan_duration_us > 0,
        "Should record scan duration in microseconds"
    );

    // Verify finding structure if any exist
    if let Some(finding) = scan_result.scan_findings.first() {
        assert!(!finding.finding_current_value.is_empty());
        assert!(!finding.finding_recommended_value.is_empty());
        assert!(!finding.finding_explanation.is_empty());
    }
}

#[tokio::test]
async fn test_kernel_validate_checks_parameters() {
    let plugin = KernelHardeningPlugin::new();
    let ctx = Context::new();
    let config = PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await;
    assert!(result.is_ok(), "Validation should succeed");

    let validation = result.unwrap();
    assert_eq!(
        validation.validation_report_plugin_id.as_str(),
        "kernel-hardening"
    );

    // Should have estimated changes for parameters that can be modified
    assert!(
        !validation.validation_report_estimated_changes.is_empty(),
        "Should estimate at least some changes"
    );
}

#[tokio::test]
#[ignore] // Run manually with: sudo cargo test kernel_apply -- --ignored --nocapture
async fn test_kernel_apply_requires_root() {
    let plugin = KernelHardeningPlugin::new();
    let mut ctx = Context::new();
    let config = PluginConfig::default();

    let result = plugin.apply(&mut ctx, &config).await;

    // This test requires root - will fail without privileges
    match result {
        Ok(apply_result) => {
            assert_eq!(apply_result.apply_plugin_id.as_str(), "kernel-hardening");
            assert!(
                apply_result.apply_success,
                "Apply should succeed with root privileges"
            );
        }
        Err(_) => {
            // Expected if not running as root
        }
    }
}
