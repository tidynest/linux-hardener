use hardener_common::types::FindingCategory;
use hardener_core::{
    Config,
    Context,
    plugin::HardeningPlugin,
};
use hardener_plugins::KernelHardeningPlugin;

#[test]
fn test_kernel_plugin_metadata() {
    let plugin = KernelHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.id.as_str(), "kernel");
    assert_eq!(metadata.name, "Kernel Hardening");
    assert_eq!(metadata.category, FindingCategory::Kernel);
    assert!(metadata.description.contains("sysctl"));
    assert!(!metadata.version.is_empty());
}

#[test]
fn test_kernel_plugin_has_no_dependencies() {
    let plugin = KernelHardeningPlugin::new();
    let deps = plugin.dependencies();

    assert_eq!(deps.len(), 0, "Kernel plugin should have no dependencies");
}

#[test]
fn test_kernel_scan_reads_parameters() {
    let plugin = KernelHardeningPlugin::new();
    let ctx = Context::new();

    let result = plugin.scan(&ctx);
    assert!(result.is_ok(), "Scan should succeed");

    let scan_result = result.unwrap();
    assert!(scan_result.success, "Scan should be successful");
    assert_eq!(scan_result.plugin_id.as_str(), "kernel");
    assert!(scan_result.duration_us > 0, "Should record scan duration in microseconds");
    println!(
        "Scan completed in {}µs ({}ms)",
        scan_result.duration_us, scan_result.duration_us / 1000
    );

    // Findings may or may not exist depending on current system state
    println!("Found {} insecure kernel parameters", scan_result.findings.len());

    // Verify finding structure if any exist
    if let Some(finding) = scan_result.findings.first() {
        assert!(!finding.current_value.is_empty());
        assert!(!finding.recommended_value.is_empty());
        assert!(!finding.explanation.is_empty());
        println!(
            "Example finding: {} (current: {}, recommended: {})",
                 finding.title, finding.current_value,
                 finding.recommended_value
        );
    }
}

#[test]
fn test_kernel_validate_checks_parameters() {
    let plugin = KernelHardeningPlugin::new();
    let config = Config::default();

    let result = plugin.validate(&config);
    assert!(result.is_ok(), "Validation should succeed");

    let validation = result.unwrap();
    assert_eq!(validation.plugin_id.as_str(), "kernel");

    // Should have estimated changes for parameters that can be modified
    assert!(!validation.estimated_changes.is_empty(), "Should estimate at least some changes");

    println!("Validation found {} potential issues", validation.issues.len());
    println!("Would make {} changes", validation.estimated_changes.len());

    // Show a few estimated changes
    for change in validation.estimated_changes.iter().take(3) {
        println!("  - {}", change);
    }
}

#[test]
#[ignore] // Run manually with: sudo cargo test kernel_apply -- --ignored --nocapture
fn test_kernel_apply_requires_root() {
    let plugin = KernelHardeningPlugin::new();
    let mut ctx = Context::new();
    let config = Config::default();

    let result = plugin.apply(&mut ctx, &config);

    // This test requires root - will fail without privileges
    match result {
        Ok(apply_result) => {
            println!("Apply succeeded!");
            println!("Plugin ID: {}", apply_result.plugin_id.as_str());
            println!("Overall success: {}", apply_result.success);
            println!("Changes made: {}", apply_result.changes.len());

            let successful = apply_result.changes.iter().filter(|c| c.success).count();
            let failed = apply_result.changes.iter().filter(|c| !c.success).count();

            println!("  Successful: {}", successful);
            println!("  Failed: {}", failed);

            for change in &apply_result.changes {
                println!(
                    "  {} {}",
                     if change.success { "✓" } else { "✗" },
                     change.description
                );
            }
        }
        Err(e) => {
            println!("Apply failed (may need root): {:?}", e);
        }
    }
}
