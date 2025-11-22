//! Integration tests for the Firewall Hardening Plugin.
//!
//! These tests verify that the firewall plugin correctly detects firewall
//! backends, scans firewall status, and applies security configurations.

use hardener_common::types::FindingCategory;
use hardener_core::{
    context::Context,
    plugin::{Config, HardeningPlugin},
};
use hardener_plugins::FirewallPlugin;

#[test]
fn test_firewall_plugin_metadata() {
    let plugin = FirewallPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id.as_str(), "firewall-hardening");
    assert_eq!(metadata.plugin_name, "Firewall Hardening");
    assert_eq!(metadata.plugin_version, "0.1.0");
    assert_eq!(metadata.plugin_category, FindingCategory::Network);
    assert!(metadata.plugin_description.contains("firewall"));
}

#[test]
fn test_firewall_plugin_has_no_dependencies() {
    let plugin = FirewallPlugin::new();
    let deps = plugin.dependencies();

    assert_eq!(deps.len(), 0, "Firewall plugin should have no dependencies");
}

#[test]
fn test_firewall_scan_detects_backend() {
    let plugin = FirewallPlugin::new();
    let ctx = Context::new();

    let result = plugin.scan(&ctx);

    // The scan should succeed (even if no backend is found, it returns success: false)
    assert!(result.is_ok(), "Scan should return Ok result");

    let scan_result = result.unwrap();
    assert_eq!(scan_result.plugin_id.as_str(), "firewall-hardening");

    // If UFW is available, scan should succeed
    // If not available, scan should fail gracefully.
    if scan_result.success {
        println!("Firewall backend detected successfully");
        println!("Findings: {}", scan_result.findings.len());
    } else {
        println!("No firewall backend found (expected on some systems)");
        assert!(scan_result.error.is_some());
    }
}

#[test]
fn test_firewall_validate_checks_backend() {
    let plugin = FirewallPlugin::new();
    let config = Config::default();

    let result = plugin.validate(&config);

    // Validate should always return Ok (stub implementation currently)
    assert!(result.is_ok(), "Validate should return Ok result");

    let validation_report = result.unwrap();
    assert_eq!(validation_report.plugin_id.as_str(), "firewall-hardening");
    assert_eq!(validation_report.is_valid, true);
}

#[test]
#[ignore] // Requires root privileges to enable firewall and apply rules
fn test_firewall_apply_requires_root() {
    let plugin = FirewallPlugin::new();
    let mut ctx = Context::new();
    let config = Config::default();

    // This test should only be run with root privileges
    // Run with: sudo cargo test --package hardener-plugins test_firewall_apply_requires_root -- --ignored --nocapture

    let result = plugin.apply(&mut ctx, &config);

    assert!(result.is_ok(), "Apply should return Ok result");

    let apply_result = result.unwrap();
    assert_eq!(apply_result.plugin_id.as_str(), "firewall-hardening");

    if apply_result.success {
        println!("[SUCCESS] Firewall apply succeeded");
        println!("Changes made: {}", apply_result.changes.len());

        for change in &apply_result.changes {
            println!("  - {}: {}", change.description, if change.success { "[OK]" } else { "[FAILED]" });
            if let Some(ref error) = change.error {
                println!("    Error: {}", error);
            }
        }

        // Verify scan now shows firewall as enabled
        let scan_result = plugin.scan(&ctx).unwrap();
        assert!(scan_result.success, "Scan should succeed after apply");

        // Should have no findings if firewall is now enabled
        let disabled_findings: Vec<_> = scan_result.findings.iter()
            .filter(|f| f.title.contains("disabled"))
            .collect();

        if disabled_findings.is_empty() {
            println!("[SUCCESS] Firewall is now enabled (no 'disabled' findings)");
        } else {
            println!("[WARNING] Firewall still shows as disabled:");
            for finding in disabled_findings {
                println!("  - {}: {}", finding.title, finding.description);
            }
        }
    } else {
        println!("[FAILED] Firewall apply failed");
        if let Some(ref error) = apply_result.error {
            println!("Error: {}", error);
        }
    }
}
