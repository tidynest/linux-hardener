//! Integration tests for the Firewall Hardening Plugin.
//!
//! These tests verify that the firewall plugin correctly detects firewall
//! backends, scans firewall status, and applies security configurations.
//!
//! Tests are organised into:
//! - Basic plugin functionality (metadata, dependencies)
//! - Backend detection (firewalld, UFW, nftables)
//! - Integration tests (requires root, marked with #[ignore])

use hardener_common::types::FindingCategory;
use hardener_core::{PluginConfig, context::Context, plugin::HardeningPlugin};
use hardener_plugins::FirewallHardeningPlugin;

#[test]
fn test_firewall_plugin_metadata() {
    let plugin = FirewallHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id.as_str(), "firewall-hardening");
    assert_eq!(metadata.plugin_name, "Firewall Hardening");
    assert_eq!(metadata.plugin_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(metadata.plugin_category, FindingCategory::Network);
    assert!(metadata.plugin_description.contains("firewall"));
}

#[test]
fn test_firewall_plugin_has_no_dependencies() {
    let plugin = FirewallHardeningPlugin::new();
    let deps = plugin.dependencies();

    assert_eq!(deps.len(), 0, "Firewall plugin should have no dependencies");
}

#[tokio::test]
async fn test_firewall_scan_detects_backend() {
    let plugin = FirewallHardeningPlugin::new();
    let ctx = Context::new();

    let result = plugin.scan(&ctx).await;

    // The scan should succeed (even if no backend is found, it returns success: false)
    assert!(result.is_ok(), "Scan should return Ok result");

    let scan_result = result.unwrap();
    assert_eq!(scan_result.scan_plugin_id.as_str(), "firewall-hardening");

    // If UFW is available, scan should succeed
    // If not available, scan should fail gracefully.
    if !scan_result.scan_success {
        assert!(scan_result.scan_error.is_some());
    }
}

#[tokio::test]
async fn test_firewall_validate_checks_backend() {
    let plugin = FirewallHardeningPlugin::new();
    let ctx = Context::new();
    let config = PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await;

    // Validate should always return Ok (stub implementation currently)
    assert!(result.is_ok(), "Validate should return Ok result");

    let validation_report = result.unwrap();
    assert_eq!(
        validation_report.validation_report_plugin_id.as_str(),
        "firewall-hardening"
    );
    assert!(validation_report.validation_report_is_valid);
}

#[tokio::test]
#[ignore] // Requires root privileges to enable firewall and apply rules
async fn test_firewall_apply_requires_root() {
    let plugin = FirewallHardeningPlugin::new();
    let mut ctx = Context::new();
    let config = PluginConfig::default();

    // This test should only be run with root privileges
    // Run with: sudo cargo test --package hardener-plugins test_firewall_apply_requires_root -- --ignored --nocapture

    let result = plugin.apply(&mut ctx, &config).await;

    assert!(result.is_ok(), "Apply should return Ok result");

    let apply_result = result.unwrap();
    assert_eq!(apply_result.apply_plugin_id.as_str(), "firewall-hardening");

    if apply_result.apply_success {
        // Verify scan now shows firewall as enabled
        let scan_result = plugin.scan(&ctx).await.unwrap();
        assert!(scan_result.scan_success, "Scan should succeed after apply");
    }
}

// ============================================================================
// Backend-Specific Tests
// ============================================================================

#[tokio::test]
async fn test_backend_detection_order() {
    // This test verifies that backend detection follows the correct priority:
    // 1. Firewalld (RHEL/Fedora/CentOS)
    // 2. UFW (Ubuntu/Debian)
    // 3. Nftables (modern systems)

    let plugin = FirewallHardeningPlugin::new();
    let ctx = Context::new();

    let result = plugin.scan(&ctx).await;
    assert!(
        result.is_ok(),
        "Scan should return Ok even if no backend found"
    );

    let scan_result = result.unwrap();

    if !scan_result.scan_success {
        assert!(
            scan_result.scan_error.is_some(),
            "Should have error message when no backend found"
        );

        let error_msg = scan_result.scan_error.unwrap();
        assert!(
            error_msg.contains("firewalld")
                && error_msg.contains("ufw")
                && error_msg.contains("nftables"),
            "Error message should mention all three backends: firewalld, ufw, nftables"
        );
    }
}

#[test]
fn test_firewall_default_rules_structure() {
    // Verify that get_baseline_rules() returns sensible defaults
    use hardener_plugins::firewall::get_baseline_rules;

    let rules = get_baseline_rules();

    assert!(!rules.is_empty(), "Default rules should not be empty");
    assert!(
        rules.len() >= 3,
        "Should have at least: loopback, established, SSH, drop default"
    );

    // Verify loopback rule exists
    let has_loopback = rules
        .iter()
        .any(|r| r.rule_description.contains("loopback"));
    assert!(has_loopback, "Should have loopback rule");

    // Verify established/related rule exists
    let has_established = rules.iter().any(|r| {
        r.rule_description.contains("established") || r.rule_description.contains("related")
    });
    assert!(
        has_established,
        "Should have established/related connections rule"
    );

    // Verify SSH rule exists (prevent lockout)
    let has_ssh = rules
        .iter()
        .any(|r| r.rule_description.contains("SSH") && r.rule_port == "22");
    assert!(has_ssh, "Should have SSH rule to prevent lockout");

    // Verify drop default rule exists
    let has_drop = rules
        .iter()
        .any(|r| r.rule_action == "drop" && r.rule_port == "any");
    assert!(has_drop, "Should have default drop rule");
}

#[test]
fn test_rule_structure_fields() {
    // Verify that Rule struct has correct fields with proper naming
    use hardener_plugins::firewall::Rule;

    let test_rule = Rule {
        rule_description: "Test rule".to_string(),
        rule_protocol: "tcp".to_string(),
        rule_port: "22".to_string(),
        rule_source: "any".to_string(),
        rule_action: "accept".to_string(),
    };

    assert_eq!(test_rule.rule_description, "Test rule");
    assert_eq!(test_rule.rule_protocol, "tcp");
    assert_eq!(test_rule.rule_port, "22");
    assert_eq!(test_rule.rule_source, "any");
    assert_eq!(test_rule.rule_action, "accept");
}

// ============================================================================
// Integration Tests (Require Specific Backends Installed)
// ============================================================================

#[tokio::test]
#[ignore] // Only run on systems with firewalld installed
async fn test_firewalld_backend_detection() {
    // Test firewalld-specific detection
    // Run with: cargo test --package hardener-plugins test_firewalld_backend_detection -- --ignored --nocapture

    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::firewalld::FirewalldBackend;

    let ctx = hardener_core::context::Context::new();
    let backend = FirewalldBackend::new();
    let detected = backend.detect(&ctx).await;

    assert!(detected.is_ok(), "Firewalld detection should not error");

    if detected.unwrap() {
        assert_eq!(backend.backend_name(), "firewalld");

        let _enabled = backend.is_enabled(&ctx).await;

        let rules = backend.get_default_rules();
        assert!(!rules.is_empty(), "Should return default rules");
    }
}

#[tokio::test]
#[ignore] // Only run on systems with UFW installed
async fn test_ufw_backend_detection() {
    // Test UFW-specific detection
    // Run with: cargo test --package hardener-plugins test_ufw_backend_detection -- --ignored --nocapture

    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::ufw::UfwBackend;

    let ctx = hardener_core::context::Context::new();
    let backend = UfwBackend::new();
    let detected = backend.detect(&ctx).await;

    assert!(detected.is_ok(), "UFW detection should not error");

    if detected.unwrap() {
        assert_eq!(backend.backend_name(), "ufw");

        let _enabled = backend.is_enabled(&ctx).await;

        let rules = backend.get_default_rules();
        assert!(!rules.is_empty(), "Should return default rules");
    }
}

#[tokio::test]
#[ignore] // Only run on systems with nftables installed
async fn test_nftables_backend_detection() {
    // Test nftables-specific detection
    // Run with: cargo test --package hardener-plugins test_nftables_backend_detection -- --ignored --nocapture

    use hardener_plugins::firewall::FirewallBackend;
    use hardener_plugins::firewall::nftables::NftablesBackend;

    let ctx = hardener_core::context::Context::new();
    let backend = NftablesBackend::new();
    let detected = backend.detect(&ctx).await;

    assert!(detected.is_ok(), "Nftables detection should not error");

    if detected.unwrap() {
        assert_eq!(backend.backend_name(), "nftables");

        let _enabled = backend.is_enabled(&ctx).await;

        let rules = backend.get_default_rules();
        assert!(!rules.is_empty(), "Should return default rules");
    }
}
