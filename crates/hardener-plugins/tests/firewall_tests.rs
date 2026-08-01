//! Integration tests for the Firewall Hardening Plugin.
//!
//! Tests are organised into:
//! - Pure tests over metadata and the baseline rule set, which read no host
//! - Host smoke tests, which run against whatever machine executes them
//! - Tests needing root or a named backend, all `#[ignore]`d
//!
//! The deterministic coverage lives in `firewall_mock_tests.rs`, where a
//! `MockExecutor` supplies the host state. Nothing in this file may assert on
//! host state: an assertion that passes or fails according to the developer's
//! box reports the box rather than the code, and one guarded by `if` reports
//! nothing at all on the hosts that skip it.

use hardener_common::types::FindingCategory;
use hardener_core::{PluginConfig, context::Context, plugin::HardeningPlugin};
use hardener_plugins::FirewallHardeningPlugin;
use hardener_plugins::firewall::FirewallBackend;

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

/// Runs the real scan against whichever host executes the suite, so it may
/// assert only what holds on every host: the call came back, it named its own
/// plugin, and it timed itself. Whether a backend is installed, whether it is
/// enforcing, and what the no-backend error says are all host state, pinned
/// deterministically in `firewall_mock_tests.rs`.
#[tokio::test]
async fn firewall_scan_on_the_host_smoke_test() {
    let plugin = FirewallHardeningPlugin::new();
    let ctx = Context::new();

    let scan_result = plugin
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("scan must return Ok whether or not the host has a backend");

    assert_eq!(scan_result.scan_plugin_id.as_str(), "firewall-hardening");
    assert!(
        scan_result.scan_duration_us > 0,
        "the scan must record how long it took"
    );
}

/// The dry-run preview against the executing host, held to the same limit as
/// the scan smoke test above. Validity is deliberately not asserted: a host
/// with no backend at all earns a Critical issue and an invalid report, which
/// is correct behaviour rather than a regression. The valid and invalid
/// verdicts are both driven from mocks in `firewall_mock_tests.rs`.
#[tokio::test]
async fn firewall_validate_on_the_host_smoke_test() {
    let plugin = FirewallHardeningPlugin::new();
    let ctx = Context::new();
    let config = PluginConfig::default();

    let validation_report = plugin
        .validate(&ctx, &config)
        .await
        .expect("validate must return Ok whether or not the host has a backend");

    assert_eq!(
        validation_report.validation_report_plugin_id.as_str(),
        "firewall-hardening"
    );
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

    match result {
        Ok(apply_result) => {
            assert_eq!(apply_result.apply_plugin_id.as_str(), "firewall-hardening");

            // Asserted flatly, not behind `if apply_result.apply_success`: a
            // privileged run that failed to harden the firewall is the single
            // outcome this test exists to catch, and guarding the checks on
            // success let exactly that outcome exit green.
            assert!(
                apply_result.apply_success,
                "all changes should succeed with root privileges"
            );
            assert!(
                apply_result.apply_error.is_none(),
                "should not have overall error"
            );

            let scan_result = plugin
                .scan(&ctx, &PluginConfig::default())
                .await
                .expect("scan after apply must return Ok");
            assert!(scan_result.scan_success, "scan should succeed after apply");
        }
        Err(e) => panic!("Apply failed: {e}"),
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

/// The host-free half of the three backend smoke tests below, which differ
/// only in the backend under test. Both checks are pure: a backend knows its
/// own name and carries a baseline rule set without being asked anything about
/// the machine.
///
/// Whether the backend is installed, and whether it is enforcing, are host
/// state and are asserted nowhere in this file. `firewall_mock_tests.rs`
/// drives both from a mock.
fn backend_names_itself_and_offers_rules(backend: &dyn FirewallBackend, expected_name: &str) {
    assert_eq!(backend.backend_name(), expected_name);
    assert!(
        !backend.get_default_rules().is_empty(),
        "{expected_name} should return default rules"
    );
}

#[tokio::test]
#[ignore] // Only run on systems with firewalld installed
async fn firewalld_backend_detection_smoke_test() {
    // Run with: cargo test --package hardener-plugins firewalld_backend_detection_smoke_test -- --ignored --nocapture

    use hardener_plugins::firewall::firewalld::FirewalldBackend;

    let backend = FirewalldBackend::new();

    // The assertion is on the probe, not on its answer: every host can be
    // asked whether firewalld is present, and only some say yes. Asserting
    // the answer would measure the machine, and asserting it behind an `if`
    // would let the hosts that say no reach no assertion at all.
    assert!(
        backend.detect(&Context::new()).await.is_ok(),
        "firewalld detection should not error"
    );

    backend_names_itself_and_offers_rules(&backend, "firewalld");
}

#[tokio::test]
#[ignore] // Only run on systems with UFW installed
async fn ufw_backend_detection_smoke_test() {
    // Run with: cargo test --package hardener-plugins ufw_backend_detection_smoke_test -- --ignored --nocapture

    use hardener_plugins::firewall::ufw::UfwBackend;

    let backend = UfwBackend::new();

    assert!(
        backend.detect(&Context::new()).await.is_ok(),
        "UFW detection should not error"
    );

    backend_names_itself_and_offers_rules(&backend, "ufw");
}

#[tokio::test]
#[ignore] // Only run on systems with nftables installed
async fn nftables_backend_detection_smoke_test() {
    // Run with: cargo test --package hardener-plugins nftables_backend_detection_smoke_test -- --ignored --nocapture

    use hardener_plugins::firewall::nftables::NftablesBackend;

    let backend = NftablesBackend::new();

    assert!(
        backend.detect(&Context::new()).await.is_ok(),
        "nftables detection should not error"
    );

    backend_names_itself_and_offers_rules(&backend, "nftables");
}
