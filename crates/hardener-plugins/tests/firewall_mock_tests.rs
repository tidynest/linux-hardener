//! Firewall plugin tests using MockExecutor.
//!
//! These tests verify plugin behaviour without touching real firewall configuration.
//! Includes tests for permission-denied scenarios (Bug D).

use hardener_common::types::{PluginId, Severity};
use hardener_core::{
    CommandOutput, Context, MockExecutor, PluginConfig, PolicyException, plugin::HardeningPlugin,
};
use hardener_plugins::FirewallHardeningPlugin;
use std::sync::Arc;

/// Creates a mock executor where UFW is installed and active.
fn ufw_active_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("ufw", true)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", false)
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

/// Creates a mock executor where UFW is installed but disabled.
fn ufw_disabled_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("ufw", true)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", false)
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: "Status: inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

/// Creates a mock executor simulating permission denied when running `ufw status`.
/// This is Bug D: UFW requires root to check status.
fn ufw_permission_denied_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("ufw", true)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", false)
        .with_command(
            "ufw",
            &["status"],
            CommandOutput {
                stdout: String::new(),
                stderr: "ERROR: You need to be root to run this script\n".to_string(),
                exit_code: 1,
            },
        )
        // Also provide systemctl check which doesn't require root
        .with_command(
            "systemctl",
            &["is-active", "ufw"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

/// Creates a mock executor where no firewall backend is installed.
fn no_firewall_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("ufw", false)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", false)
}

#[tokio::test]
async fn test_firewall_scan_ufw_active_no_findings() {
    let executor = ufw_active_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = FirewallHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success, "active firewall scan should succeed");
    assert_eq!(result.scan_plugin_id, PluginId::new("firewall-hardening"));

    // UFW is active, should have no "disabled" findings
    let disabled_findings: Vec<_> = result
        .scan_findings
        .iter()
        .filter(|f| f.finding_title.to_lowercase().contains("disabled"))
        .collect();

    assert!(
        disabled_findings.is_empty(),
        "Active firewall should NOT have 'disabled' findings, but got: {:?}",
        disabled_findings
            .iter()
            .map(|f| &f.finding_title)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_firewall_scan_ufw_disabled_has_finding() {
    let executor = ufw_disabled_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = FirewallHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success, "disabled firewall scan should succeed");

    // UFW is disabled, should have a "disabled" finding
    let disabled_findings: Vec<_> = result
        .scan_findings
        .iter()
        .filter(|f| f.finding_title.to_lowercase().contains("disabled"))
        .collect();

    assert!(
        !disabled_findings.is_empty(),
        "Disabled firewall SHOULD have 'disabled' finding"
    );

    // Verify severity (High per current implementation)
    let finding = &disabled_findings[0];
    assert_eq!(
        finding.finding_severity,
        Severity::High,
        "Disabled firewall should be High severity"
    );
}

/// BUG D TEST: This test exposes the false positive bug.
///
/// When `ufw status` fails due to permission denied, the plugin should NOT
/// report "Firewall disabled" - it should either:
/// 1. Fall back to `systemctl is-active ufw` (doesn't need root)
/// 2. Report "Unable to determine firewall status (permission denied)"
/// 3. Return scan_success=false with appropriate error
///
/// Currently this test will FAIL because the plugin incorrectly reports
/// "Firewall disabled" when it can't check status due to permissions.
#[tokio::test]
async fn test_firewall_scan_permission_denied_should_not_report_disabled() {
    let executor = ufw_permission_denied_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = FirewallHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    // The plugin detected UFW exists (command_exists returns true)
    // But `ufw status` failed with permission denied

    // BUG D: Currently this incorrectly reports "Firewall disabled"
    // The correct behaviour would be one of:
    // A) No "disabled" finding (because we don't actually know if it's disabled)
    // B) scan_success = false with error explaining permission issue
    // C) Fall back to systemctl check

    let disabled_findings: Vec<_> = result
        .scan_findings
        .iter()
        .filter(|f| f.finding_title.to_lowercase().contains("disabled"))
        .collect();

    // This assertion documents the EXPECTED behaviour (not current buggy behaviour)
    assert!(
        disabled_findings.is_empty(),
        "BUG D: Permission denied should NOT result in 'Firewall disabled' finding. \
         The firewall might actually be active (and in this mock it IS active via systemctl). \
         Got findings: {:?}",
        disabled_findings
            .iter()
            .map(|f| &f.finding_title)
            .collect::<Vec<_>>()
    );

    // Alternative acceptable behaviours:
    // 1. scan_success = false with permission error
    // 2. Finding that says "Unable to verify firewall status" (not "disabled")
}

#[tokio::test]
async fn test_firewall_scan_no_backend_fails_gracefully() {
    let executor = no_firewall_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = FirewallHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    // No backend found - scan should indicate this
    assert!(
        !result.scan_success || result.scan_error.is_some(),
        "Scan with no firewall backend should fail or have error"
    );

    if let Some(error) = &result.scan_error {
        assert!(
            error.contains("firewall") || error.contains("backend"),
            "Error message should mention firewall or backend"
        );
    }
}

#[tokio::test]
async fn test_firewall_metadata() {
    let plugin = FirewallHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id, PluginId::new("firewall-hardening"));
    assert_eq!(metadata.plugin_name, "Firewall Hardening");
}

#[tokio::test]
async fn test_firewall_scan_logs_commands() {
    let executor = ufw_active_executor();
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = FirewallHardeningPlugin::new();

    let _ = plugin.scan(&ctx).await;

    let log = executor.log();

    // Should have executed ufw command
    assert!(
        log.commands_executed.iter().any(|(cmd, _)| cmd == "ufw"),
        "Should execute ufw command"
    );
}

#[tokio::test]
async fn test_firewall_scan_duration_recorded() {
    let executor = ufw_active_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = FirewallHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(
        result.scan_duration_us > 0,
        "scan duration should be recorded"
    );
}

/// Helper: UFW active + all baseline rule commands registered.
/// Accepts an optional port override for the SSH rule (default "22").
fn ufw_apply_executor(ssh_port: &str) -> MockExecutor {
    let ok = CommandOutput {
        stdout: "Rule added\n".to_string(),
        stderr: String::new(),
        exit_code: 0,
    };
    MockExecutor::new()
        .with_command_exists("ufw", true)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", false)
        // is_enabled: systemctl returns active → skip enable
        .with_command(
            "systemctl",
            &["is-active", "ufw"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // Baseline rule commands (UFW build_ufw_rule_args output)
        .with_command("ufw", &["allow", "from", "127.0.0.1/8"], ok.clone())
        .with_command("ufw", &["allow"], ok.clone())
        .with_command(
            "ufw",
            &["allow", "to", "any", "port", ssh_port, "proto", "tcp"],
            ok.clone(),
        )
        .with_command("ufw", &["deny"], ok)
}

#[tokio::test]
async fn test_firewall_apply_respects_directives() {
    let executor = ufw_apply_executor("2222");
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = FirewallHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config
        .directives
        .insert("ssh.port".to_string(), "2222".to_string());

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    assert!(
        result.apply_success,
        "apply should succeed, errors: {:?}",
        result
            .apply_changes
            .iter()
            .filter(|c| !c.change_success)
            .collect::<Vec<_>>()
    );

    // Verify the mock received the overridden port in the ufw command
    let log = executor.log();
    let ssh_cmd = log
        .commands_executed
        .iter()
        .find(|(cmd, args)| cmd == "ufw" && args.iter().any(|a| a == "2222"));
    assert!(
        ssh_cmd.is_some(),
        "ufw should have been called with port 2222, got: {:?}",
        log.commands_executed
    );
}

#[tokio::test]
async fn test_firewall_apply_skips_exceptions() {
    // Register commands for the 3 remaining rules (loopback, established, drop).
    // SSH rule is excepted, so its ufw command should NOT be called.
    let ok = CommandOutput {
        stdout: "Rule added\n".to_string(),
        stderr: String::new(),
        exit_code: 0,
    };
    let executor = MockExecutor::new()
        .with_command_exists("ufw", true)
        .with_command_exists("firewall-cmd", false)
        .with_command_exists("nft", false)
        .with_command(
            "systemctl",
            &["is-active", "ufw"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command("ufw", &["allow", "from", "127.0.0.1/8"], ok.clone())
        .with_command("ufw", &["allow"], ok.clone())
        // No SSH rule registered — if the plugin tries to call it, the mock errors
        .with_command("ufw", &["deny"], ok);

    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = FirewallHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "ssh".to_string(),
        PolicyException {
            value: "skip".to_string(),
            allowed: true,
            reason: "SSH managed externally".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    assert!(
        result.apply_success,
        "apply should succeed, errors: {:?}",
        result
            .apply_changes
            .iter()
            .filter(|c| !c.change_success)
            .collect::<Vec<_>>()
    );

    // Should have a "skipped" change for the SSH rule
    let skipped = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("skipped"));
    assert!(skipped.is_some(), "should have a skipped change for SSH");
    assert!(
        skipped
            .expect("checked above")
            .change_description
            .contains("SSH managed externally"),
    );

    // Verify no ufw command was issued for SSH port
    let log = executor.log();
    assert!(
        !log.commands_executed
            .iter()
            .any(|(cmd, args)| cmd == "ufw" && args.iter().any(|a| a == "22")),
        "should not execute ufw command for excepted SSH rule"
    );
}

#[tokio::test]
async fn test_firewall_validate_skips_exceptions() {
    let executor = ufw_active_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = FirewallHardeningPlugin::new();

    // Exception on the SSH rule — should reduce baseline count from 4 to 3
    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "ssh".to_string(),
        PolicyException {
            value: "skip".to_string(),
            allowed: true,
            reason: "SSH managed externally".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let report = plugin.validate(&ctx, &config).await.unwrap();

    // Should say "Apply 3 baseline firewall rules" (not 4)
    let rule_change = report
        .validation_report_estimated_changes
        .iter()
        .find(|c| c.contains("baseline firewall rules"));
    assert!(
        rule_change.is_some(),
        "should have estimated changes for rules"
    );
    assert!(
        rule_change.expect("checked above").contains("3"),
        "expected 3 rules after exception, got: {:?}",
        report.validation_report_estimated_changes
    );
}

#[test]
fn test_zone_name_validation() {
    use hardener_plugins::firewall::firewalld::validate_zone_name;

    assert!(validate_zone_name("public").is_ok());
    assert!(validate_zone_name("trusted").is_ok());
    assert!(validate_zone_name("my-zone").is_ok());
    assert!(validate_zone_name("zone_1").is_ok());

    assert!(validate_zone_name("").is_err());
    assert!(validate_zone_name("--help").is_err());
    assert!(validate_zone_name("zone; rm -rf /").is_err());
    assert!(validate_zone_name(&"a".repeat(65)).is_err());
    assert!(validate_zone_name("zone\nnewline").is_err());
}
