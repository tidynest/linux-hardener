//! Services plugin tests using MockExecutor.
//!
//! These tests verify plugin behavior without touching real systemd services.

use hardener_common::types::{PluginId, Severity};
use hardener_core::{
    CommandOutput, Context, MockExecutor, SystemExecutor, plugin::HardeningPlugin,
};
use hardener_plugins::ServicesHardeningPlugin;
use std::sync::Arc;

/// Creates a mock executor where all unnecessary services are disabled.
fn clean_system_executor() -> MockExecutor {
    MockExecutor::new()
        // systemctl list-unit-files shows no matching services
        .with_command(
            "systemctl",
            &["list-unit-files", "bluetooth"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["list-unit-files", "cups"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["list-unit-files", "avahi-daemon"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["list-unit-files", "ModemManager"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command_exists("systemctl", true)
}

/// Creates a mock executor with insecure services running.
fn insecure_services_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("systemctl", true)
        // Bluetooth - exists, enabled, and active
        .with_command(
            "systemctl",
            &["list-unit-files", "bluetooth"],
            CommandOutput {
                stdout: "bluetooth.service enabled enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-enabled", "bluetooth"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "bluetooth"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // CUPS - exists and enabled but not active
        .with_command(
            "systemctl",
            &["list-unit-files", "cups"],
            CommandOutput {
                stdout: "cups.service enabled enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-enabled", "cups"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "cups"],
            CommandOutput {
                stdout: "inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 3, // Not active
            },
        )
        // Avahi - does not exist on this system
        .with_command(
            "systemctl",
            &["list-unit-files", "avahi-daemon"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // ModemManager - exists but disabled
        .with_command(
            "systemctl",
            &["list-unit-files", "ModemManager"],
            CommandOutput {
                stdout: "ModemManager.service disabled disabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-enabled", "ModemManager"],
            CommandOutput {
                stdout: "disabled\n".to_string(),
                stderr: String::new(),
                exit_code: 1,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "ModemManager"],
            CommandOutput {
                stdout: "inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 3,
            },
        )
}

/// Creates a mock executor without systemctl (non-systemd system).
fn no_systemd_executor() -> MockExecutor {
    MockExecutor::new().with_command_exists("systemctl", false)
}

#[tokio::test]
async fn test_services_scan_clean_system_no_findings() {
    let executor = clean_system_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success);
    assert_eq!(result.scan_plugin_id, PluginId::new("service-minimisation"));
    assert!(
        result.scan_findings.is_empty(),
        "Clean system should have no findings, but got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_title)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_services_scan_finds_enabled_services() {
    let executor = insecure_services_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success);

    // Should find bluetooth (enabled and active) and cups (enabled)
    let finding_ids: Vec<_> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();

    assert!(
        finding_ids.contains(&"service_bluetooth"),
        "Should find bluetooth service"
    );
    assert!(
        finding_ids.contains(&"service_cups"),
        "Should find cups service"
    );

    // Should NOT find avahi (doesn't exist) or ModemManager (disabled)
    assert!(
        !finding_ids.contains(&"service_avahi_daemon"),
        "Should not flag non-existent avahi"
    );
    assert!(
        !finding_ids.contains(&"service_ModemManager"),
        "Should not flag disabled ModemManager"
    );
}

#[tokio::test]
async fn test_services_scan_finding_structure() {
    let executor = insecure_services_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    // Find bluetooth finding
    let bt_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "service_bluetooth")
        .expect("Should have bluetooth finding");

    assert_eq!(bt_finding.finding_current_value, "enabled and active");
    assert_eq!(bt_finding.finding_recommended_value, "disabled and masked");
    assert_eq!(bt_finding.finding_severity, Severity::High);
    assert!(bt_finding.finding_title.contains("bluetooth"));
    assert!(!bt_finding.finding_remediation_steps.is_empty());

    // Check remediation steps
    let steps: Vec<_> = bt_finding
        .finding_remediation_steps
        .iter()
        .map(|s| s.as_str())
        .collect();
    assert!(steps.iter().any(|s| s.contains("systemctl stop")));
    assert!(steps.iter().any(|s| s.contains("systemctl disable")));
    assert!(steps.iter().any(|s| s.contains("systemctl mask")));
}

#[tokio::test]
async fn test_services_scan_cups_enabled_only() {
    let executor = insecure_services_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    // Find CUPS finding - enabled but not active
    let cups_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "service_cups")
        .expect("Should have cups finding");

    // CUPS is enabled but not active
    assert_eq!(cups_finding.finding_current_value, "enabled");
    assert_eq!(cups_finding.finding_severity, Severity::Medium);
}

#[tokio::test]
async fn test_services_validate_with_systemctl() {
    let executor = insecure_services_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();
    let config = hardener_core::Config;

    let result = plugin.validate(&ctx, &config).await.unwrap();

    assert!(result.validation_report_is_valid);
    assert!(result.validation_report_issues.is_empty());

    // Should list estimated changes for enabled services
    assert!(!result.validation_report_estimated_changes.is_empty());

    let changes_str = result.validation_report_estimated_changes.join(" ");
    assert!(changes_str.contains("bluetooth"));
    assert!(changes_str.contains("cups"));
}

#[tokio::test]
async fn test_services_validate_no_systemctl() {
    let executor = no_systemd_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();
    let config = hardener_core::Config;

    let result = plugin.validate(&ctx, &config).await.unwrap();

    // Should have critical issue about missing systemctl
    assert!(!result.validation_report_is_valid);
    assert!(!result.validation_report_issues.is_empty());

    let issue = &result.validation_report_issues[0];
    assert_eq!(issue.validation_issue_severity, Severity::Critical);
    assert!(issue.validation_issue_message.contains("systemctl"));
    assert!(issue.validation_issue_message.contains("systemd"));
}

#[tokio::test]
async fn test_services_scan_logs_commands() {
    let executor = insecure_services_executor();
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = ServicesHardeningPlugin::new();

    let _ = plugin.scan(&ctx).await;

    let log = executor.log();

    // Should have executed systemctl commands
    assert!(
        log.commands_executed
            .iter()
            .any(|(cmd, _)| cmd == "systemctl"),
        "Should execute systemctl commands"
    );

    // Should check list-unit-files for each service
    assert!(
        log.commands_executed
            .iter()
            .any(|(_, args)| args.contains(&"list-unit-files".to_string())),
        "Should check list-unit-files"
    );
}

#[tokio::test]
async fn test_services_scan_duration_recorded() {
    let executor = clean_system_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(
        result.scan_duration_us > 0,
        "Scan duration should be recorded"
    );
}

#[tokio::test]
async fn test_services_metadata() {
    let plugin = ServicesHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id, PluginId::new("service-minimisation"));
    assert_eq!(metadata.plugin_name, "Service Minimisation");
    assert!(metadata.plugin_description.contains("systemd"));
}

#[tokio::test]
async fn test_services_scan_with_remote_executor() {
    // Simulate scanning services on a remote system
    let executor = MockExecutor::new()
        .remote()
        .with_description("ssh://admin@server.example.com")
        .with_command_exists("systemctl", true)
        .with_command(
            "systemctl",
            &["list-unit-files", "bluetooth"],
            CommandOutput {
                stdout: "bluetooth.service enabled enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-enabled", "bluetooth"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "bluetooth"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["list-unit-files", "cups"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["list-unit-files", "avahi-daemon"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["list-unit-files", "ModemManager"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        );

    assert!(executor.is_remote());

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success);
    // Should find bluetooth on remote system
    assert!(
        result
            .scan_findings
            .iter()
            .any(|f| f.finding_id == "service_bluetooth")
    );
}

#[tokio::test]
async fn test_services_compliance_mappings() {
    // Create executor with cups and avahi enabled to test compliance mappings
    let executor = MockExecutor::new()
        .with_command_exists("systemctl", true)
        .with_command(
            "systemctl",
            &["list-unit-files", "bluetooth"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["list-unit-files", "cups"],
            CommandOutput {
                stdout: "cups.service enabled enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-enabled", "cups"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "cups"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["list-unit-files", "avahi-daemon"],
            CommandOutput {
                stdout: "avahi-daemon.service enabled enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-enabled", "avahi-daemon"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "avahi-daemon"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["list-unit-files", "ModemManager"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        );

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = ServicesHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    // CUPS should have CIS 2.2.4 mapping
    let cups_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "service_cups")
        .expect("Should have cups finding");
    assert!(!cups_finding.finding_compliance.is_empty());
    assert_eq!(
        cups_finding.finding_compliance[0].compliance_control_id,
        "2.2.4"
    );

    // Avahi should have CIS 2.2.3 mapping
    let avahi_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "service_avahi_daemon")
        .expect("Should have avahi finding");
    assert!(!avahi_finding.finding_compliance.is_empty());
    assert_eq!(
        avahi_finding.finding_compliance[0].compliance_control_id,
        "2.2.3"
    );
}
