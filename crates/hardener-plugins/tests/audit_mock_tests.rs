//! Audit plugin tests using MockExecutor.
//!
//! These tests verify plugin behavior without touching real auditd.

use hardener_common::types::{PluginId, Severity};
use hardener_core::{
    CommandOutput, Context, MockExecutor, SystemExecutor, plugin::HardeningPlugin,
};
use hardener_plugins::AuditHardeningPlugin;
use std::sync::Arc;

/// Creates a mock executor with auditd fully configured and running.
fn fully_configured_audit_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // All rules are configured
        .with_command(
            "auditctl",
            &["-l"],
            CommandOutput {
                stdout: r#"-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network-change
-w /etc/hosts -p wa -k network-change
-a always,exit -F arch=b64 -S chmod -k perm-mod
-a always,exit -F arch=b64 -S chown -k perm-mod
-w /usr/bin/sudo -p x -k privileged
-w /usr/bin/su -p x -k privileged
-a always,exit -F arch=b64 -S unlink -k delete
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
"#
                .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

/// Creates a mock executor where auditd is not installed.
fn no_auditd_executor() -> MockExecutor {
    MockExecutor::new().with_command_exists("auditd", false)
}

/// Creates a mock executor where auditd is installed but not enabled/running.
fn auditd_disabled_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "disabled\n".to_string(),
                stderr: String::new(),
                exit_code: 1,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "inactive\n".to_string(),
                stderr: String::new(),
                exit_code: 3,
            },
        )
        .with_command(
            "auditctl",
            &["-l"],
            CommandOutput {
                stdout: "No rules\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

/// Creates a mock executor with auditd running but missing some rules.
fn partial_rules_executor() -> MockExecutor {
    MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        // Only identity rules configured, missing others
        .with_command(
            "auditctl",
            &["-l"],
            CommandOutput {
                stdout: r#"-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
"#
                .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

#[tokio::test]
async fn test_audit_scan_fully_configured_no_findings() {
    let executor = fully_configured_audit_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success);
    assert_eq!(result.scan_plugin_id, PluginId::new("audit-hardening"));
    assert!(
        result.scan_findings.is_empty(),
        "Fully configured audit should have no findings, but got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_title)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_audit_scan_not_installed() {
    let executor = no_auditd_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success);
    assert_eq!(result.scan_findings.len(), 1);

    let finding = &result.scan_findings[0];
    assert_eq!(finding.finding_id, "audit_not_installed");
    assert_eq!(finding.finding_severity, Severity::Critical);
    assert_eq!(finding.finding_current_value, "not installed");
}

#[tokio::test]
async fn test_audit_scan_disabled_and_stopped() {
    let executor = auditd_disabled_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success);

    let finding_ids: Vec<_> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();

    // Should find auditd not enabled and not running
    assert!(finding_ids.contains(&"audit_not_enabled"));
    assert!(finding_ids.contains(&"auditd_not_running"));

    // Check severities
    let not_enabled = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "audit_not_enabled")
        .unwrap();
    assert_eq!(not_enabled.finding_severity, Severity::High);
}

#[tokio::test]
async fn test_audit_scan_missing_rules() {
    let executor = partial_rules_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success);

    let finding_ids: Vec<_> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();

    // Should find missing rule categories
    // identity rules are present, but time-change, network-change, perm-mod,
    // privileged, delete, modules should be flagged
    assert!(
        finding_ids.iter().any(|id| id.contains("time_change")),
        "Should flag missing time-change rules"
    );
    assert!(
        finding_ids.iter().any(|id| id.contains("network_change")),
        "Should flag missing network-change rules"
    );
    assert!(
        finding_ids.iter().any(|id| id.contains("perm_mod")),
        "Should flag missing perm-mod rules"
    );

    // identity is present, should NOT be flagged
    // Note: The plugin checks for category name in the rule, so we need to verify
}

#[tokio::test]
async fn test_audit_scan_finding_structure() {
    let executor = no_auditd_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    let finding = &result.scan_findings[0];

    assert_eq!(finding.finding_id, "audit_not_installed");
    assert!(!finding.finding_compliance.is_empty());
    assert_eq!(
        finding.finding_compliance[0].compliance_control_id,
        "4.1.1.1"
    );
    assert!(!finding.finding_remediation_steps.is_empty());
}

#[tokio::test]
async fn test_audit_validate_with_auditd() {
    let executor = partial_rules_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();
    let config = hardener_core::Config::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    assert!(result.validation_report_is_valid);
    // Should have estimated changes for missing rules
    assert!(!result.validation_report_estimated_changes.is_empty());
}

#[tokio::test]
async fn test_audit_validate_no_auditd() {
    let executor = no_auditd_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();
    let config = hardener_core::Config::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    assert!(!result.validation_report_is_valid);
    assert!(!result.validation_report_issues.is_empty());

    let issue = &result.validation_report_issues[0];
    assert_eq!(issue.validation_issue_severity, Severity::Critical);
    assert!(issue.validation_issue_message.contains("auditd"));
}

#[tokio::test]
async fn test_audit_scan_duration_recorded() {
    let executor = fully_configured_audit_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_duration_us > 0);
}

#[tokio::test]
async fn test_audit_scan_logs_commands() {
    let executor = partial_rules_executor();
    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = AuditHardeningPlugin::new();

    let _ = plugin.scan(&ctx).await;

    let log = executor.log();

    // Should have executed systemctl and auditctl commands
    assert!(
        log.commands_executed
            .iter()
            .any(|(cmd, _)| cmd == "systemctl"),
        "Should execute systemctl"
    );
    assert!(
        log.commands_executed
            .iter()
            .any(|(cmd, _)| cmd == "auditctl"),
        "Should execute auditctl"
    );
}

#[tokio::test]
async fn test_audit_metadata() {
    let plugin = AuditHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id, PluginId::new("audit-hardening"));
    assert_eq!(metadata.plugin_name, "Audit Rules Hardening");
}

#[tokio::test]
async fn test_audit_scan_with_remote_executor() {
    let executor = MockExecutor::new()
        .remote()
        .with_description("ssh://admin@server.example.com")
        .with_command_exists("auditd", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "inactive\n".to_string(), // Not running on remote
                stderr: String::new(),
                exit_code: 3,
            },
        )
        .with_command(
            "auditctl",
            &["-l"],
            CommandOutput {
                stdout: "No rules\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );

    assert!(executor.is_remote());

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = AuditHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success);
    // Should find auditd not running on remote
    assert!(
        result
            .scan_findings
            .iter()
            .any(|f| f.finding_id == "auditd_not_running")
    );
}
