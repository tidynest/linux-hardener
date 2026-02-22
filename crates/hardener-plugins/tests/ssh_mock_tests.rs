//! SSH plugin tests using MockExecutor.
//!
//! These tests verify plugin behavior without touching the real filesystem.

use hardener_common::types::{PluginId, Severity};
use hardener_core::{Context, MockExecutor, SystemExecutor, plugin::HardeningPlugin};
use hardener_plugins::ssh::SshHardeningPlugin;
use std::sync::Arc;

/// Creates a mock executor with a typical secure SSH config.
fn secure_ssh_executor() -> MockExecutor {
    MockExecutor::new().with_file(
        "/etc/ssh/sshd_config",
        r#"
# Secure SSH configuration
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
Protocol 2
MaxAuthTries 3
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
"#,
    )
}

/// Creates a mock executor with an insecure SSH config.
fn insecure_ssh_executor() -> MockExecutor {
    MockExecutor::new().with_file(
        "/etc/ssh/sshd_config",
        r#"
# Default SSH configuration (insecure)
PermitRootLogin yes
PasswordAuthentication yes
X11Forwarding yes
"#,
    )
}

/// Creates a mock executor with no SSH config file.
fn missing_ssh_executor() -> MockExecutor {
    MockExecutor::new()
    // No /etc/ssh/sshd_config file
}

#[tokio::test]
async fn test_ssh_scan_secure_config_no_findings() {
    let executor = secure_ssh_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success);
    assert_eq!(result.scan_plugin_id, PluginId::new("ssh-hardening"));
    assert!(result.scan_error.is_none());
    assert!(
        result.scan_findings.is_empty(),
        "Secure config should have no findings, but got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_title)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_ssh_scan_insecure_config_finds_issues() {
    let executor = insecure_ssh_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success);
    assert!(
        !result.scan_findings.is_empty(),
        "Should find insecure settings"
    );

    // Check for specific findings
    let finding_ids: Vec<_> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();

    assert!(
        finding_ids.contains(&"ssh-permitrootlogin"),
        "Should flag PermitRootLogin yes"
    );
    assert!(
        finding_ids.contains(&"ssh-passwordauthentication"),
        "Should flag PasswordAuthentication yes"
    );
    assert!(
        finding_ids.contains(&"ssh-x11forwarding"),
        "Should flag X11Forwarding yes"
    );

    // Verify severity is correct
    let root_login = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "ssh-permitrootlogin")
        .unwrap();
    assert_eq!(root_login.finding_severity, Severity::Critical);
    assert_eq!(root_login.finding_current_value, "yes");
    assert_eq!(root_login.finding_recommended_value, "no");
}

#[tokio::test]
async fn test_ssh_scan_missing_config_file() {
    let executor = missing_ssh_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    // Scan should return gracefully with an error message
    assert!(!result.scan_success);
    assert!(result.scan_error.is_some());
    assert!(result.scan_error.unwrap().contains("Failed to read"));
}

#[tokio::test]
async fn test_ssh_scan_missing_directives_flagged() {
    // Config with only one directive set
    let executor = MockExecutor::new().with_file("/etc/ssh/sshd_config", "PermitRootLogin no\n");

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success);

    // Missing directives should be flagged
    let finding_ids: Vec<_> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();

    // PermitRootLogin is set correctly, shouldn't be flagged
    assert!(!finding_ids.contains(&"ssh-permitrootlogin"));

    // These are missing, should be flagged
    assert!(finding_ids.contains(&"ssh-passwordauthentication"));
    assert!(finding_ids.contains(&"ssh-permitemptypasswords"));
    assert!(finding_ids.contains(&"ssh-protocol"));

    // Verify "not set" current value
    let password_auth = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "ssh-passwordauthentication")
        .unwrap();
    assert_eq!(password_auth.finding_current_value, "not set");
}

#[tokio::test]
async fn test_ssh_validate_file_exists() {
    let executor = MockExecutor::new().with_file("/etc/ssh/sshd_config", "# config");

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    assert!(result.validation_report_is_valid);
    assert!(result.validation_report_issues.is_empty());
}

#[tokio::test]
async fn test_ssh_validate_file_missing() {
    let executor = MockExecutor::new();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    assert!(!result.validation_report_is_valid);
    assert!(!result.validation_report_issues.is_empty());

    // MockExecutor returns FileMetadata { exists: false, is_file: false } for missing files
    // So the first issue is "not a regular file", and the second is "Cannot read"
    let messages: Vec<_> = result
        .validation_report_issues
        .iter()
        .map(|i| i.validation_issue_message.as_str())
        .collect();

    assert!(
        messages
            .iter()
            .any(|m| m.contains("not a regular file") || m.contains("Cannot read")),
        "Expected validation error about missing file, got: {:?}",
        messages
    );

    // All issues should be critical severity
    for issue in &result.validation_report_issues {
        assert_eq!(issue.validation_issue_severity, Severity::Critical);
    }
}

#[tokio::test]
async fn test_ssh_validate_not_regular_file() {
    let executor = MockExecutor::new().with_directory("/etc/ssh/sshd_config"); // Directory instead of file

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    assert!(!result.validation_report_is_valid);

    let issue = &result.validation_report_issues[0];
    assert!(
        issue
            .validation_issue_message
            .contains("not a regular file")
    );
}

#[tokio::test]
async fn test_ssh_scan_logs_file_read() {
    let executor = MockExecutor::new().with_file("/etc/ssh/sshd_config", "PermitRootLogin no");

    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = SshHardeningPlugin::new();

    let _ = plugin.scan(&ctx).await;

    // Verify the plugin read the config file
    let log = executor.log();
    assert!(
        log.files_read
            .iter()
            .any(|p| p.to_str().unwrap() == "/etc/ssh/sshd_config"),
        "Plugin should read /etc/ssh/sshd_config"
    );
}

#[tokio::test]
async fn test_ssh_scan_compliance_mappings() {
    let executor = insecure_ssh_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    // Find PermitRootLogin finding
    let root_login = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "ssh-permitrootlogin")
        .expect("Should have PermitRootLogin finding");

    // Verify compliance mapping
    assert!(!root_login.finding_compliance.is_empty());
    let cis_mapping = &root_login.finding_compliance[0];
    assert_eq!(cis_mapping.compliance_control_id, "5.2.10");
    assert!(cis_mapping.compliance_control_title.contains("root login"));
}

#[tokio::test]
async fn test_ssh_scan_duration_recorded() {
    let executor = secure_ssh_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(
        result.scan_duration_us > 0,
        "Scan duration should be recorded"
    );
}

#[tokio::test]
async fn test_ssh_scan_with_remote_executor() {
    // Simulate scanning a remote system
    let executor = MockExecutor::new()
        .remote()
        .with_description("ssh://admin@server.example.com")
        .with_file(
            "/etc/ssh/sshd_config",
            "PermitRootLogin no\nPasswordAuthentication no\n",
        );

    assert!(executor.is_remote());

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = SshHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();
    assert!(result.scan_success);
}
