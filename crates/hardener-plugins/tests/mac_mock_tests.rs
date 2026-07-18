//! MAC (Mandatory Access Control) plugin tests using MockExecutor.
//!
//! These tests verify plugin behavior without touching real SELinux/AppArmor.

use hardener_common::types::{PluginId, Severity};
use hardener_core::{
    ChangeType, CommandOutput, Context, FileMetadata, MockExecutor, PluginConfig, PolicyException,
    SystemExecutor, plugin::HardeningPlugin,
};
use hardener_plugins::MacHardeningPlugin;
use std::sync::Arc;

/// Creates a mock executor with SELinux in enforcing mode.
fn selinux_enforcing_executor() -> MockExecutor {
    MockExecutor::new()
        // SELinux path exists
        .with_file_metadata(
            "/sys/fs/selinux",
            "",
            FileMetadata {
                exists: true,
                is_file: false,
                is_dir: true,
                mode: 0o755,
                size: 0,
                uid: 0,
                gid: 0,
            },
        )
        // AppArmor path doesn't exist
        .with_command(
            "getenforce",
            &[],
            CommandOutput {
                stdout: "Enforcing\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

/// Creates a mock executor with SELinux in permissive mode.
fn selinux_permissive_executor() -> MockExecutor {
    MockExecutor::new()
        .with_file_metadata(
            "/sys/fs/selinux",
            "",
            FileMetadata {
                exists: true,
                is_file: false,
                is_dir: true,
                mode: 0o755,
                size: 0,
                uid: 0,
                gid: 0,
            },
        )
        .with_command(
            "getenforce",
            &[],
            CommandOutput {
                stdout: "Permissive\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

/// Creates a mock executor with SELinux disabled.
fn selinux_disabled_executor() -> MockExecutor {
    MockExecutor::new()
        .with_file_metadata(
            "/sys/fs/selinux",
            "",
            FileMetadata {
                exists: true,
                is_file: false,
                is_dir: true,
                mode: 0o755,
                size: 0,
                uid: 0,
                gid: 0,
            },
        )
        .with_command(
            "getenforce",
            &[],
            CommandOutput {
                stdout: "Disabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

/// Creates a mock executor with AppArmor fully configured.
fn apparmor_enforcing_executor() -> MockExecutor {
    MockExecutor::new()
        // AppArmor path exists
        .with_file_metadata(
            "/sys/kernel/security/apparmor",
            "",
            FileMetadata {
                exists: true,
                is_file: false,
                is_dir: true,
                mode: 0o755,
                size: 0,
                uid: 0,
                gid: 0,
            },
        )
        // SELinux path doesn't exist (MockExecutor returns exists: false by default)
        .with_command(
            "aa-status",
            &["--verbose"],
            CommandOutput {
                stdout: r#"apparmor module is loaded.
37 profiles are loaded.
37 profiles are in enforce mode.
   /snap/snapd/21759/usr/lib/snapd/snap-confine
   /usr/bin/evince
   /usr/bin/man
   ...
0 profiles are in complain mode.
5 processes have profiles defined.
"#
                .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

/// Creates a mock executor with AppArmor profiles in complain mode.
fn apparmor_complain_executor() -> MockExecutor {
    MockExecutor::new()
        .with_file_metadata(
            "/sys/kernel/security/apparmor",
            "",
            FileMetadata {
                exists: true,
                is_file: false,
                is_dir: true,
                mode: 0o755,
                size: 0,
                uid: 0,
                gid: 0,
            },
        )
        .with_command(
            "aa-status",
            &["--verbose"],
            CommandOutput {
                stdout: r#"apparmor module is loaded.
37 profiles are loaded.
10 profiles are in enforce mode.
27 profiles are in complain mode.
5 processes have profiles defined.
"#
                .to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
}

/// Creates a mock executor with no MAC system.
fn no_mac_executor() -> MockExecutor {
    MockExecutor::new()
    // Both paths will return exists: false by default
}

#[tokio::test]
async fn test_mac_scan_selinux_enforcing_no_findings() {
    let executor = selinux_enforcing_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = MacHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success, "SELinux enforcing scan should succeed");
    assert_eq!(result.scan_plugin_id, PluginId::new("mac-hardening"));
    assert!(
        result.scan_findings.is_empty(),
        "SELinux enforcing should have no findings, but got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_title)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_mac_scan_selinux_permissive() {
    let executor = selinux_permissive_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = MacHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(
        result.scan_success,
        "SELinux permissive scan should succeed"
    );
    assert!(
        !result.scan_findings.is_empty(),
        "SELinux permissive should have findings"
    );

    let finding = &result.scan_findings[0];
    assert!(
        finding.finding_id.contains("selinux"),
        "finding ID should mention selinux, got: {}",
        finding.finding_id
    );
    assert_eq!(finding.finding_current_value, "Permissive");
    assert_eq!(finding.finding_recommended_value, "Enforcing");
    assert_eq!(finding.finding_severity, Severity::High);
}

#[tokio::test]
async fn test_mac_scan_selinux_disabled() {
    let executor = selinux_disabled_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = MacHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success, "SELinux disabled scan should succeed");
    assert!(
        !result.scan_findings.is_empty(),
        "SELinux disabled should have findings"
    );

    let finding = &result.scan_findings[0];
    assert_eq!(finding.finding_current_value, "Disabled");
    // SELinux not enforcing is High severity (same as Permissive)
    assert_eq!(finding.finding_severity, Severity::High);
}

#[tokio::test]
async fn test_mac_scan_apparmor_enforcing_no_findings() {
    let executor = apparmor_enforcing_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = MacHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(
        result.scan_success,
        "AppArmor enforcing scan should succeed"
    );
    // All profiles in enforce mode - should have no findings
    assert!(
        result.scan_findings.is_empty(),
        "AppArmor all-enforce should have no findings, but got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_title)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_mac_scan_apparmor_complain_mode() {
    let executor = apparmor_complain_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = MacHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success, "AppArmor complain scan should succeed");
    assert!(
        !result.scan_findings.is_empty(),
        "AppArmor complain mode should have findings"
    );

    // Should flag profiles in complain mode
    let finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id.contains("apparmor"))
        .expect("Should have AppArmor finding");

    assert!(
        finding.finding_description.contains("complain")
            || finding.finding_current_value.contains("complain"),
        "finding should mention complain mode, got description: {}, value: {}",
        finding.finding_description,
        finding.finding_current_value
    );
}

#[tokio::test]
async fn test_mac_scan_no_mac_system() {
    let executor = no_mac_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = MacHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success, "no MAC system scan should succeed");
    assert!(
        !result.scan_findings.is_empty(),
        "no MAC system should have findings"
    );

    let finding = &result.scan_findings[0];
    assert_eq!(finding.finding_id, "no-mac-system");
    // No MAC system is Medium severity (not Critical per the implementation)
    assert_eq!(finding.finding_severity, Severity::Medium);
}

#[tokio::test]
async fn test_mac_scan_compliance_mappings() {
    let executor = selinux_permissive_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = MacHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    let finding = &result.scan_findings[0];
    assert!(
        !finding.finding_compliance.is_empty(),
        "MAC finding should have compliance mappings"
    );
    // CIS control for MAC
    assert!(
        finding.finding_compliance[0]
            .compliance_control_id
            .starts_with("1.6"),
        "MAC compliance control should start with 1.6, got: {}",
        finding.finding_compliance[0].compliance_control_id
    );
}

#[tokio::test]
async fn test_mac_validate_with_selinux() {
    let executor = selinux_enforcing_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = MacHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    assert!(
        result.validation_report_is_valid,
        "validation with SELinux should be valid"
    );
}

#[tokio::test]
async fn test_mac_validate_no_mac() {
    let executor = no_mac_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = MacHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    // Current implementation: validate returns valid even with no MAC
    // (the scan will flag the issue, but validate just checks prerequisites)
    // This is a design choice - validate checks if apply CAN run, not if it SHOULD
    assert!(
        result.validation_report_is_valid,
        "validation without MAC should still be valid (checks prerequisites only)"
    );
}

#[tokio::test]
async fn test_mac_scan_duration_recorded() {
    let executor = selinux_enforcing_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = MacHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(
        result.scan_duration_us > 0,
        "scan duration should be recorded"
    );
}

#[tokio::test]
async fn test_mac_metadata() {
    let plugin = MacHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id, PluginId::new("mac-hardening"));
    assert_eq!(metadata.plugin_name, "MAC System Hardening");
}

#[tokio::test]
async fn test_mac_scan_with_remote_executor() {
    let executor = MockExecutor::new()
        .remote()
        .with_description("ssh://admin@rhel-server.example.com")
        .with_file_metadata(
            "/sys/fs/selinux",
            "",
            FileMetadata {
                exists: true,
                is_file: false,
                is_dir: true,
                mode: 0o755,
                size: 0,
                uid: 0,
                gid: 0,
            },
        )
        .with_command(
            "getenforce",
            &[],
            CommandOutput {
                stdout: "Permissive\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        );

    assert!(
        executor.is_remote(),
        "remote executor should report as remote"
    );

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = MacHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success, "remote MAC scan should succeed");
    // Should find SELinux not enforcing on remote
    assert!(
        !result.scan_findings.is_empty(),
        "SELinux permissive on remote should have findings"
    );
}

#[tokio::test]
async fn test_mac_apply_skips_exceptions() {
    // SELinux permissive, but NO setenforce command registered.
    // If the plugin tries to call setenforce, the mock will error → test fails.
    let executor = selinux_permissive_executor();
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = MacHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "selinux-enforcing".to_string(),
        PolicyException {
            value: "Permissive".to_string(),
            allowed: true,
            reason: "Development environment".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    // Should have a "skipped" change for SELinux enforcement
    let skipped = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("skipped"));
    assert!(
        skipped.is_some(),
        "should have a skipped change for SELinux"
    );
    assert!(
        skipped
            .expect("checked above")
            .change_description
            .contains("Development environment"),
    );

    // Verify no setenforce command was issued
    let log = executor.log();
    assert!(
        !log.commands_executed
            .iter()
            .any(|(cmd, _)| cmd == "setenforce"),
        "should not execute setenforce for excepted MAC action"
    );
}

#[tokio::test]
async fn test_mac_validate_skips_exceptions() {
    let executor = selinux_permissive_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = MacHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "selinux-enforcing".to_string(),
        PolicyException {
            value: "Permissive".to_string(),
            allowed: true,
            reason: "Development environment".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let report = plugin.validate(&ctx, &config).await.unwrap();

    // Excepted action should NOT appear in estimated_changes
    assert!(
        !report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("SELinux") || c.contains("selinux")),
        "excepted SELinux action should not appear in estimated changes"
    );
}

#[tokio::test]
async fn test_mac_apply_no_mac_system_is_graceful_skip() {
    // A host with neither SELinux nor AppArmor is a normal configuration
    // (many desktop distros ship without a MAC system). Apply must report a
    // successful no-op skip, not a plugin failure: a failure here makes every
    // all-plugin apply abort with "One or more plugins failed to apply".
    let executor = no_mac_executor();
    let mut ctx = Context::with_executor(Arc::new(executor));
    let plugin = MacHardeningPlugin::new();

    let result = plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        result.apply_success,
        "absent MAC system must be a graceful skip, got error: {:?}",
        result.apply_error
    );
    assert!(result.apply_error.is_none());
    let skip = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("No MAC system"))
        .expect("should record an explanatory no-op change");
    assert!(skip.change_success);
    assert_eq!(
        skip.change_type,
        ChangeType::Skipped,
        "a no-op skip must not carry a real ChangeType, or renderers will \
         count it as an applied change"
    );
}

#[tokio::test]
async fn test_mac_apply_exception_skips_carry_skipped_change_type() {
    // Policy-exception skips (SELinux/AppArmor) are semantically the same as
    // the no-MAC-system skip: nothing was touched on the host, so they must
    // not be counted as applied changes either.
    let executor = selinux_permissive_executor();
    let mut ctx = Context::with_executor(Arc::new(executor));
    let plugin = MacHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "selinux-enforcing".to_string(),
        PolicyException {
            value: "Permissive".to_string(),
            allowed: true,
            reason: "Development environment".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    let skip = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("skipped"))
        .expect("should have a skipped change for SELinux");
    assert_eq!(skip.change_type, ChangeType::Skipped);
}
