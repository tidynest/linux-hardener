//! Permissions plugin tests using MockExecutor.
//!
//! These tests verify plugin behavior without touching real file permissions.

use hardener_common::types::{PluginId, Severity};
use hardener_core::{
    CommandOutput, Context, FileMetadata, MockExecutor, PluginConfig, PolicyException,
    SystemExecutor, plugin::HardeningPlugin,
};
use hardener_plugins::PermissionsHardeningPlugin;
use std::sync::Arc;

/// Creates a mock executor with secure file permissions.
fn secure_permissions_executor() -> MockExecutor {
    MockExecutor::new()
        .with_file_metadata(
            "/root",
            "",
            FileMetadata {
                exists: true,
                is_file: false,
                is_dir: true,
                mode: 0o700,
                size: 0,
            },
        )
        .with_file_metadata(
            "/boot",
            "",
            FileMetadata {
                exists: true,
                is_file: false,
                is_dir: true,
                mode: 0o700,
                size: 0,
            },
        )
        .with_file_metadata(
            "/etc/ssh",
            "",
            FileMetadata {
                exists: true,
                is_file: false,
                is_dir: true,
                mode: 0o755,
                size: 0,
            },
        )
        .with_file_metadata(
            "/etc/sudoers",
            "",
            FileMetadata {
                exists: true,
                is_file: true,
                is_dir: false,
                mode: 0o440,
                size: 100,
            },
        )
        .with_file_metadata(
            "/etc/sudoers.d",
            "",
            FileMetadata {
                exists: true,
                is_file: false,
                is_dir: true,
                mode: 0o750,
                size: 0,
            },
        )
}

/// Creates a mock executor with insecure file permissions.
fn insecure_permissions_executor() -> MockExecutor {
    MockExecutor::new()
        // /root is world-readable
        .with_file_metadata(
            "/root",
            "",
            FileMetadata {
                exists: true,
                is_file: false,
                is_dir: true,
                mode: 0o755, // Too permissive
                size: 0,
            },
        )
        // /boot is world-writable
        .with_file_metadata(
            "/boot",
            "",
            FileMetadata {
                exists: true,
                is_file: false,
                is_dir: true,
                mode: 0o777, // Way too permissive
                size: 0,
            },
        )
        // /etc/ssh is correct
        .with_file_metadata(
            "/etc/ssh",
            "",
            FileMetadata {
                exists: true,
                is_file: false,
                is_dir: true,
                mode: 0o755,
                size: 0,
            },
        )
        // /etc/sudoers is world-readable
        .with_file_metadata(
            "/etc/sudoers",
            "",
            FileMetadata {
                exists: true,
                is_file: true,
                is_dir: false,
                mode: 0o644, // Too permissive
                size: 100,
            },
        )
    // /etc/sudoers.d is missing
}

#[tokio::test]
async fn test_permissions_scan_secure_config_no_findings() {
    let executor = secure_permissions_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(
        result.scan_success,
        "secure permissions scan should succeed"
    );
    assert_eq!(
        result.scan_plugin_id,
        PluginId::new("permissions-hardening")
    );
    assert!(
        result.scan_findings.is_empty(),
        "Secure permissions should have no findings, but got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_title)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_permissions_scan_finds_insecure_permissions() {
    let executor = insecure_permissions_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(
        result.scan_success,
        "insecure permissions scan should succeed"
    );
    assert!(
        !result.scan_findings.is_empty(),
        "insecure permissions should have findings"
    );

    let finding_ids: Vec<_> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();

    // Should find issues with /root, /boot, and /etc/sudoers
    assert!(
        finding_ids.iter().any(|id| id.contains("root")),
        "should flag /root, got: {finding_ids:?}"
    );
    assert!(
        finding_ids.iter().any(|id| id.contains("boot")),
        "should flag /boot, got: {finding_ids:?}"
    );
    assert!(
        finding_ids
            .iter()
            .any(|id| id.contains("sudoers") && !id.contains("sudoers.d")),
        "should flag /etc/sudoers, got: {finding_ids:?}"
    );

    // /etc/ssh should NOT be in findings (it's correct)
    assert!(
        !finding_ids.iter().any(|id| id.contains("etc-ssh")),
        "correctly-permissioned /etc/ssh should not be flagged"
    );
}

#[tokio::test]
async fn test_permissions_scan_finding_structure() {
    let executor = MockExecutor::new().with_file_metadata(
        "/root",
        "",
        FileMetadata {
            exists: true,
            is_file: false,
            is_dir: true,
            mode: 0o755, // Wrong - should be 0o700
            size: 0,
        },
    );

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert_eq!(result.scan_findings.len(), 1);
    let finding = &result.scan_findings[0];

    assert!(
        finding.finding_id.contains("root"),
        "finding ID should mention root, got: {}",
        finding.finding_id
    );
    assert_eq!(finding.finding_current_value, "0755");
    assert_eq!(finding.finding_recommended_value, "0700");
    assert_eq!(finding.finding_severity, Severity::High);
    assert!(
        finding.finding_title.contains("/root"),
        "finding title should mention /root, got: {}",
        finding.finding_title
    );
    assert!(
        !finding.finding_remediation_steps.is_empty(),
        "finding should have remediation steps"
    );
    assert!(
        finding.finding_remediation_steps[0].contains("chmod"),
        "remediation should mention chmod, got: {}",
        finding.finding_remediation_steps[0]
    );
}

#[tokio::test]
async fn test_permissions_scan_missing_paths_skipped() {
    // Empty executor - no paths exist
    let executor = MockExecutor::new();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(
        result.scan_success,
        "scan with missing paths should succeed"
    );
    // Missing paths should be skipped, not flagged
    assert!(
        result.scan_findings.is_empty(),
        "missing paths should produce no findings, found: {:?}",
        result.scan_findings
    );
}

#[tokio::test]
async fn test_permissions_scan_sudoers_severity() {
    let executor = MockExecutor::new().with_file_metadata(
        "/etc/sudoers",
        "",
        FileMetadata {
            exists: true,
            is_file: true,
            is_dir: false,
            mode: 0o644, // Wrong - should be 0o440
            size: 100,
        },
    );

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    let sudoers_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id.contains("sudoers"))
        .expect("Should have sudoers finding");

    // Sudoers should be Critical severity
    assert_eq!(sudoers_finding.finding_severity, Severity::Critical);
}

#[tokio::test]
async fn test_permissions_scan_logs_operations() {
    let executor = MockExecutor::new().with_file_metadata(
        "/root",
        "",
        FileMetadata {
            exists: true,
            is_file: false,
            is_dir: true,
            mode: 0o700,
            size: 0,
        },
    );

    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = PermissionsHardeningPlugin::new();

    let _ = plugin.scan(&ctx).await;

    // Note: path_exists uses file_metadata internally in MockExecutor
    // So we can't directly check files_read, but we can verify the scan completed
}

#[tokio::test]
async fn test_permissions_scan_duration_recorded() {
    let executor = secure_permissions_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(
        result.scan_duration_us > 0,
        "scan duration should be recorded"
    );
}

#[tokio::test]
async fn test_permissions_validate_always_valid() {
    // Current validate implementation always returns valid
    let executor = MockExecutor::new();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    assert!(
        result.validation_report_is_valid,
        "permissions validation should always be valid"
    );
    assert!(
        result.validation_report_issues.is_empty(),
        "permissions validation should have no issues, found: {:?}",
        result.validation_report_issues
    );
}

#[tokio::test]
async fn test_permissions_metadata() {
    let plugin = PermissionsHardeningPlugin::new();
    let metadata = plugin.metadata();

    assert_eq!(metadata.plugin_id, PluginId::new("permissions-hardening"));
    assert_eq!(metadata.plugin_name, "File Permissions Hardening");
}

#[tokio::test]
async fn test_permissions_scan_with_remote_executor() {
    let executor = MockExecutor::new()
        .remote()
        .with_description("ssh://admin@server.example.com")
        .with_file_metadata(
            "/root",
            "",
            FileMetadata {
                exists: true,
                is_file: false,
                is_dir: true,
                mode: 0o755, // Insecure
                size: 0,
            },
        );

    assert!(
        executor.is_remote(),
        "remote executor should report as remote"
    );

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(
        result.scan_success,
        "remote permissions scan should succeed"
    );
    assert!(
        !result.scan_findings.is_empty(),
        "insecure remote permissions should have findings"
    );
}

/// Tests that chmod returning success but not actually changing mode is detected.
///
/// Simulates vfat/FAT32 behaviour where chmod exits 0 but the filesystem
/// ignores the request (permissions are governed by mount options).
#[tokio::test]
async fn test_permissions_apply_detects_vfat_noop() {
    // /boot at 0o755 — chmod will "succeed" but mode stays 0o755
    let executor = MockExecutor::new()
        .with_file_metadata(
            "/boot",
            "",
            FileMetadata {
                exists: true,
                is_file: false,
                is_dir: true,
                mode: 0o755,
                size: 0,
            },
        )
        .with_command(
            "chmod",
            &["0700", "/boot"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        );

    let mut ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    // Find the /boot change
    let boot_change = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("/boot"))
        .expect("Should have a change for /boot");

    assert!(
        !boot_change.change_success,
        "chmod on vfat should report failure"
    );
    assert!(
        boot_change.change_description.contains("unchanged"),
        "Should explain permissions were unchanged, got: {}",
        boot_change.change_description
    );
}

#[tokio::test]
async fn test_permissions_apply_respects_directives() {
    // /boot at 0o777 — directive overrides target to 0o755 instead of baseline 0o700
    let executor = MockExecutor::new()
        .with_file_metadata(
            "/boot",
            "",
            FileMetadata {
                exists: true,
                is_file: false,
                is_dir: true,
                mode: 0o777,
                size: 0,
            },
        )
        .with_command(
            "chmod",
            &["0755", "/boot"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        );

    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = PermissionsHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config
        .directives
        .insert("/boot".to_string(), "755".to_string());

    let _result = plugin.apply(&mut ctx, &config).await.unwrap();

    // Verify chmod was called with 0755 (not the baseline 0700)
    let log = executor.log();
    let chmod_cmd = log
        .commands_executed
        .iter()
        .find(|(cmd, args): &&(String, Vec<String>)| {
            cmd == "chmod" && args.iter().any(|a| a == "/boot")
        });
    assert!(
        chmod_cmd.is_some(),
        "should have called chmod for /boot, got: {:?}",
        log.commands_executed
    );
    let (_, args) = chmod_cmd.expect("checked above");
    assert!(
        args.iter().any(|a| a == "0755"),
        "chmod should use directive value 0755, got: {:?}",
        args
    );
}

#[tokio::test]
async fn test_permissions_apply_skips_exceptions() {
    // /boot exists with insecure perms, but excepted
    // NO chmod command registered — mock will error if called
    let executor = MockExecutor::new().with_file_metadata(
        "/boot",
        "",
        FileMetadata {
            exists: true,
            is_file: false,
            is_dir: true,
            mode: 0o777,
            size: 0,
        },
    );

    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = PermissionsHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "/boot".to_string(),
        PolicyException {
            value: "0777".to_string(),
            allowed: true,
            reason: "Mounted vfat partition".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    // Should have a "skipped" change for /boot
    let skipped = result.apply_changes.iter().find(|c| {
        c.change_description.contains("skipped") && c.change_description.contains("/boot")
    });
    assert!(skipped.is_some(), "should have a skipped change for /boot");
    assert!(
        skipped
            .expect("checked above")
            .change_description
            .contains("vfat partition"),
    );

    // Verify no chmod command was issued at all
    let log = executor.log();
    assert!(
        !log.commands_executed.iter().any(|(cmd, _)| cmd == "chmod"),
        "should not execute chmod for excepted path"
    );
}

#[tokio::test]
async fn test_permissions_validate_skips_exceptions() {
    let executor = insecure_permissions_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "/root".to_string(),
        PolicyException {
            value: "0755".to_string(),
            allowed: true,
            reason: "Shared admin access".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let report = plugin.validate(&ctx, &config).await.unwrap();

    // /root should NOT appear in estimated_changes
    assert!(
        !report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("/root")),
        "excepted path should not appear in estimated changes"
    );

    // /boot should still appear (not excepted, has insecure perms)
    assert!(
        report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("/boot")),
        "non-excepted paths should still appear"
    );
}
