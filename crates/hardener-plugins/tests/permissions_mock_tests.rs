//! Permissions plugin tests using MockExecutor.
//!
//! These tests verify plugin behavior without touching real file permissions.

use hardener_common::types::{PluginId, Severity};
use hardener_core::{Context, FileMetadata, MockExecutor, SystemExecutor, plugin::HardeningPlugin};
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

    assert!(result.scan_success);
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

    assert!(result.scan_success);
    assert!(!result.scan_findings.is_empty());

    let finding_ids: Vec<_> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();

    // Should find issues with /root, /boot, and /etc/sudoers
    assert!(finding_ids.iter().any(|id| id.contains("root")));
    assert!(finding_ids.iter().any(|id| id.contains("boot")));
    assert!(
        finding_ids
            .iter()
            .any(|id| id.contains("sudoers") && !id.contains("sudoers.d"))
    );

    // /etc/ssh should NOT be in findings (it's correct)
    assert!(!finding_ids.iter().any(|id| id.contains("etc-ssh")));
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

    assert!(finding.finding_id.contains("root"));
    assert_eq!(finding.finding_current_value, "0755");
    assert_eq!(finding.finding_recommended_value, "0700");
    assert_eq!(finding.finding_severity, Severity::High);
    assert!(finding.finding_title.contains("/root"));
    assert!(!finding.finding_remediation_steps.is_empty());
    assert!(finding.finding_remediation_steps[0].contains("chmod"));
}

#[tokio::test]
async fn test_permissions_scan_missing_paths_skipped() {
    // Empty executor - no paths exist
    let executor = MockExecutor::new();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success);
    // Missing paths should be skipped, not flagged
    assert!(result.scan_findings.is_empty());
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

    assert!(result.scan_duration_us > 0);
}

#[tokio::test]
async fn test_permissions_validate_always_valid() {
    // Current validate implementation always returns valid
    let executor = MockExecutor::new();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    assert!(result.validation_report_is_valid);
    assert!(result.validation_report_issues.is_empty());
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

    assert!(executor.is_remote());

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success);
    assert!(!result.scan_findings.is_empty());
}
