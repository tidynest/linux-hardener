//! Kernel plugin tests using MockExecutor.
//!
//! These tests verify plugin behavior without touching the real /proc/sys filesystem.

use hardener_common::types::{PluginId, Severity};
use hardener_core::{Context, FileMetadata, MockExecutor, SystemExecutor, plugin::HardeningPlugin};
use hardener_plugins::KernelHardeningPlugin;
use std::sync::Arc;

/// Creates a mock executor with secure kernel parameters.
fn secure_kernel_executor() -> MockExecutor {
    MockExecutor::new()
        // All parameters set to secure values
        .with_file("/proc/sys/kernel/randomize_va_space", "2")
        .with_file("/proc/sys/kernel/kptr_restrict", "2")
        .with_file("/proc/sys/kernel/dmesg_restrict", "1")
        .with_file("/proc/sys/kernel/yama/ptrace_scope", "2")
        .with_file("/proc/sys/fs/suid_dumpable", "0")
        .with_file("/proc/sys/fs/protected_hardlinks", "1")
        .with_file("/proc/sys/fs/protected_symlinks", "1")
        .with_file("/proc/sys/net/ipv4/conf/all/rp_filter", "1")
        .with_file("/proc/sys/net/ipv4/conf/default/rp_filter", "1")
        .with_file("/proc/sys/net/ipv4/tcp_syncookies", "1")
        .with_file("/proc/sys/net/ipv4/conf/all/accept_source_route", "0")
        .with_file("/proc/sys/net/ipv4/conf/default/accept_source_route", "0")
}

/// Creates a mock executor with insecure kernel parameters.
fn insecure_kernel_executor() -> MockExecutor {
    MockExecutor::new()
        // ASLR disabled
        .with_file("/proc/sys/kernel/randomize_va_space", "0")
        // Kernel pointers exposed
        .with_file("/proc/sys/kernel/kptr_restrict", "0")
        // dmesg accessible to all
        .with_file("/proc/sys/kernel/dmesg_restrict", "0")
        // ptrace unrestricted
        .with_file("/proc/sys/kernel/yama/ptrace_scope", "0")
        // Core dumps from setuid allowed
        .with_file("/proc/sys/fs/suid_dumpable", "2")
        // Hardlink/symlink protection disabled
        .with_file("/proc/sys/fs/protected_hardlinks", "0")
        .with_file("/proc/sys/fs/protected_symlinks", "0")
        // Reverse path filtering disabled
        .with_file("/proc/sys/net/ipv4/conf/all/rp_filter", "0")
        .with_file("/proc/sys/net/ipv4/conf/default/rp_filter", "0")
        // SYN cookies disabled
        .with_file("/proc/sys/net/ipv4/tcp_syncookies", "0")
        // Source routing enabled (dangerous)
        .with_file("/proc/sys/net/ipv4/conf/all/accept_source_route", "1")
        .with_file("/proc/sys/net/ipv4/conf/default/accept_source_route", "1")
}

/// Creates a mock executor with partial/mixed settings.
fn partial_kernel_executor() -> MockExecutor {
    MockExecutor::new()
        // Some secure
        .with_file("/proc/sys/kernel/randomize_va_space", "2")
        .with_file("/proc/sys/kernel/dmesg_restrict", "1")
        // Some insecure
        .with_file("/proc/sys/kernel/kptr_restrict", "0")
        .with_file("/proc/sys/fs/suid_dumpable", "1")
    // Some missing (kernel.yama.ptrace_scope, etc.)
}

#[tokio::test]
async fn test_kernel_scan_secure_config_no_findings() {
    let executor = secure_kernel_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success);
    assert_eq!(result.scan_plugin_id, PluginId::new("kernel-hardening"));
    assert!(
        result.scan_findings.is_empty(),
        "Secure kernel should have no findings, but got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_title)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_kernel_scan_insecure_config_finds_all_issues() {
    let executor = insecure_kernel_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success);

    // Should find all 12 insecure parameters
    assert_eq!(
        result.scan_findings.len(),
        12,
        "Expected 12 findings, got {}",
        result.scan_findings.len()
    );

    // Check specific findings exist
    let finding_ids: Vec<_> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();

    assert!(finding_ids.contains(&"kernel_kernel_randomize_va_space"));
    assert!(finding_ids.contains(&"kernel_kernel_kptr_restrict"));
    assert!(finding_ids.contains(&"kernel_net_ipv4_tcp_syncookies"));
}

#[tokio::test]
async fn test_kernel_scan_partial_config_finds_some_issues() {
    let executor = partial_kernel_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success);

    // Should find issues for insecure params, skip missing ones
    let finding_ids: Vec<_> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();

    // These are insecure
    assert!(finding_ids.contains(&"kernel_kernel_kptr_restrict"));
    assert!(finding_ids.contains(&"kernel_fs_suid_dumpable"));

    // These are secure - should NOT be in findings
    assert!(!finding_ids.contains(&"kernel_kernel_randomize_va_space"));
    assert!(!finding_ids.contains(&"kernel_kernel_dmesg_restrict"));
}

#[tokio::test]
async fn test_kernel_scan_missing_params_gracefully_skipped() {
    // Empty executor - no proc files
    let executor = MockExecutor::new();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    // Scan should succeed even with no readable params
    assert!(result.scan_success);
    // No findings because params don't exist
    assert!(result.scan_findings.is_empty());
}

#[tokio::test]
async fn test_kernel_scan_finding_structure() {
    let executor = MockExecutor::new().with_file("/proc/sys/kernel/randomize_va_space", "0");

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert_eq!(result.scan_findings.len(), 1);
    let finding = &result.scan_findings[0];

    assert_eq!(finding.finding_id, "kernel_kernel_randomize_va_space");
    assert_eq!(finding.finding_current_value, "0");
    assert_eq!(finding.finding_recommended_value, "2");
    assert_eq!(finding.finding_severity, Severity::Medium);
    assert!(finding.finding_title.contains("kernel.randomize_va_space"));
    assert!(!finding.finding_compliance.is_empty());
}

#[tokio::test]
async fn test_kernel_scan_compliance_mappings() {
    let executor = MockExecutor::new()
        .with_file("/proc/sys/kernel/randomize_va_space", "0")
        .with_file("/proc/sys/net/ipv4/tcp_syncookies", "0");

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    // ASLR finding should have CIS 1.5.1 mapping
    let aslr_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "kernel_kernel_randomize_va_space")
        .unwrap();
    assert!(!aslr_finding.finding_compliance.is_empty());
    assert_eq!(
        aslr_finding.finding_compliance[0].compliance_control_id,
        "1.5.1"
    );

    // TCP syncookies should have CIS 3.2.8 mapping
    let syncookies_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "kernel_net_ipv4_tcp_syncookies")
        .unwrap();
    assert_eq!(
        syncookies_finding.finding_compliance[0].compliance_control_id,
        "3.2.8"
    );
}

#[tokio::test]
async fn test_kernel_validate_writable_params() {
    let executor = MockExecutor::new().with_file_metadata(
        "/proc/sys/kernel/randomize_va_space",
        "2",
        FileMetadata {
            exists: true,
            is_file: true,
            is_dir: false,
            mode: 0o644, // rw-r--r-- (writable by owner)
            size: 2,
        },
    );

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    // Should have estimated change for writable param
    assert!(!result.validation_report_estimated_changes.is_empty());
    assert!(result.validation_report_estimated_changes[0].contains("randomize_va_space"));
}

#[tokio::test]
async fn test_kernel_validate_readonly_params() {
    let executor = MockExecutor::new().with_file_metadata(
        "/proc/sys/kernel/randomize_va_space",
        "2",
        FileMetadata {
            exists: true,
            is_file: true,
            is_dir: false,
            mode: 0o444, // r--r--r-- (read-only)
            size: 2,
        },
    );

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    // Should have validation issue for read-only param
    assert!(!result.validation_report_is_valid);
    assert!(!result.validation_report_issues.is_empty());

    let issue = &result.validation_report_issues[0];
    assert_eq!(issue.validation_issue_severity, Severity::High);
    assert!(issue.validation_issue_message.contains("read-only"));
}

#[tokio::test]
async fn test_kernel_validate_missing_params() {
    // MockExecutor returns Ok(FileMetadata { exists: false, mode: 0 }) for missing files
    // The kernel plugin sees mode=0, which means "read-only" (no write bit)
    // So missing params are treated as High severity "read-only" issues
    let executor = MockExecutor::new(); // Empty - no params
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();
    let config = hardener_core::PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    // With MockExecutor, missing files return mode=0, which triggers "read-only" check
    // This results in High severity issues, making validation fail
    assert!(!result.validation_report_is_valid);
    assert!(!result.validation_report_issues.is_empty());

    // All issues should be about read-only (mode=0)
    for issue in &result.validation_report_issues {
        assert_eq!(issue.validation_issue_severity, Severity::High);
        assert!(issue.validation_issue_message.contains("read-only"));
    }
}

#[tokio::test]
async fn test_kernel_scan_logs_file_reads() {
    let executor = MockExecutor::new()
        .with_file("/proc/sys/kernel/randomize_va_space", "2")
        .with_file("/proc/sys/kernel/kptr_restrict", "2");

    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = KernelHardeningPlugin::new();

    let _ = plugin.scan(&ctx).await;

    let log = executor.log();

    // Should have attempted to read all kernel params
    assert!(
        log.files_read
            .iter()
            .any(|p| p.to_str().unwrap().contains("randomize_va_space"))
    );
    assert!(
        log.files_read
            .iter()
            .any(|p| p.to_str().unwrap().contains("kptr_restrict"))
    );
}

#[tokio::test]
async fn test_kernel_scan_duration_recorded() {
    let executor = secure_kernel_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(
        result.scan_duration_us > 0,
        "Scan duration should be recorded"
    );
}

#[tokio::test]
async fn test_kernel_scan_with_remote_executor() {
    // Simulate scanning a remote system's kernel
    let executor = MockExecutor::new()
        .remote()
        .with_description("ssh://admin@server.example.com")
        .with_file("/proc/sys/kernel/randomize_va_space", "2")
        .with_file("/proc/sys/kernel/kptr_restrict", "1"); // Insecure

    assert!(executor.is_remote());

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let result = plugin.scan(&ctx).await.unwrap();

    assert!(result.scan_success);
    // Should find kptr_restrict issue
    assert!(
        result
            .scan_findings
            .iter()
            .any(|f| f.finding_id == "kernel_kernel_kptr_restrict")
    );
}
