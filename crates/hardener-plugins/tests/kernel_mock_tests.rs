//! Kernel plugin tests using MockExecutor.
//!
//! These tests verify plugin behaviour without touching the real /proc/sys filesystem.

use hardener_common::types::{PluginId, Severity};
use hardener_core::{
    CommandOutput, Context, FileMetadata, MockExecutor, PluginConfig, PolicyException,
    SystemExecutor, plugin::HardeningPlugin,
};
use hardener_plugins::KernelHardeningPlugin;
use std::sync::Arc;

/// Creates a mock executor with secure kernel parameters.
fn secure_kernel_executor() -> MockExecutor {
    MockExecutor::new()
        // Nearly every host ships the sysctl drop-in directory; the ones that
        // do not are covered by their own tests further down.
        .with_directory("/etc/sysctl.d")
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

/// Creates a mock executor with EVERY kernel parameter at its secure value,
/// covering the full baseline (the `secure_kernel_executor` above omits the
/// redirect/martian parameters, which state-aware tests must also see).
fn fully_secure_kernel_executor() -> MockExecutor {
    secure_kernel_executor()
        .with_file("/proc/sys/net/ipv4/conf/all/accept_redirects", "0")
        .with_file("/proc/sys/net/ipv4/conf/default/accept_redirects", "0")
        .with_file("/proc/sys/net/ipv4/conf/all/secure_redirects", "0")
        .with_file("/proc/sys/net/ipv4/conf/default/secure_redirects", "0")
        .with_file("/proc/sys/net/ipv4/conf/all/log_martians", "1")
        .with_file("/proc/sys/net/ipv4/conf/default/log_martians", "1")
}

/// Creates a mock executor with insecure kernel parameters.
fn insecure_kernel_executor() -> MockExecutor {
    MockExecutor::new()
        .with_directory("/etc/sysctl.d")
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
        .with_directory("/etc/sysctl.d")
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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(
        result.scan_success,
        "secure kernel scan should succeed, got: {result:?}"
    );
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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(result.scan_success, "insecure kernel scan should succeed");

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

    assert!(
        finding_ids.contains(&"kernel_kernel_randomize_va_space"),
        "should flag ASLR, got: {finding_ids:?}"
    );
    assert!(
        finding_ids.contains(&"kernel_kernel_kptr_restrict"),
        "should flag kptr_restrict, got: {finding_ids:?}"
    );
    assert!(
        finding_ids.contains(&"kernel_net_ipv4_tcp_syncookies"),
        "should flag tcp_syncookies, got: {finding_ids:?}"
    );
}

#[tokio::test]
async fn test_kernel_scan_partial_config_finds_some_issues() {
    let executor = partial_kernel_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(result.scan_success, "partial kernel scan should succeed");

    // Should find issues for insecure params, skip missing ones
    let finding_ids: Vec<_> = result
        .scan_findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();

    // These are insecure
    assert!(
        finding_ids.contains(&"kernel_kernel_kptr_restrict"),
        "insecure kptr_restrict should be flagged"
    );
    assert!(
        finding_ids.contains(&"kernel_fs_suid_dumpable"),
        "insecure suid_dumpable should be flagged"
    );

    // These are secure - should NOT be in findings
    assert!(
        !finding_ids.contains(&"kernel_kernel_randomize_va_space"),
        "secure ASLR should not be flagged"
    );
    assert!(
        !finding_ids.contains(&"kernel_kernel_dmesg_restrict"),
        "secure dmesg_restrict should not be flagged"
    );
}

#[tokio::test]
async fn test_kernel_scan_missing_params_gracefully_skipped() {
    // Empty executor - no proc files
    let executor = MockExecutor::new();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    // Scan should succeed even with no readable params
    assert!(
        result.scan_success,
        "scan with missing params should still succeed"
    );
    // No findings because params don't exist
    assert!(
        result.scan_findings.is_empty(),
        "missing params should produce no findings, found: {:?}",
        result.scan_findings
    );
}

#[tokio::test]
async fn test_kernel_scan_finding_structure() {
    let executor = MockExecutor::new().with_file("/proc/sys/kernel/randomize_va_space", "0");

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert_eq!(result.scan_findings.len(), 1);
    let finding = &result.scan_findings[0];

    assert_eq!(finding.finding_id, "kernel_kernel_randomize_va_space");
    assert_eq!(finding.finding_current_value, "0");
    assert_eq!(finding.finding_recommended_value, "2");
    assert_eq!(finding.finding_severity, Severity::High);
    assert!(
        finding.finding_title.contains("kernel.randomize_va_space"),
        "finding title should mention param name, got: {}",
        finding.finding_title
    );
    assert!(
        !finding.finding_compliance.is_empty(),
        "finding should have compliance mappings"
    );
}

#[tokio::test]
async fn test_kernel_scan_compliance_mappings() {
    let executor = MockExecutor::new()
        .with_file("/proc/sys/kernel/randomize_va_space", "0")
        .with_file("/proc/sys/net/ipv4/tcp_syncookies", "0");

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    // ASLR finding should have CIS 1.5.1 mapping
    let aslr_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "kernel_kernel_randomize_va_space")
        .unwrap();
    assert!(
        !aslr_finding.finding_compliance.is_empty(),
        "ASLR finding should have compliance mappings"
    );
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
    // Deliberately drifted (0, target 2): validate is state-aware, so only a
    // parameter whose current value differs from the target is listed as
    // pending. (This test previously used the compliant value "2" and still
    // expected a pending line; that encoded the old unconditional behaviour.)
    let executor = MockExecutor::new().with_file_metadata(
        "/proc/sys/kernel/randomize_va_space",
        "0",
        FileMetadata {
            exists: true,
            is_file: true,
            is_dir: false,
            mode: 0o644, // rw-r--r-- (writable by owner)
            size: 2,
            uid: 0,
            gid: 0,
        },
    );

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();
    let config = PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    // Should have estimated change for writable, drifted param
    assert!(
        !result.validation_report_estimated_changes.is_empty(),
        "writable drifted param should produce estimated changes"
    );
    assert!(
        result.validation_report_estimated_changes[0].contains("randomize_va_space"),
        "estimated change should mention randomize_va_space, got: {}",
        result.validation_report_estimated_changes[0]
    );
}

/// State-aware validate: a fully compliant host lists ZERO pending parameter
/// changes; every checked parameter is tallied in
/// `validation_report_compliant_count` instead, so the admin can see they were
/// checked without the estimated-change count being inflated.
#[tokio::test]
async fn kernel_validate_all_compliant_lists_no_pending_changes() {
    let executor = fully_secure_kernel_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let report = plugin
        .validate(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        report.validation_report_is_valid,
        "compliant host should validate cleanly"
    );
    assert!(
        !report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("will change") || c.contains("will be set")),
        "no parameter should be listed as pending on a compliant host, got: {:?}",
        report.validation_report_estimated_changes
    );
    assert!(
        report.validation_report_estimated_changes.is_empty(),
        "a fully compliant host has no pending changes, got: {:?}",
        report.validation_report_estimated_changes
    );
    assert_eq!(
        report.validation_report_compliant_count, 18,
        "all 18 parameters must be counted as already compliant, not listed as pending"
    );
}

/// State-aware validate: with exactly one drifted parameter, exactly that
/// parameter is listed as "current -> target" and the rest are summarised.
#[tokio::test]
async fn kernel_validate_one_drifted_lists_exactly_that_parameter() {
    let executor = fully_secure_kernel_executor().with_file("/proc/sys/kernel/kptr_restrict", "0");
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let report = plugin
        .validate(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    let pending: Vec<&String> = report
        .validation_report_estimated_changes
        .iter()
        .filter(|c| c.contains("will change"))
        .collect();
    assert_eq!(
        pending.len(),
        1,
        "exactly one parameter should be pending, got: {:?}",
        report.validation_report_estimated_changes
    );
    assert!(
        pending[0].contains("kernel.kptr_restrict")
            && pending[0].contains('0')
            && pending[0].contains('2'),
        "pending line must show current and target, got: {}",
        pending[0]
    );
    assert_eq!(
        report.validation_report_estimated_changes.len(),
        1,
        "only the drifted parameter is pending, got: {:?}",
        report.validation_report_estimated_changes
    );
    assert_eq!(
        report.validation_report_compliant_count, 17,
        "the other 17 parameters must be counted as already compliant"
    );
}

/// State-aware apply: on a fully compliant host no /proc/sys path is written;
/// the run reports one Skipped summary and only the persistent config file
/// (absent in this fixture) is created.
#[tokio::test]
async fn kernel_apply_all_compliant_writes_no_runtime_params() {
    let executor = Arc::new(fully_secure_kernel_executor());
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = KernelHardeningPlugin::new();

    let result = plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(result.apply_success, "compliant apply should succeed");

    let log = executor.log();
    assert!(
        !log.files_written
            .iter()
            .any(|(p, _)| p.starts_with("/proc/sys")),
        "no runtime sysctl should be written on a compliant host, got: {:?}",
        log.files_written
    );

    let skipped = result
        .apply_changes
        .iter()
        .find(|c| c.is_skipped() && c.change_description.contains("already compliant"))
        .expect("expected a Skipped summary for already-compliant sysctls");
    assert!(
        skipped.change_description.contains("18"),
        "summary should count all 18 compliant sysctls, got: {}",
        skipped.change_description
    );
    assert!(skipped.change_success);
}

/// A second apply on an unchanged host is a complete no-op: the persistent
/// config written by the first run already matches, so nothing at all is
/// written and the config skip is reported honestly.
#[tokio::test]
async fn kernel_apply_second_run_writes_nothing_at_all() {
    let executor = Arc::new(fully_secure_kernel_executor());
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = KernelHardeningPlugin::new();

    // First run creates /etc/sysctl.d/99-hardener.conf.
    plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .unwrap();
    executor.clear_log();

    let result = plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .unwrap();

    let log = executor.log();
    assert!(
        log.files_written.is_empty(),
        "second apply on an unchanged host must write nothing, got: {:?}",
        log.files_written
    );
    assert!(
        result
            .apply_changes
            .iter()
            .any(|c| c.is_skipped() && c.change_description.contains("already up to date")),
        "persistent config skip must be reported, got: {:?}",
        result.apply_changes
    );
    assert_eq!(
        result.applied_change_count(),
        0,
        "no-op apply must count zero applied changes"
    );
}

/// State-aware apply: exactly the drifted parameter is written at runtime.
#[tokio::test]
async fn kernel_apply_one_drifted_writes_only_that_parameter() {
    let executor =
        Arc::new(fully_secure_kernel_executor().with_file("/proc/sys/kernel/kptr_restrict", "0"));
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = KernelHardeningPlugin::new();

    let result = plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .unwrap();

    let log = executor.log();
    let proc_writes: Vec<_> = log
        .files_written
        .iter()
        .filter(|(p, _)| p.starts_with("/proc/sys"))
        .collect();
    assert_eq!(
        proc_writes.len(),
        1,
        "only the drifted parameter should be written, got: {proc_writes:?}"
    );
    assert_eq!(
        proc_writes[0].0.to_str().unwrap(),
        "/proc/sys/kernel/kptr_restrict"
    );
    assert_eq!(proc_writes[0].1, "2");

    assert!(
        result
            .apply_changes
            .iter()
            .any(|c| c.is_skipped() && c.change_description.contains("17")),
        "the other 17 compliant sysctls must be summarised as skipped, got: {:?}",
        result.apply_changes
    );
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
            uid: 0,
            gid: 0,
        },
    );

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();
    let config = PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    // Should have validation issue for read-only param
    assert!(
        !result.validation_report_is_valid,
        "read-only param should make validation invalid"
    );
    assert!(
        !result.validation_report_issues.is_empty(),
        "read-only param should produce validation issues"
    );

    let issue = &result.validation_report_issues[0];
    assert_eq!(issue.validation_issue_severity, Severity::High);
    assert!(
        issue.validation_issue_message.contains("read-only"),
        "issue should mention read-only, got: {}",
        issue.validation_issue_message
    );
}

#[tokio::test]
async fn test_kernel_validate_missing_params() {
    // MockExecutor returns Ok(FileMetadata { exists: false, mode: 0 }) for missing files
    // The kernel plugin sees mode=0, which means "read-only" (no write bit)
    // So missing params are treated as High severity "read-only" issues
    let executor = MockExecutor::new(); // Empty - no params
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();
    let config = PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    // With MockExecutor, missing files return mode=0, which triggers "read-only" check
    // This results in High severity issues, making validation fail
    assert!(
        !result.validation_report_is_valid,
        "missing params (mode=0) should make validation invalid"
    );
    assert!(
        !result.validation_report_issues.is_empty(),
        "missing params should produce validation issues"
    );

    // All issues should be about read-only (mode=0)
    for issue in &result.validation_report_issues {
        assert_eq!(issue.validation_issue_severity, Severity::High);
        assert!(
            issue.validation_issue_message.contains("read-only"),
            "issue should mention read-only, got: {}",
            issue.validation_issue_message
        );
    }
}

#[tokio::test]
async fn test_kernel_scan_logs_file_reads() {
    let executor = MockExecutor::new()
        .with_file("/proc/sys/kernel/randomize_va_space", "2")
        .with_file("/proc/sys/kernel/kptr_restrict", "2");

    let ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = KernelHardeningPlugin::new();

    let _ = plugin.scan(&ctx, &PluginConfig::default()).await;

    let log = executor.log();

    // Should have attempted to read all kernel params
    assert!(
        log.files_read
            .iter()
            .any(|p| p.to_str().unwrap().contains("randomize_va_space")),
        "should have read randomize_va_space, got: {:?}",
        log.files_read
    );
    assert!(
        log.files_read
            .iter()
            .any(|p| p.to_str().unwrap().contains("kptr_restrict")),
        "should have read kptr_restrict, got: {:?}",
        log.files_read
    );
}

#[tokio::test]
async fn test_kernel_scan_duration_recorded() {
    let executor = secure_kernel_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    assert!(
        executor.is_remote(),
        "remote executor should report as remote"
    );

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(result.scan_success, "remote kernel scan should succeed");
    // Should find kptr_restrict issue
    assert!(
        result
            .scan_findings
            .iter()
            .any(|f| f.finding_id == "kernel_kernel_kptr_restrict"),
        "should flag kptr_restrict on remote, got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_id)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_kernel_apply_respects_directives() {
    let executor = insecure_kernel_executor();
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = KernelHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config
        .directives
        .insert("kernel.kptr_restrict".to_string(), "3".to_string());

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    // The directive-overridden param should report target value "3"
    let kptr_change = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("kernel pointers"))
        .expect("should have a kptr_restrict change");
    assert!(
        kptr_change.change_description.contains("set to 3"),
        "expected directive value '3', got: {}",
        kptr_change.change_description
    );

    // Verify the mock executor received "3" for that path
    let log = executor.log();
    let kptr_write = log
        .files_written
        .iter()
        .find(|(p, _)| p.to_str().unwrap().contains("kptr_restrict"))
        .expect("should have written to kptr_restrict path");
    assert_eq!(kptr_write.1, "3");
}

#[tokio::test]
async fn test_kernel_apply_skips_exceptions() {
    let executor = insecure_kernel_executor();
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = KernelHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "kernel.randomize_va_space".to_string(),
        PolicyException {
            value: "0".to_string(),
            allowed: true,
            reason: "Legacy software compatibility".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    // Should have a "skipped" change for the excepted param
    let skipped = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("skipped"))
        .expect("should have a skipped change");
    assert!(skipped.change_description.contains("Legacy software"));
    assert!(
        skipped.change_success,
        "skipped change should report success"
    );

    // Should NOT have written to the excepted param's /proc/sys path
    let log = executor.log();
    assert!(
        !log.files_written
            .iter()
            .any(|(p, _)| p.to_str().unwrap().contains("randomize_va_space")),
        "should not write to excepted parameter"
    );
}

#[tokio::test]
async fn apply_ignores_exception_whose_value_does_not_match() {
    // The host has randomize_va_space = 0, but the exception documents 2.
    // An exception that does not describe the host must not stop hardening.
    let executor = insecure_kernel_executor();
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = KernelHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "kernel.randomize_va_space".to_string(),
        PolicyException {
            value: "2".to_string(),
            allowed: true,
            reason: "Stale exception".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    assert!(
        !result
            .apply_changes
            .iter()
            .any(|c| c.change_description.contains("Stale exception")),
        "a non-matching exception must not produce a skipped change"
    );

    // The positive assertion: hardening must actually have happened, not
    // merely have failed to record a stale-exception skip (which would also
    // pass if apply returned early for an unrelated reason).
    let log = executor.log();
    let write = log
        .files_written
        .iter()
        .find(|(p, _)| p.to_str().unwrap().contains("randomize_va_space"))
        .expect("should have written randomize_va_space despite the stale exception");
    assert_eq!(
        write.1, "2",
        "randomize_va_space must be hardened to the secure value 2, got: {}",
        write.1
    );
}

#[tokio::test]
async fn scan_honours_directive_override() {
    // Baseline for a param whose actual value equals the built-in expected,
    // but a stricter directive makes it non-compliant -> a finding appears.
    let executor = secure_kernel_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config
        .directives
        .insert("kernel.kptr_restrict".to_string(), "3".to_string());

    let result = plugin.scan(&ctx, &config).await.unwrap();

    let finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "kernel_kernel_kptr_restrict")
        .unwrap_or_else(|| {
            panic!(
                "stricter directive should surface a finding, got: {:?}",
                result
                    .scan_findings
                    .iter()
                    .map(|f| &f.finding_id)
                    .collect::<Vec<_>>()
            )
        });

    // Target-dependent fields must reflect the override (3), not the built-in
    // baseline (2) the host already meets - otherwise the finding would
    // recommend the value the host is at and read as self-contradictory.
    assert_eq!(
        finding.finding_recommended_value, "3",
        "recommended value should reflect the directive override, not the baseline"
    );
    assert!(
        finding.finding_explanation.contains('3'),
        "explanation should quote the override value, got: {}",
        finding.finding_explanation
    );
    assert!(
        finding
            .finding_remediation_steps
            .iter()
            .any(|s| s.contains("kernel.kptr_restrict = 3")),
        "remediation should set the override value, got: {:?}",
        finding.finding_remediation_steps
    );
}

#[tokio::test]
async fn scan_annotates_valid_exception() {
    // A param that IS non-compliant, plus a valid exception for it:
    // the finding is still present but annotated.
    let executor = insecure_kernel_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "kernel.randomize_va_space".to_string(),
        PolicyException {
            value: "0".to_string(),
            allowed: true,
            reason: "Legacy software compatibility".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let result = plugin.scan(&ctx, &config).await.unwrap();

    let f = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "kernel_kernel_randomize_va_space")
        .expect("non-compliant param should still produce a finding");
    assert!(
        f.finding_policy_exception.is_some(),
        "finding should be annotated with the valid exception"
    );
}

#[tokio::test]
async fn scan_ignores_exception_whose_value_does_not_match() {
    // The exception documents a deviation to "1", but the host is actually at
    // "0". An exception that does not describe the real deviation is not an
    // exception: the finding stays a live violation, unannotated, so it still
    // fails its compliance controls.
    let executor = insecure_kernel_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "kernel.randomize_va_space".to_string(),
        PolicyException {
            value: "1".to_string(),
            allowed: true,
            reason: "Legacy software compatibility".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let result = plugin.scan(&ctx, &config).await.unwrap();

    let f = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "kernel_kernel_randomize_va_space")
        .expect("non-compliant param should still produce a finding");
    assert!(
        f.finding_policy_exception.is_none(),
        "an exception for a value the host does not have must not be honoured"
    );
}

#[tokio::test]
async fn test_kernel_validate_skips_exceptions() {
    let executor = MockExecutor::new().with_file_metadata(
        "/proc/sys/kernel/randomize_va_space",
        "0",
        FileMetadata {
            exists: true,
            is_file: true,
            is_dir: false,
            mode: 0o644,
            size: 2,
            uid: 0,
            gid: 0,
        },
    );

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "kernel.randomize_va_space".to_string(),
        PolicyException {
            value: "0".to_string(),
            allowed: true,
            reason: "Legacy software compatibility".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let report = plugin.validate(&ctx, &config).await.unwrap();

    // Excepted param should NOT appear in estimated_changes
    assert!(
        !report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("randomize_va_space")),
        "excepted param should not appear in estimated changes"
    );
}

#[tokio::test]
async fn validate_ignores_exception_whose_value_does_not_match() {
    let executor = insecure_kernel_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "kernel.randomize_va_space".to_string(),
        PolicyException {
            value: "2".to_string(),
            allowed: true,
            reason: "Stale exception".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );

    let report = plugin.validate(&ctx, &config).await.unwrap();

    assert!(
        report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("randomize_va_space")),
        "a non-matching exception must leave the change in the preview"
    );
}

/// A host stricter than this tool's baseline on the two parameters where the
/// baseline is not already the strongest value the kernel accepts: ptrace is
/// forbidden outright rather than restricted to admins, and SYN cookies are
/// unconditional rather than used on demand.
fn stricter_than_baseline_kernel_executor() -> MockExecutor {
    fully_secure_kernel_executor()
        .with_file("/proc/sys/kernel/yama/ptrace_scope", "3")
        .with_file("/proc/sys/net/ipv4/tcp_syncookies", "2")
}

#[tokio::test]
async fn kernel_scan_does_not_report_a_stricter_host_as_violating() {
    let ctx = Context::with_executor(Arc::new(stricter_than_baseline_kernel_executor()));

    let result = KernelHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("kernel scan should not error");

    assert!(
        result.scan_findings.is_empty(),
        "a host stricter than the baseline is compliant, but these were flagged: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| (f.finding_id.as_str(), f.finding_current_value.as_str()))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn kernel_apply_never_loosens_a_stricter_host() {
    let executor = Arc::new(stricter_than_baseline_kernel_executor());
    let mut ctx = Context::with_executor(executor.clone());

    KernelHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("kernel apply should not error");

    let log = executor.log();
    assert!(
        !log.files_written
            .iter()
            .any(|(p, _)| p.starts_with("/proc/sys")),
        "a host already at least as strict as the baseline needs no runtime write, got: {:?}",
        log.files_written
    );

    // The persistent file is the half of this that survives a reboot, and it
    // was written for every parameter regardless of the host's own value.
    let persisted = log
        .files_written
        .iter()
        .find(|(p, _)| p.to_str() == Some("/etc/sysctl.d/99-hardener.conf"))
        .map(|(_, content)| content.clone())
        .expect("apply must persist the settings it manages");
    assert!(
        persisted.contains("kernel.yama.ptrace_scope = 3"),
        "the persistent file would loosen ptrace_scope from 3 back to 2 at the next \
         boot, got:\n{persisted}"
    );
    assert!(
        persisted.contains("net.ipv4.tcp_syncookies = 2"),
        "the persistent file would loosen tcp_syncookies from 2 back to 1 at the next \
         boot, got:\n{persisted}"
    );
}

#[tokio::test]
async fn kernel_validate_does_not_promise_to_loosen_a_stricter_host() {
    let ctx = Context::with_executor(Arc::new(stricter_than_baseline_kernel_executor()));

    let report = KernelHardeningPlugin::new()
        .validate(&ctx, &PluginConfig::default())
        .await
        .expect("kernel validate should not error");

    assert!(
        !report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("ptrace_scope") || c.contains("tcp_syncookies")),
        "the preview promised a change that would leave the host less secure, got: {:?}",
        report.validation_report_estimated_changes
    );
}

#[tokio::test]
async fn kernel_apply_clamps_an_operator_override_that_would_loosen() {
    let executor = Arc::new(insecure_kernel_executor());
    let mut ctx = Context::with_executor(executor.clone());

    let mut config = PluginConfig::default();
    config
        .directives
        .insert("kernel.kptr_restrict".to_string(), "0".to_string());

    KernelHardeningPlugin::new()
        .apply(&mut ctx, &config)
        .await
        .expect("kernel apply should not error");

    let log = executor.log();
    let written = log
        .files_written
        .iter()
        .find(|(p, _)| p.to_str().is_some_and(|s| s.contains("kptr_restrict")))
        .map(|(_, content)| content.clone())
        .expect("a host with kernel pointers exposed must be hardened");
    assert_eq!(
        written, "2",
        "an override may tighten the baseline and never relax it"
    );
}

#[tokio::test]
async fn kernel_scan_flags_loose_mode_reverse_path_filtering() {
    // rp_filter is the parameter whose strictness its own integer does not
    // carry: 0 is off, 1 is strict mode and 2 is loose mode, so 2 is weaker
    // than 1 despite being the larger number. Judged as "larger is stricter"
    // it would score compliant.
    let ctx = Context::with_executor(Arc::new(
        fully_secure_kernel_executor().with_file("/proc/sys/net/ipv4/conf/all/rp_filter", "2"),
    ));

    let result = KernelHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .expect("kernel scan should not error");

    assert!(
        result
            .scan_findings
            .iter()
            .any(|f| f.finding_id == "kernel_net_ipv4_conf_all_rp_filter"),
        "loose-mode reverse path filtering is weaker than strict mode, findings: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| f.finding_id.as_str())
            .collect::<Vec<_>>()
    );
}

// =============================================================================
// The drop-in directory the persistent file needs
// =============================================================================

const SYSCTL_DIR: &str = "/etc/sysctl.d";
const HARDENER_CONF: &str = "/etc/sysctl.d/99-hardener.conf";

/// How many times the apply asked for the sysctl drop-in directory to exist.
fn sysctl_mkdir_count(executor: &MockExecutor) -> usize {
    executor
        .log()
        .commands_executed
        .iter()
        .filter(|(command, args)| {
            command == "mkdir"
                && args.contains(&"-p".to_string())
                && args.contains(&SYSCTL_DIR.to_string())
        })
        .count()
}

/// Whether the apply wrote the file that carries the settings across a reboot.
fn persisted_the_config(executor: &MockExecutor) -> bool {
    executor
        .log()
        .files_written
        .iter()
        .any(|(path, _)| path.to_str() == Some(HARDENER_CONF))
}

fn command_output(stderr: &str, exit_code: i32) -> CommandOutput {
    CommandOutput {
        stdout: String::new(),
        stderr: stderr.to_string(),
        exit_code,
    }
}

/// A host whose /etc/sysctl.d does not exist: on the RHEL family the directory
/// belongs to systemd-udev, and a minimal install that never pulled that package
/// in has no such directory. `write_file` lands its content through a temporary
/// file in the target directory, so it cannot create a missing parent, and the
/// persistence half of the apply failed on every run there.
#[tokio::test]
async fn kernel_apply_creates_the_sysctl_directory_when_it_is_absent() {
    let executor = Arc::new(
        fully_secure_kernel_executor()
            .with_path_exists(SYSCTL_DIR, false)
            .with_command("mkdir", &["-p", SYSCTL_DIR], command_output("", 0)),
    );
    let mut ctx = Context::with_executor(executor.clone());

    let result = KernelHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("kernel apply should not error");

    assert_eq!(
        sysctl_mkdir_count(&executor),
        1,
        "an absent parent must be created, commands: {:?}",
        executor.log().commands_executed
    );
    assert!(
        persisted_the_config(&executor),
        "the settings must still reach the persistent file, writes: {:?}",
        executor.log().files_written
    );
    assert!(
        result.apply_success,
        "an apply that created the directory it needed succeeded, changes: {:?}",
        result.apply_changes
    );
}

/// A probe that cannot answer is not an answer. `path_exists` returns an error
/// for a directory it could not determine, and reading that as "it is there"
/// would skip the creation on exactly the host that needs it. `mkdir -p` on an
/// existing directory does nothing, so attempting it costs nothing.
#[tokio::test]
async fn kernel_apply_creates_the_sysctl_directory_when_the_probe_cannot_answer() {
    let executor = Arc::new(
        fully_secure_kernel_executor()
            .with_path_exists_error(SYSCTL_DIR)
            .with_command("mkdir", &["-p", SYSCTL_DIR], command_output("", 0)),
    );
    let mut ctx = Context::with_executor(executor.clone());

    KernelHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("kernel apply should not error");

    assert_eq!(
        sysctl_mkdir_count(&executor),
        1,
        "a probe that failed must be treated as may-be-missing, commands: {:?}",
        executor.log().commands_executed
    );
}

/// `execute_command` returns Ok for a command that ran and failed, so an
/// unchecked exit code would let a failed mkdir be followed by a write that
/// cannot land. The failure must be reported as a failed change carrying the
/// reason, because "Failed to write file X" alone tells the operator nothing
/// about the directory.
#[tokio::test]
async fn kernel_apply_reports_why_the_sysctl_directory_could_not_be_created() {
    let executor = Arc::new(
        fully_secure_kernel_executor()
            .with_path_exists(SYSCTL_DIR, false)
            .with_command(
                "mkdir",
                &["-p", SYSCTL_DIR],
                command_output(
                    "mkdir: cannot create directory '/etc/sysctl.d': Read-only file system\n",
                    1,
                ),
            ),
    );
    let mut ctx = Context::with_executor(executor.clone());

    let result = KernelHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("kernel apply should not error");

    let failed = result
        .apply_changes
        .iter()
        .find(|change| !change.change_success)
        .expect("a failed mkdir must produce a failed change, not a silent success");
    assert!(
        failed
            .change_error
            .as_deref()
            .is_some_and(|reason| reason.contains("Read-only file system")),
        "the operator must be told why the directory could not be created, got: {:?}",
        failed.change_error
    );
    assert!(
        !result
            .apply_changes
            .iter()
            .any(|change| change.change_success
                && change
                    .change_description
                    .contains("persistent sysctl config")),
        "no change may report the persistent config as created, changes: {:?}",
        result.apply_changes
    );
    assert!(
        !result.apply_success,
        "an apply whose settings cannot survive a reboot has not succeeded"
    );
}

/// The directory has to exist before the checkpoint, not merely before the
/// write.
///
/// The checkpoint captures /etc/sysctl.d, and `hardener-state` stores an absent
/// path with a zero mode, which a rollback reads as "remove this". A directory
/// created after that capture therefore turns a clean rollback into a refusal:
/// the path sits in `UNDELETABLE_ROLLBACK_PATHS`, whose branch refuses a path
/// the checkpoint called absent and the host now has. Created before the
/// capture, it is recorded present and the rollback restores it.
///
/// A run that writes nothing is the case that separates the two placements: a
/// creation hung off the write cannot happen here, and one that runs ahead of
/// the checkpoint still does.
#[tokio::test]
async fn kernel_apply_creates_the_sysctl_directory_even_when_it_writes_nothing() {
    let executor = Arc::new(
        fully_secure_kernel_executor()
            .with_path_exists_error(SYSCTL_DIR)
            .with_command("mkdir", &["-p", SYSCTL_DIR], command_output("", 0)),
    );
    let mut ctx = Context::with_executor(executor.clone());
    let plugin = KernelHardeningPlugin::new();

    // The first apply leaves the persistent file holding exactly what the
    // second would write, so the second has nothing to write.
    plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("the first apply should not error");
    executor.clear_log();

    let result = plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("the second apply should not error");

    assert!(
        result.apply_changes.iter().any(|change| change.is_skipped()
            && change.change_description.contains("already up to date")),
        "this test is only meaningful on a run that writes nothing, changes: {:?}",
        result.apply_changes
    );
    assert_eq!(
        sysctl_mkdir_count(&executor),
        1,
        "the directory must be ensured before the checkpoint, not before the write, \
         commands: {:?}",
        executor.log().commands_executed
    );
}

/// The creation runs only where it is needed: an ordinary host, which ships the
/// directory, must not gain a command it does not need.
#[tokio::test]
async fn kernel_apply_issues_no_mkdir_when_the_sysctl_directory_is_there() {
    let executor = Arc::new(fully_secure_kernel_executor().with_directory(SYSCTL_DIR));
    let mut ctx = Context::with_executor(executor.clone());

    KernelHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("kernel apply should not error");

    assert_eq!(
        sysctl_mkdir_count(&executor),
        0,
        "a directory that is already there needs no creation, commands: {:?}",
        executor.log().commands_executed
    );
    assert!(
        persisted_the_config(&executor),
        "the persistent file must still be written, writes: {:?}",
        executor.log().files_written
    );
}
