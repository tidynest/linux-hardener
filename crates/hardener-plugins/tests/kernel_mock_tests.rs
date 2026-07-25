//! Kernel plugin tests using MockExecutor.
//!
//! These tests verify plugin behaviour without touching the real /proc/sys filesystem.

use hardener_common::types::{PluginId, Severity};
use hardener_core::{
    Context, FileMetadata, MockExecutor, PluginConfig, PolicyException, SystemExecutor,
    plugin::HardeningPlugin,
};
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
