//! Kernel plugin tests using MockExecutor.
//!
//! These tests verify plugin behaviour without touching the real /proc/sys filesystem.

use hardener_common::types::{PluginId, Severity};
use hardener_core::{
    ChangeType, CommandOutput, Context, FileMetadata, MockExecutor, PluginConfig, PolicyException,
    SystemExecutor, plugin::HardeningPlugin,
};
use hardener_plugins::KernelHardeningPlugin;
use std::sync::Arc;

/// Every managed parameter at its secure value, as one list.
///
/// The fixtures below are folds of this rather than hand-written copies of it,
/// because a fixture that drifts from the plugin's own parameter table stops
/// representing a host.
const SECURE_PARAMETER_VALUES: &[(&str, &str)] = &[
    ("/proc/sys/kernel/randomize_va_space", "2"),
    ("/proc/sys/kernel/kptr_restrict", "2"),
    ("/proc/sys/kernel/dmesg_restrict", "1"),
    ("/proc/sys/kernel/yama/ptrace_scope", "2"),
    ("/proc/sys/fs/suid_dumpable", "0"),
    ("/proc/sys/fs/protected_hardlinks", "1"),
    ("/proc/sys/fs/protected_symlinks", "1"),
    ("/proc/sys/net/ipv4/conf/all/rp_filter", "1"),
    ("/proc/sys/net/ipv4/conf/default/rp_filter", "1"),
    ("/proc/sys/net/ipv4/tcp_syncookies", "1"),
    ("/proc/sys/net/ipv4/conf/all/accept_source_route", "0"),
    ("/proc/sys/net/ipv4/conf/default/accept_source_route", "0"),
    ("/proc/sys/net/ipv4/conf/all/accept_redirects", "0"),
    ("/proc/sys/net/ipv4/conf/default/accept_redirects", "0"),
    ("/proc/sys/net/ipv4/conf/all/secure_redirects", "0"),
    ("/proc/sys/net/ipv4/conf/default/secure_redirects", "0"),
    ("/proc/sys/net/ipv4/conf/all/log_martians", "1"),
    ("/proc/sys/net/ipv4/conf/default/log_martians", "1"),
];

/// What [`secure_kernel_executor`] leaves out, so the omission is a decision
/// the fixture states rather than a gap in a hand-written list.
const PARTIAL_FIXTURE_OMITS: &[&str] = &[
    "/proc/sys/net/ipv4/conf/all/accept_redirects",
    "/proc/sys/net/ipv4/conf/default/accept_redirects",
    "/proc/sys/net/ipv4/conf/all/secure_redirects",
    "/proc/sys/net/ipv4/conf/default/secure_redirects",
    "/proc/sys/net/ipv4/conf/all/log_martians",
    "/proc/sys/net/ipv4/conf/default/log_martians",
];

/// A host holding every parameter in `values` at the value given.
///
/// Nearly every host ships the sysctl drop-in directory; the ones that do not
/// are covered by their own tests further down.
fn kernel_executor_holding(values: &[(&str, &str)]) -> MockExecutor {
    values.iter().fold(
        MockExecutor::new().with_directory("/etc/sysctl.d"),
        |executor, (path, value)| executor.with_file(path, value),
    )
}

/// Creates a mock executor with secure kernel parameters, omitting the redirect
/// and martian ones, which the state-aware tests below must not see here.
fn secure_kernel_executor() -> MockExecutor {
    let values: Vec<(&str, &str)> = SECURE_PARAMETER_VALUES
        .iter()
        .filter(|(path, _)| !PARTIAL_FIXTURE_OMITS.contains(path))
        .copied()
        .collect();
    kernel_executor_holding(&values)
}

/// Creates a mock executor with EVERY kernel parameter at its secure value,
/// covering the full baseline.
fn fully_secure_kernel_executor() -> MockExecutor {
    kernel_executor_holding(SECURE_PARAMETER_VALUES)
}

/// The fully secure host with one parameter's file never registered.
///
/// An unregistered path in the mock is absent and `read_file` fails for it,
/// which is what a kernel built without the parameter looks like: the Yama
/// scope is the real case, absent on any kernel without that LSM.
fn fully_secure_kernel_executor_without(path: &str) -> MockExecutor {
    fully_secure_kernel_executor().without_file(path)
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
///
/// This asserted an empty list until the preview learned to name the
/// persistent file it was about to write, which on this fixture is absent. The
/// list is therefore one line long here, and the claim narrows to the one this
/// test was always about: no PARAMETER inflates it. What that remaining line
/// is belongs to
/// `kernel_validate_previews_the_persistent_file_when_it_is_absent`.
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
    assert_eq!(
        report.validation_report_estimated_changes.len(),
        1,
        "a fully compliant host has only the persistent file pending, got: {:?}",
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
    // The drifted parameter and the persistent file the apply writes for it,
    // in that order: apply walks the parameters and writes the file afterwards,
    // and an operator comparing a dry run against the run it previews reads the
    // two lists in order.
    assert_eq!(
        report.validation_report_estimated_changes,
        vec![
            "kernel.kptr_restrict will change: 0 -> 2".to_string(),
            CREATE_PERSISTENT_CONFIG.to_string(),
        ],
        "only the drifted parameter and the persistent file are pending"
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
    // This test used to assert the defect. Its own comment explained the
    // mechanism and then called the result correct: a missing file returns
    // Ok(exists: false, mode: 0), the zero mode has no write bit, so every
    // absent parameter was reported "is read-only" at High and failed the dry
    // run. The message was wrong, the severity was wrong, and the test was
    // pinning both, which is why the swap survived. A test that encodes a defect
    // as an expectation is the reason nobody finds it.
    let executor = MockExecutor::new(); // Empty - no params
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = KernelHardeningPlugin::new();
    let config = PluginConfig::default();

    let result = plugin.validate(&ctx, &config).await.unwrap();

    assert!(
        !result.validation_report_issues.is_empty(),
        "a kernel carrying none of the managed parameters has something to say"
    );
    // Absence is a fact about the host, not a blocker: apply cannot set a
    // parameter this kernel does not have, and there is nothing for an operator
    // to fix, so the preview says so and still runs.
    assert!(
        result.validation_report_is_valid,
        "an absent parameter is not a reason to refuse the dry run, got: {:?}",
        result.validation_report_issues
    );
    for issue in &result.validation_report_issues {
        assert_eq!(issue.validation_issue_severity, Severity::Low);
        assert!(
            issue.validation_issue_message.contains("does not exist"),
            "an absent parameter must be described as absent, got: {}",
            issue.validation_issue_message
        );
        assert!(
            !issue.validation_issue_message.contains("read-only"),
            "a parameter this kernel does not carry is not a read-only one: {}",
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

// =============================================================================
// The preview must name the persistent file the apply is about to write
// =============================================================================

/// The sentence the preview uses for the persistent file. Apply prints
/// `"Created persistent sysctl config"`; this is that same sentence in the
/// tense a preview uses, which is what 420a52b established for the firewall's
/// boot line and what lets the two halves be read against each other.
const CREATE_PERSISTENT_CONFIG: &str = "Create persistent sysctl config";

/// The subject both halves name, spelled the way each of them spells it.
const PERSISTENT_CONFIG_SUBJECT: &str = "persistent sysctl config";

/// What a change line names, which is everything after its leading verb.
///
/// Returns `None` rather than an empty string when there is no verb to strip,
/// so a rewording on either side surfaces as a missing subject instead of as
/// two silences that happen to compare equal.
fn change_subject(line: &str) -> Option<&str> {
    line.split_once(' ').map(|(_verb, subject)| subject)
}

/// The content the apply writes to the persistent file, taken from the run
/// itself.
///
/// Spelling that content out here would be a second copy of the builder under
/// test, and a preview's job is to predict what the apply writes rather than
/// what a test says it writes. The executor is left holding the file, so a
/// `validate` on the same one afterwards sees the host a second apply would.
async fn config_the_apply_writes(executor: &Arc<MockExecutor>, config: &PluginConfig) -> String {
    let mut ctx = Context::with_executor(executor.clone());
    KernelHardeningPlugin::new()
        .apply(&mut ctx, config)
        .await
        .expect("kernel apply should not error");
    executor
        .log()
        .files_written
        .iter()
        .find(|(path, _)| path.to_str() == Some(HARDENER_CONF))
        .map(|(_, content)| content.clone())
        .expect("apply must persist the settings it manages")
}

/// The defect the container run of 2026-07-31 found on rhel, and on rhel alone
/// because it is the only fixture where every parameter arrives compliant.
/// `validate` had nothing per-parameter to report and returned an empty
/// preview; the apply then created /etc/sysctl.d/99-hardener.conf and reported
/// one applied change. The operator approved a preview shorter than the run.
#[tokio::test]
async fn kernel_validate_previews_the_persistent_file_when_it_is_absent() {
    let ctx = Context::with_executor(Arc::new(fully_secure_kernel_executor()));

    let report = KernelHardeningPlugin::new()
        .validate(&ctx, &PluginConfig::default())
        .await
        .expect("kernel validate should not error");

    assert_eq!(
        report.validation_report_estimated_changes,
        vec![CREATE_PERSISTENT_CONFIG.to_string()],
        "every parameter on this host is compliant and the persistent file is \
         absent, so the file is the whole of what the apply will do, and a \
         preview silent about it is shorter than the run it previews"
    );
}

/// The opposite defect, and just as wrong: a preview that claims a pending
/// write on every host. The file is seeded by running the apply, so what it
/// holds is what the run itself writes.
///
/// This passed against the unfixed plugin, which named the file on no host at
/// all, so it is a guard rather than evidence of a live defect and was proved
/// by mutation: pushing the line unconditionally fails exactly this test and
/// the stricter-host one below.
#[tokio::test]
async fn kernel_validate_previews_nothing_when_the_persistent_file_already_matches() {
    let executor = Arc::new(fully_secure_kernel_executor());
    let config = PluginConfig::default();
    let written = config_the_apply_writes(&executor, &config).await;
    assert!(
        written.contains("kernel.kptr_restrict = 2"),
        "the seed must be the settings file the apply writes, got:\n{written}"
    );

    let ctx = Context::with_executor(executor.clone());
    let report = KernelHardeningPlugin::new()
        .validate(&ctx, &config)
        .await
        .expect("kernel validate should not error");

    assert!(
        report.validation_report_estimated_changes.is_empty(),
        "the file on this host is already exactly what the run would write, and \
         apply reports that as a skipped no-op, so a preview naming it queues a \
         write that will not happen, got: {:?}",
        report.validation_report_estimated_changes
    );
}

/// The file is present but holds something else, which is the arm of apply's
/// condition that fires on content rather than on a runtime change.
#[tokio::test]
async fn kernel_validate_previews_the_persistent_file_when_its_content_differs() {
    let executor = fully_secure_kernel_executor().with_file(
        HARDENER_CONF,
        "# left by an older release of this tool\nkernel.kptr_restrict = 1\n",
    );
    let ctx = Context::with_executor(Arc::new(executor));

    let report = KernelHardeningPlugin::new()
        .validate(&ctx, &PluginConfig::default())
        .await
        .expect("kernel validate should not error");

    assert_eq!(
        report.validation_report_estimated_changes,
        vec![CREATE_PERSISTENT_CONFIG.to_string()],
        "a file whose content differs from what this run would write is rewritten \
         by the apply, so the preview must name it"
    );
}

/// The preview predicts the file's content, and the content is written with the
/// host's own value wherever that is stricter than the baseline. A preview that
/// predicted the unclamped baseline would compute different content on exactly
/// this host and report a pending write that never arrives.
///
/// This is the assertion that proves the clamp is shared with the apply rather
/// than spelled a second time in the preview, and like the test above it
/// passed against the unfixed plugin and was proved by mutation. Re-spelling
/// the target in `validate` alone, without the clamp, fails exactly this test
/// and nothing else in the file.
#[tokio::test]
async fn kernel_validate_predicts_the_stricter_value_a_stricter_host_keeps() {
    let config = PluginConfig::default();
    let hardened = Arc::new(stricter_than_baseline_kernel_executor());
    let written = config_the_apply_writes(&hardened, &config).await;
    assert!(
        written.contains("kernel.yama.ptrace_scope = 3"),
        "the fixture must be the stricter host, whose persistent file keeps its \
         own value rather than the baseline's, got:\n{written}"
    );

    // The same host, already carrying exactly the file the apply writes for it.
    let ctx = Context::with_executor(Arc::new(
        stricter_than_baseline_kernel_executor().with_file(HARDENER_CONF, &written),
    ));
    let report = KernelHardeningPlugin::new()
        .validate(&ctx, &config)
        .await
        .expect("kernel validate should not error");

    assert!(
        report.validation_report_estimated_changes.is_empty(),
        "the preview computed content the apply would not write: this host keeps \
         ptrace_scope 3 and tcp_syncookies 2, so a preview predicting the \
         baseline's 2 and 1 reports a rewrite that never happens, got: {:?}",
        report.validation_report_estimated_changes
    );
}

/// Both halves against ONE host, which is the shape b981ef2 established: two
/// fixtures would prove that two similar hosts agree rather than that one host
/// is described consistently by the dry run and by the apply.
///
/// The preview is taken first for the reason the differential suite takes its
/// dry run first: afterwards the apply has written the file and the preview
/// would agree with a host the run had already changed.
#[tokio::test]
async fn kernel_preview_and_apply_agree_the_persistent_file_is_pending() {
    let executor = Arc::new(fully_secure_kernel_executor());
    let config = PluginConfig::default();

    let previewed = KernelHardeningPlugin::new()
        .validate(&Context::with_executor(executor.clone()), &config)
        .await
        .expect("kernel validate should not error");
    let mut apply_ctx = Context::with_executor(executor.clone());
    let applied = KernelHardeningPlugin::new()
        .apply(&mut apply_ctx, &config)
        .await
        .expect("kernel apply should not error");

    assert_eq!(
        applied.applied_change_count(),
        1,
        "this is rhel's shape and the apply must have something to do on it, or \
         the comparison below holds two silences against each other, changes: {:?}",
        applied.apply_changes
    );

    // Found by its type rather than by its wording, so this is not looking for
    // the string it is about to assert.
    let apply_line = applied
        .apply_changes
        .iter()
        .find(|change| change.change_type == ChangeType::ConfigFile && change.change_success)
        .map(|change| change.change_description.as_str())
        .expect("apply must record the persistent file it wrote");
    let [preview_line] = previewed.validation_report_estimated_changes.as_slice() else {
        panic!(
            "the preview must name exactly the one change this apply makes, got: {:?}",
            previewed.validation_report_estimated_changes
        )
    };

    let apply_subject = change_subject(apply_line).expect("apply's change must name a subject");
    let preview_subject =
        change_subject(preview_line).expect("the preview's line must name a subject");
    assert_eq!(
        apply_subject, preview_subject,
        "the preview and the run must name the same change the same way, or an \
         operator reading the dry run cannot match it to what the apply reports.\n  \
         apply:    {apply_line}\n  preview:  {preview_line}"
    );
    // Without this the assertion above passes on two subjects that are both
    // wrong in the same way, which a reword moving both halves together would
    // produce.
    assert_eq!(
        apply_subject, PERSISTENT_CONFIG_SUBJECT,
        "both sides must name the persistent sysctl config, got: {apply_line}"
    );
}

/// The builder's other arm, on the same host both halves would see. An excepted
/// parameter is written into the persistent file as a comment rather than as a
/// setting, so a preview omitting that block computes content the file can
/// never match and reports a rewrite on every run for as long as the exception
/// stands.
///
/// Reached by none of the tests above, all of which use hosts with no
/// exception, and this is the arm most easily lost: moving validate's
/// `push_config_section` call past the excepted arm leaves all of them green.
#[tokio::test]
async fn kernel_validate_predicts_the_block_an_excepted_parameter_gets() {
    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "kernel.yama.ptrace_scope".to_string(),
        PolicyException {
            value: "1".to_string(),
            allowed: true,
            reason: "Debugger required on this build host".to_string(),
            approved_by: None,
            approved_date: None,
            ticket: None,
            expires: None,
        },
    );
    let executor = Arc::new(
        fully_secure_kernel_executor().with_file("/proc/sys/kernel/yama/ptrace_scope", "1"),
    );

    let written = config_the_apply_writes(&executor, &config).await;
    assert!(
        written.contains("# kernel.yama.ptrace_scope: SKIPPED"),
        "the file must record the excepted parameter as skipped rather than \
         re-impose the baseline on it at the next boot, got:\n{written}"
    );

    let ctx = Context::with_executor(executor.clone());
    let report = KernelHardeningPlugin::new()
        .validate(&ctx, &config)
        .await
        .expect("kernel validate should not error");

    assert!(
        report.validation_report_estimated_changes.is_empty(),
        "the file on this host is already exactly what the run would write, so a \
         preview naming it queues a rewrite that will never stop being pending, \
         got: {:?}",
        report.validation_report_estimated_changes
    );
}

// =============================================================================
// Whether the values this plugin writes survive the next boot
// =============================================================================

/// ufw's enablement flag. `ufw-init-functions` sources this file and
/// `ufw_start` applies the sysctl file only inside `[ "$ENABLED" = "yes" ]`
/// (ufw 0.36.2, `/usr/lib/ufw/ufw-init-functions:111` and `:387`).
const UFW_CONF: &str = "/etc/ufw/ufw.conf";
/// Where ufw names the sysctl file it applies, in `IPT_SYSCTL`.
const UFW_DEFAULTS: &str = "/etc/default/ufw";
/// The file ufw ships there. Read on the arch host 2026-07-31: it spells its
/// keys as procfs paths, `net/ipv4/conf/all/log_martians=0`, where this tool
/// and `sysctl.d` spell them `net.ipv4.conf.all.log_martians = 1`.
const UFW_SYSCTL: &str = "/etc/ufw/sysctl.conf";

/// The body ufw ships on arch and debian, trimmed to the lines that touch a
/// managed parameter. `log_martians` is the reported defect; the rp_filter and
/// accept_source_route lines are at or stricter than this tool's targets and
/// are the six false findings a direction-blind comparison would emit.
const UFW_SHIPPED_SYSCTL: &str = "\
# ufw's own comment\n\
net/ipv4/conf/default/rp_filter=1\n\
net/ipv4/conf/all/rp_filter=1\n\
net/ipv4/conf/default/accept_source_route=0\n\
net/ipv4/conf/all/accept_source_route=0\n\
net/ipv4/conf/default/log_martians=0\n\
net/ipv4/conf/all/log_martians=0\n";

/// A host whose ufw is enabled and whose `IPT_SYSCTL` names `body`.
fn ufw_enabled(executor: MockExecutor, body: &str) -> MockExecutor {
    executor
        .with_file(UFW_CONF, "# /etc/ufw/ufw.conf\nENABLED=yes\nLOGLEVEL=low\n")
        .with_file(
            UFW_DEFAULTS,
            "IPV6=yes\nIPT_SYSCTL=/etc/ufw/sysctl.conf\nIPT_MODULES=\"\"\n",
        )
        .with_file(UFW_SYSCTL, body)
}

/// The findings that say a managed parameter will not survive the next boot,
/// picked out by their id prefix rather than by their wording.
fn boot_findings(
    result: &hardener_core::plugin::ScanResult,
) -> Vec<&hardener_core::plugin::Finding> {
    result
        .scan_findings
        .iter()
        .filter(|f| f.finding_id.starts_with("kernel_boot_override_"))
        .collect()
}

/// A one-line summary of each boot finding, for assertion messages.
fn boot_summary(result: &hardener_core::plugin::ScanResult) -> Vec<String> {
    boot_findings(result)
        .iter()
        .map(|f| format!("{}: {}", f.finding_id, f.finding_title))
        .collect()
}

async fn scan_host(executor: MockExecutor) -> hardener_core::plugin::ScanResult {
    KernelHardeningPlugin::new()
        .scan(
            &Context::with_executor(Arc::new(executor)),
            &PluginConfig::default(),
        )
        .await
        .expect("kernel scan should not error")
}

/// The reported defect. Measured on the debian container 2026-07-31:
/// `/etc/sysctl.d/99-hardener.conf` holds `log_martians = 1` and the running
/// kernel reads 0, because `ufw.service` is `After=systemd-sysctl.service` and
/// its start applies `/etc/ufw/sysctl.conf` over everything `sysctl.d` set.
#[tokio::test]
async fn a_ufw_sysctl_file_that_loosens_a_managed_parameter_is_reported() {
    let result = scan_host(ufw_enabled(
        fully_secure_kernel_executor(),
        UFW_SHIPPED_SYSCTL,
    ))
    .await;

    let findings = boot_findings(&result);
    assert_eq!(
        findings.len(),
        2,
        "both log_martians parameters are undone at the next boot and neither \
         of the four rp_filter/accept_source_route lines is looser, got: {:?}",
        boot_summary(&result)
    );

    let all = findings
        .iter()
        .find(|f| f.finding_id.ends_with("net_ipv4_conf_all_log_martians"))
        .unwrap_or_else(|| {
            panic!(
                "the all-interfaces parameter must be named, got: {:?}",
                boot_summary(&result)
            )
        });
    let named = format!(
        "{} {} {:?}",
        all.finding_title, all.finding_explanation, all.finding_remediation_steps
    );
    assert!(
        named.contains(UFW_SYSCTL),
        "the finding must name the file that undoes the setting, got: {named}"
    );
    assert!(
        named.contains("net.ipv4.conf.all.log_martians"),
        "the finding must name the parameter, got: {named}"
    );
    assert_eq!(
        all.finding_current_value, "0",
        "the finding must carry the value that file sets"
    );
    assert_eq!(
        all.finding_recommended_value, "1",
        "the finding must carry the target it undercuts"
    );
}

/// The six-false-findings guard, twice over.
///
/// The first six lines are what ufw really ships for parameters this tool
/// manages: two `rp_filter`, two ipv4 `accept_source_route` and two
/// `accept_redirects`, every one of them at exactly this tool's target. A check
/// that reported a managed parameter merely for APPEARING in ufw's file emits
/// all six on every arch and debian host.
///
/// The seventh line ships in no ufw file and is here deliberately: because
/// those six are exactly equal to their targets, they cannot tell a
/// direction-aware comparison from an equality one. `ptrace_scope = 3` forbids
/// ptrace outright and is stricter than the target of 2, so only a comparison
/// that knows which way strictness runs leaves it alone.
#[tokio::test]
async fn ufw_values_at_or_stricter_than_the_target_are_not_reported() {
    let body = "\
net/ipv4/conf/default/rp_filter=1\n\
net/ipv4/conf/all/rp_filter=1\n\
net/ipv4/conf/default/accept_source_route=0\n\
net/ipv4/conf/all/accept_source_route=0\n\
net/ipv4/conf/all/accept_redirects=0\n\
net/ipv4/conf/default/accept_redirects=0\n\
kernel/yama/ptrace_scope=3\n";
    let result = scan_host(ufw_enabled(fully_secure_kernel_executor(), body)).await;

    assert!(
        boot_findings(&result).is_empty(),
        "a file agreeing with this tool, or stricter than it, undoes nothing, \
         got: {:?}",
        boot_summary(&result)
    );
}

/// The Debian 13 guard, and the single most important test here. Debian 13
/// ships `/usr/lib/sysctl.d/50-default.conf` from `linux-sysctl-defaults`
/// setting `rp_filter = 2`, which is LOOSER than this tool's target of 1
/// (`0, 2, 1` weakest first). systemd-sysctl sorts drop-ins by filename and the
/// lexicographically last name wins (`sysctl.d(5)`, CONFIGURATION DIRECTORIES
/// AND PRECEDENCE), so `99-hardener.conf` beats `50-default.conf` and there is
/// nothing to report.
#[tokio::test]
async fn a_dropin_sorting_before_the_hardener_file_is_not_reported() {
    let executor = fully_secure_kernel_executor().with_file(
        "/usr/lib/sysctl.d/50-default.conf",
        "kernel.sysrq = 16\nnet.ipv4.conf.default.rp_filter = 2\nnet.ipv4.conf.all.rp_filter = 2\n",
    );
    let result = scan_host(executor).await;

    assert!(
        boot_findings(&result).is_empty(),
        "99-hardener.conf sorts after 50-default.conf and therefore wins, so \
         reporting this would be a false finding on every Debian 13 host, got: \
         {:?}",
        boot_summary(&result)
    );
}

/// The other half of the pair above: without this, a reader that never looked
/// at a drop-in at all would satisfy the Debian 13 guard, and the two only mean
/// something together.
#[tokio::test]
async fn a_dropin_sorting_after_the_hardener_file_is_reported() {
    let executor = fully_secure_kernel_executor().with_file(
        "/etc/sysctl.d/zz-local-overrides.conf",
        "net.ipv4.conf.all.rp_filter = 2\n",
    );
    let result = scan_host(executor).await;

    let findings = boot_findings(&result);
    let [finding] = findings.as_slice() else {
        panic!(
            "a drop-in sorting after 99-hardener.conf decides the value the host \
             runs, got: {:?}",
            boot_summary(&result)
        )
    };
    let named = format!(
        "{} {} {:?}",
        finding.finding_title, finding.finding_explanation, finding.finding_remediation_steps
    );
    assert!(
        named.contains("/etc/sysctl.d/zz-local-overrides.conf"),
        "the finding must name the file, got: {named}"
    );
    assert_eq!(finding.finding_current_value, "2");
    assert_eq!(finding.finding_recommended_value, "1");
}

/// Nothing applies the file when ufw does not name one.
#[tokio::test]
async fn a_commented_out_ipt_sysctl_is_not_reported() {
    let executor = fully_secure_kernel_executor()
        .with_file(UFW_CONF, "ENABLED=yes\n")
        .with_file(UFW_DEFAULTS, "IPV6=yes\n#IPT_SYSCTL=/etc/ufw/sysctl.conf\n")
        .with_file(UFW_SYSCTL, UFW_SHIPPED_SYSCTL);
    let result = scan_host(executor).await;

    assert!(
        boot_findings(&result).is_empty(),
        "ufw applies IPT_SYSCTL only when it is set, so a commented-out line \
         undoes nothing, got: {:?}",
        boot_summary(&result)
    );
}

/// Measured on the arch host 2026-07-31: ufw is installed, `IPT_SYSCTL` is
/// active and `/etc/ufw/sysctl.conf` sets `log_martians=0`, yet
/// `/etc/ufw/ufw.conf` says `ENABLED=no` and `ufw_start` skips everything
/// inside its enablement test. A check that ignored that flag would emit a
/// false finding on every host with ufw merely installed.
#[tokio::test]
async fn a_disabled_ufw_is_not_reported() {
    let executor = fully_secure_kernel_executor()
        .with_file(UFW_CONF, "ENABLED=no\nLOGLEVEL=low\n")
        .with_file(UFW_DEFAULTS, "IPT_SYSCTL=/etc/ufw/sysctl.conf\n")
        .with_file(UFW_SYSCTL, UFW_SHIPPED_SYSCTL);
    let result = scan_host(executor).await;

    assert!(
        boot_findings(&result).is_empty(),
        "ufw that is not enabled never runs its start script, so its sysctl \
         file is never applied, got: {:?}",
        boot_summary(&result)
    );
}

/// A file that cannot be read is not a silence.
#[tokio::test]
async fn an_unreadable_ufw_defaults_file_is_unchecked_rather_than_a_pass() {
    let executor = fully_secure_kernel_executor()
        .with_file(UFW_CONF, "ENABLED=yes\n")
        .with_read_permission_denied(UFW_DEFAULTS);
    let result = scan_host(executor).await;

    assert!(
        boot_findings(&result).is_empty(),
        "nothing was read, so nothing can be asserted about a parameter"
    );
    let [unchecked] = result.scan_unchecked.as_slice() else {
        panic!(
            "a file this scan could not read must be reported as unchecked, got: {:?}",
            result.scan_unchecked
        )
    };
    assert!(
        unchecked.unchecked_reason.contains(UFW_DEFAULTS),
        "the unchecked entry must name the file, got: {}",
        unchecked.unchecked_reason
    );
    assert!(
        unchecked.unchecked_needs_privilege,
        "a read refused for permission is exactly what a privileged run would fix"
    );
    assert!(
        !unchecked.unchecked_compliance.is_empty(),
        "an unanswerable question must stop its controls auto-passing"
    );
}

/// The same for the file `IPT_SYSCTL` names.
#[tokio::test]
async fn an_unreadable_ipt_sysctl_target_is_unchecked_rather_than_a_pass() {
    let executor = ufw_enabled(fully_secure_kernel_executor(), UFW_SHIPPED_SYSCTL)
        .with_read_permission_denied(UFW_SYSCTL);
    let result = scan_host(executor).await;

    assert!(
        boot_findings(&result).is_empty(),
        "the file was never read, so no value can be held against a target"
    );
    assert!(
        result
            .scan_unchecked
            .iter()
            .any(|u| u.unchecked_reason.contains(UFW_SYSCTL)),
        "the file ufw would apply could not be read and must be reported as \
         unchecked, got: {:?}",
        result.scan_unchecked
    );
}

/// This is report-only work: the scan says so and the apply does nothing new
/// about it. Asserted against the same apply on a host without any of it,
/// rather than assumed.
#[tokio::test]
async fn the_apply_writes_nothing_new_for_a_parameter_another_package_overrides() {
    let plain = Arc::new(fully_secure_kernel_executor());
    let overridden = Arc::new(
        ufw_enabled(fully_secure_kernel_executor(), UFW_SHIPPED_SYSCTL).with_file(
            "/etc/sysctl.d/zz-local-overrides.conf",
            "net.ipv4.conf.all.rp_filter = 2\n",
        ),
    );

    let mut plain_ctx = Context::with_executor(plain.clone());
    let plain_apply = KernelHardeningPlugin::new()
        .apply(&mut plain_ctx, &PluginConfig::default())
        .await
        .expect("kernel apply should not error");
    let mut overridden_ctx = Context::with_executor(overridden.clone());
    let overridden_apply = KernelHardeningPlugin::new()
        .apply(&mut overridden_ctx, &PluginConfig::default())
        .await
        .expect("kernel apply should not error");

    let descriptions = |result: &hardener_core::plugin::ApplyResult| -> Vec<String> {
        result
            .apply_changes
            .iter()
            .map(|c| c.change_description.clone())
            .collect()
    };
    assert_eq!(
        descriptions(&overridden_apply),
        descriptions(&plain_apply),
        "the apply must not grow a change for something it has decided not to fix"
    );

    let written = |executor: &MockExecutor| -> Vec<String> {
        executor
            .log()
            .files_written
            .iter()
            .map(|(path, _)| path.to_string_lossy().into_owned())
            .collect()
    };
    assert_eq!(
        written(&overridden),
        written(&plain),
        "this tool does not edit another package's configuration file, so the \
         apply writes exactly what it always wrote"
    );
    // Named, not just compared. A write this apply performs on every host
    // would grow both lists together and the comparison above would not see it.
    assert!(
        written(&overridden)
            .iter()
            .all(|path| path == HARDENER_CONF || path.starts_with("/proc/sys/")),
        "the only files this plugin writes are its own drop-in and /proc/sys, \
         got: {:?}",
        written(&overridden)
    );
}

/// A drop-in that assigns through a glob pattern is not resolved here, and a
/// pattern this reader walked past in silence would read exactly like a file
/// that agrees with the tool.
#[tokio::test]
async fn a_later_dropin_using_glob_patterns_is_unchecked_rather_than_a_pass() {
    let executor = fully_secure_kernel_executor().with_file(
        "/etc/sysctl.d/zz-patterns.conf",
        "net.ipv4.conf.*.rp_filter = 2\n",
    );
    let result = scan_host(executor).await;

    assert!(
        boot_findings(&result).is_empty(),
        "no pattern was resolved, so no value can be held against a target"
    );
    assert!(
        result.scan_unchecked.iter().any(|u| u
            .unchecked_reason
            .contains("/etc/sysctl.d/zz-patterns.conf")),
        "a file this scan could not fully read must be reported as unchecked, \
         got: {:?}",
        result.scan_unchecked
    );
}

/// ufw runs from a unit ordered after systemd-sysctl, so it lands after every
/// drop-in whatever those are called. A parameter a late drop-in loosens and
/// ufw then sets back is a value the host never runs, and reporting it would be
/// a finding about a state that does not exist.
#[tokio::test]
async fn the_last_writer_decides_and_ufw_writes_after_every_dropin() {
    let executor = ufw_enabled(
        fully_secure_kernel_executor(),
        "net/ipv4/conf/all/rp_filter=1\n",
    )
    .with_file(
        "/etc/sysctl.d/zz-local-overrides.conf",
        "net.ipv4.conf.all.rp_filter = 2\n",
    );
    let result = scan_host(executor).await;

    assert!(
        boot_findings(&result).is_empty(),
        "ufw applies its file after every sysctl.d drop-in, so the value the \
         host runs is ufw's, got: {:?}",
        boot_summary(&result)
    );
}

/// The dry run said the opposite of the truth in both directions.
///
/// `file_metadata` reports a positively confirmed absence as
/// `Ok(exists: false, mode: 0)` and reserves `Err` for "could not determine",
/// and its trait contract says callers must never read `Err` as absence. Kernel
/// validate did exactly that: the `Err` arm announced "does not exist on this
/// kernel" at Low, while a real absence, whose zero mode carries no write bit,
/// fell into the read-only arm and was announced "is read-only" at High, which
/// blocks the dry run.
///
/// So the parameter that was missing blocked the run under the wrong reason, and
/// the parameter nobody could read passed it under the other wrong reason. Both
/// directions are asserted, because a fix that merely reworded one arm would
/// leave the other saying something it never established.
#[tokio::test]
async fn an_absent_parameter_is_reported_absent_rather_than_read_only() {
    const YAMA: &str = "/proc/sys/kernel/yama/ptrace_scope";
    let executor = fully_secure_kernel_executor_without(YAMA);
    let ctx = Context::with_executor(Arc::new(executor) as Arc<dyn SystemExecutor>);

    let report = KernelHardeningPlugin::new()
        .validate(&ctx, &PluginConfig::default())
        .await
        .expect("kernel validate should not error");

    let issue = report
        .validation_report_issues
        .iter()
        .find(|i| i.validation_issue_config_key.as_deref() == Some("kernel.yama.ptrace_scope"))
        .unwrap_or_else(|| {
            panic!(
                "an absent parameter must be reported, got: {:?}",
                report.validation_report_issues
            )
        });
    assert!(
        !issue.validation_issue_message.contains("read-only"),
        "a parameter this kernel does not carry is not a read-only one: {}",
        issue.validation_issue_message
    );
    assert!(
        issue.validation_issue_message.contains("does not exist"),
        "the message must say what was actually established: {}",
        issue.validation_issue_message
    );
}

/// The other direction: a parameter whose metadata could not be read must not be
/// announced as absent, and must fail the dry run rather than passing it.
#[tokio::test]
async fn an_unreadable_parameter_is_not_reported_as_absent() {
    const ASLR: &str = "/proc/sys/kernel/randomize_va_space";
    let executor = fully_secure_kernel_executor().with_metadata_error(ASLR);
    let ctx = Context::with_executor(Arc::new(executor) as Arc<dyn SystemExecutor>);

    let report = KernelHardeningPlugin::new()
        .validate(&ctx, &PluginConfig::default())
        .await
        .expect("kernel validate should not error");

    let issue = report
        .validation_report_issues
        .iter()
        .find(|i| i.validation_issue_config_key.as_deref() == Some("kernel.randomize_va_space"))
        .unwrap_or_else(|| {
            panic!(
                "a parameter the run could not examine must be reported, got: {:?}",
                report.validation_report_issues
            )
        });
    assert!(
        !issue.validation_issue_message.contains("does not exist"),
        "the probe failed; absence was never established: {}",
        issue.validation_issue_message
    );
    assert_eq!(
        issue.validation_issue_severity,
        Severity::High,
        "a preview that could not examine a managed parameter must not read as clean"
    );
}

/// A parameter this scan could not read is not a parameter it found compliant.
///
/// The scan judged the value it read and said nothing at all when the read
/// failed, so the parameter left no finding and no unchecked entry. That is not
/// silence in a log: `coverage()` declares all eighteen parameters assessed, and
/// `ReportGenerator` passes an assessed control on the mere absence of a
/// finding, so an unreadable ASLR setting rendered CIS 1.5.1 as a Pass with no
/// value ever read. The generator's own comment states the invariant this
/// breaks: only a control the engine both assesses and could evaluate this run
/// may pass on an absent finding.
///
/// Both flavours are asserted because the site's comment claimed only one of
/// them. A refused read is a parameter that is there, and a privileged run would
/// reach it; an absent file is a kernel that does not carry the parameter, which
/// no privilege fixes. They must both be unchecked, and they must disagree about
/// whether privilege would help, or the entry is repeating a hardcoded literal
/// rather than reporting what the probe saw.
#[tokio::test]
async fn a_parameter_that_could_not_be_read_is_unchecked_rather_than_a_pass() {
    const ASLR: &str = "/proc/sys/kernel/randomize_va_space";

    for (label, executor, privilege_helps) in [
        (
            "refused for permission",
            fully_secure_kernel_executor().with_read_permission_denied(ASLR),
            true,
        ),
        (
            "absent from this kernel",
            fully_secure_kernel_executor_without(ASLR),
            false,
        ),
    ] {
        let result = scan_host(executor).await;

        let entry = result
            .scan_unchecked
            .iter()
            .find(|unchecked| unchecked.unchecked_reason.contains(ASLR))
            .unwrap_or_else(|| {
                panic!(
                    "a parameter {label} must be reported unchecked, got: {:?}",
                    result.scan_unchecked
                )
            });

        assert!(
            entry
                .unchecked_compliance
                .iter()
                .any(|mapping| mapping.compliance_control_id == "1.5.1"),
            "the entry must carry the parameter's own compliance mappings, or \
             the report still auto-passes the control it covers ({label}), got: {:?}",
            entry.unchecked_compliance
        );
        assert_eq!(
            entry.unchecked_needs_privilege, privilege_helps,
            "whether a privileged re-run would reach this must come from the \
             failure the probe saw ({label})"
        );
        assert!(
            !result
                .scan_findings
                .iter()
                .any(|finding| finding.finding_id == "kernel_kernel_randomize_va_space"),
            "a value that was never read cannot be judged against a target ({label})"
        );
    }
}
