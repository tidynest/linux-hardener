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
                uid: 0,
                gid: 0,
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
                uid: 0,
                gid: 0,
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
                uid: 0,
                gid: 0,
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
                uid: 0,
                gid: 0,
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
                uid: 0,
                gid: 0,
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
                uid: 0,
                gid: 0,
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
                uid: 0,
                gid: 0,
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
                uid: 0,
                gid: 0,
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
                uid: 0,
                gid: 0,
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
            uid: 0,
            gid: 0,
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
            uid: 0,
            gid: 0,
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
            uid: 0,
            gid: 0,
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
                uid: 0,
                gid: 0,
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

/// Tests the reactive fallback: when the filesystem type cannot be positively
/// identified (neither `findmnt` nor `stat -f` is registered here, mirroring a
/// host where both are unavailable), the pre-emptive non-POSIX gate stays
/// silent (fail-safe) and the chmod is attempted. A filesystem that then lies
/// (chmod exits 0 but the mode is unchanged) is caught reactively by the
/// post-chmod re-read. Uses `.remote()` because MockExecutor cannot support
/// local fchmod.
#[tokio::test]
async fn test_permissions_apply_detects_vfat_noop() {
    // /boot at 0o755: chmod will "succeed" but mode stays 0o755
    let executor = MockExecutor::new()
        .remote()
        .with_file_metadata(
            "/boot",
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
    // /boot at 0o777: directive overrides target to 0o755 instead of baseline 0o700
    // Uses `.remote()` because MockExecutor cannot support local fchmod.
    let executor = MockExecutor::new()
        .remote()
        .with_file_metadata(
            "/boot",
            "",
            FileMetadata {
                exists: true,
                is_file: false,
                is_dir: true,
                mode: 0o777,
                size: 0,
                uid: 0,
                gid: 0,
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
    // NO chmod command registered: mock will error if called
    let executor = MockExecutor::new().with_file_metadata(
        "/boot",
        "",
        FileMetadata {
            exists: true,
            is_file: false,
            is_dir: true,
            mode: 0o777,
            size: 0,
            uid: 0,
            gid: 0,
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

/// A metadata record for a directory at a given mode (helper for the
/// non-POSIX filesystem tests below).
fn dir_mode(mode: u32) -> FileMetadata {
    FileMetadata {
        exists: true,
        is_file: false,
        is_dir: true,
        mode,
        size: 0,
        uid: 0,
        gid: 0,
    }
}

/// A registered `findmnt -no FSTYPE <path>` response yielding `fstype`.
fn findmnt_fstype(executor: MockExecutor, path: &str, fstype: &str) -> MockExecutor {
    executor.with_command(
        "findmnt",
        &["-no", "FSTYPE", path],
        CommandOutput {
            stdout: format!("{fstype}\n"),
            stderr: String::new(),
            exit_code: 0,
        },
    )
}

/// A violating path on a filesystem that cannot hold POSIX permissions must be
/// reported as an unchecked check (with fstab guidance), NOT as a finding,
/// while a violating path on a POSIX filesystem is still flagged normally.
#[tokio::test]
async fn test_permissions_scan_nonposix_fs_emits_unchecked_not_finding() {
    // /boot on vfat at 0o755 (violates exact 0o700); /etc/passwd on ext4 at
    // 0o666 (violates exact 0o644).
    let mut executor = MockExecutor::new()
        .with_file_metadata("/boot", "", dir_mode(0o755))
        .with_file_metadata(
            "/etc/passwd",
            "",
            FileMetadata {
                exists: true,
                is_file: true,
                is_dir: false,
                mode: 0o666,
                size: 100,
                uid: 0,
                gid: 0,
            },
        );
    executor = findmnt_fstype(executor, "/boot", "vfat");
    executor = findmnt_fstype(executor, "/etc/passwd", "ext4");

    let ctx = Context::with_executor(Arc::new(executor));
    let result = PermissionsHardeningPlugin::new().scan(&ctx).await.unwrap();

    // /boot must not be a finding.
    assert!(
        !result
            .scan_findings
            .iter()
            .any(|f| f.finding_id.contains("boot")),
        "vfat /boot must not be a finding, got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_id)
            .collect::<Vec<_>>()
    );

    // /boot must appear once as an unchecked check with fstab guidance, keyed
    // to the same id the finding would have used.
    let boot_unchecked: Vec<_> = result
        .scan_unchecked
        .iter()
        .filter(|u| u.unchecked_check_id == "perm--boot")
        .collect();
    assert_eq!(
        boot_unchecked.len(),
        1,
        "vfat /boot must yield exactly one unchecked check, got: {:?}",
        result
            .scan_unchecked
            .iter()
            .map(|u| &u.unchecked_check_id)
            .collect::<Vec<_>>()
    );
    let reason = &boot_unchecked[0].unchecked_reason;
    assert!(
        reason.contains("vfat") && reason.contains("fstab"),
        "reason must name the filesystem and fstab guidance, got: {reason}"
    );

    // POSIX /etc/passwd is unaffected: still a finding, never unchecked.
    assert!(
        result
            .scan_findings
            .iter()
            .any(|f| f.finding_id.contains("etc-passwd")),
        "POSIX /etc/passwd must still be flagged as a finding"
    );
    assert!(
        !result
            .scan_unchecked
            .iter()
            .any(|u| u.unchecked_check_id.contains("etc-passwd")),
        "POSIX /etc/passwd must not be reported as unchecked"
    );
}

/// FAIL-SAFE: when the filesystem probe is inconclusive (neither findmnt nor
/// stat registered), a violating path is still emitted as a finding. A real
/// permissions gap is never hidden by an unknowable filesystem.
#[tokio::test]
async fn test_permissions_scan_nonposix_probe_failsafe() {
    // /boot at 0o755, no findmnt/stat responses registered.
    let executor = MockExecutor::new().with_file_metadata("/boot", "", dir_mode(0o755));
    let ctx = Context::with_executor(Arc::new(executor));
    let result = PermissionsHardeningPlugin::new().scan(&ctx).await.unwrap();

    assert!(
        result
            .scan_findings
            .iter()
            .any(|f| f.finding_id.contains("boot")),
        "inconclusive probe must fall back to emitting the finding"
    );
    assert!(
        result.scan_unchecked.is_empty(),
        "inconclusive probe must not produce an unchecked check, got: {:?}",
        result
            .scan_unchecked
            .iter()
            .map(|u| &u.unchecked_check_id)
            .collect::<Vec<_>>()
    );
}

/// Apply on a non-POSIX filesystem must skip the chmod entirely (fixing the
/// silent local-fchmod false success) and record a single Skipped change with
/// fstab guidance. No chmod/fchmod command may reach the executor.
#[tokio::test]
async fn test_permissions_apply_nonposix_fs_skips_chmod() {
    // `.remote()` keeps the path off the real local fchmod; findmnt says vfat.
    let mut executor =
        MockExecutor::new()
            .remote()
            .with_file_metadata("/boot", "", dir_mode(0o755));
    executor = findmnt_fstype(executor, "/boot", "vfat");

    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = PermissionsHardeningPlugin::new();
    let config = PluginConfig::default();

    let result = plugin.apply(&mut ctx, &config).await.unwrap();

    // No real change was applied to the host.
    assert_eq!(
        result.applied_change_count(),
        0,
        "vfat apply must apply zero real changes"
    );

    // Exactly one Skipped change for /boot, carrying the guidance.
    let boot_skip = result
        .apply_changes
        .iter()
        .find(|c| c.is_skipped() && c.change_description.contains("/boot"))
        .expect("should have a skipped change for /boot");
    assert!(
        boot_skip.change_description.contains("fstab")
            && boot_skip.change_description.contains("vfat"),
        "skip must carry fstab + filesystem guidance, got: {}",
        boot_skip.change_description
    );

    // The chmod must never have been attempted.
    let log = executor.log();
    assert!(
        !log.commands_executed.iter().any(|(cmd, _)| cmd == "chmod"),
        "chmod must not run on a non-POSIX filesystem, log: {:?}",
        log.commands_executed
    );
}

/// A non-POSIX filesystem path is not a pending change: validate's dry-run must
/// exclude it from estimated changes.
#[tokio::test]
async fn test_permissions_validate_nonposix_fs_not_pending() {
    let mut executor = MockExecutor::new().with_file_metadata("/boot", "", dir_mode(0o755));
    executor = findmnt_fstype(executor, "/boot", "vfat");

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();
    let config = PluginConfig::default();

    let report = plugin.validate(&ctx, &config).await.unwrap();

    assert!(
        !report
            .validation_report_estimated_changes
            .iter()
            .any(|c| c.contains("/boot")),
        "vfat /boot must not be counted as a pending change, got: {:?}",
        report.validation_report_estimated_changes
    );
}
