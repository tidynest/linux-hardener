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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    let sudoers_finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id.contains("sudoers"))
        .expect("Should have sudoers finding");

    // Sudoers should be Critical severity
    assert_eq!(sudoers_finding.finding_severity, Severity::Critical);
}

#[tokio::test]
async fn test_permissions_scan_duration_recorded() {
    let executor = secure_permissions_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(
        result.scan_duration_us > 0,
        "scan duration should be recorded"
    );
}

/// A probe that failed is not a path that is absent.
///
/// `path_exists` has three outcomes by contract: present, confirmed absent, and
/// could not be determined. Validate collapsed the last two with
/// `unwrap_or(false)` under the comment "Path doesn't exist - not an error, just
/// skip", so a Critical path this run could not probe vanished from the dry run
/// entirely and the operator approved a run whose scope they had not been shown.
///
/// The scan was fixed for exactly this and says so in its own comment: treating
/// an errored probe as absence made it silent about a path it never managed to
/// look at. Validate kept the collapse.
#[tokio::test]
async fn validate_reports_a_path_whose_existence_could_not_be_determined() {
    let executor = secure_permissions_executor().with_path_exists_error("/etc/shadow");
    let ctx = Context::with_executor(Arc::new(executor));

    let report = PermissionsHardeningPlugin::new()
        .validate(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    let issue = report
        .validation_report_issues
        .iter()
        .find(|i| i.validation_issue_message.contains("/etc/shadow"))
        .unwrap_or_else(|| {
            panic!(
                "a path the dry run could not probe must be reported, got: {:?}",
                report.validation_report_issues
            )
        });
    assert_eq!(
        issue.validation_issue_severity,
        Severity::High,
        "the preview cannot describe this run, so it must not read as a clean one"
    );
    assert!(
        !report.validation_report_is_valid,
        "a report that could not see a Critical path is not a valid preview"
    );
}

/// The other half, and the one that must not move: a path confirmed absent is
/// still nothing to report. Without this, making the error case loud could be
/// "fixed" by reporting every absence, which would fire on openSUSE, where
/// /etc/gshadow is legitimately absent from both layers.
#[tokio::test]
async fn validate_stays_silent_about_a_path_confirmed_absent() {
    let executor = secure_permissions_executor().with_path_exists("/etc/shadow", false);
    let ctx = Context::with_executor(Arc::new(executor));

    let report = PermissionsHardeningPlugin::new()
        .validate(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        !report
            .validation_report_issues
            .iter()
            .any(|i| i.validation_issue_message.contains("/etc/shadow")),
        "a confirmed absence is not a defect, got: {:?}",
        report.validation_report_issues
    );
}

/// Apply carried the same collapse, and an omitted change cannot be a failed
/// one: the run reported success and its change list, which is the operator's
/// record of what was hardened, had no entry for the path at all.
#[tokio::test]
async fn apply_records_a_failure_when_existence_cannot_be_determined() {
    let executor = secure_permissions_executor().with_path_exists_error("/etc/shadow");
    let mut ctx = Context::with_executor(Arc::new(executor));

    let result = PermissionsHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .unwrap();

    let change = result
        .apply_changes
        .iter()
        .find(|c| c.change_description.contains("/etc/shadow"))
        .unwrap_or_else(|| {
            panic!(
                "a path the apply could not probe must appear in the record, got: {:?}",
                result.apply_changes
            )
        });
    assert!(
        !change.change_success,
        "a path that was never examined was not hardened: {change:?}"
    );
    assert!(
        !result.apply_success,
        "an apply that could not examine a Critical path did not fully succeed"
    );
}

/// A host where every managed path is confirmed absent has nothing to preview
/// and nothing to complain about.
///
/// Named for what it pins rather than for the old claim that validate "always
/// returns valid": it can now report an issue, for a path whose existence could
/// not be determined, and this fixture is the case that must stay quiet.
#[tokio::test]
async fn validate_is_clean_when_every_path_is_confirmed_absent() {
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

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

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
async fn apply_reports_a_mode_that_did_not_move_after_a_successful_chmod() {
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
        "a mode that did not move must report failure"
    );
    // The message must state what was observed. It used to blame vfat, a
    // cause `scan` has already excluded: a path positively confirmed to be on
    // a non-POSIX filesystem is diverted to PermissionCheck::NonPosix long
    // before apply runs, so naming it here sent operators to fstab for a
    // problem that was not there.
    assert!(
        !boot_change.change_description.contains("vfat"),
        "vfat is excluded before apply runs; it must not be named: {}",
        boot_change.change_description
    );
    assert!(
        boot_change.change_description.contains("0755")
            && boot_change.change_description.contains("0700"),
        "the message must state the observed and wanted modes, got: {}",
        boot_change.change_description
    );
}

/// A tightening override reaches the chmod, and a loosening one does not.
///
/// This used to assert the opposite half of its own subject: it set `/boot` to
/// 0755 against a baseline of 0700 and required the chmod to use it, which is
/// the one place in the repository that pinned a loosening override as correct
/// behaviour. The rule is now that an override may clear bits and never set
/// one, so the same fixture asks the same question of a value that qualifies,
/// and asks the refused case beside it rather than in a separate test: a clamp
/// that refused everything and a clamp that refused nothing must both fail
/// here, and only one assertion cannot tell them apart.
#[tokio::test]
async fn test_permissions_apply_respects_directives() {
    // /boot at 0o777, so both overrides have real work to do. `.remote()`
    // because MockExecutor cannot support local fchmod.
    let loose_boot = || {
        MockExecutor::new().remote().with_file_metadata(
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
    };
    let ok = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };

    let chmod_mode_for = |executor: &MockExecutor| -> String {
        let log = executor.log();
        let (_, args) = log
            .commands_executed
            .iter()
            .find(|(cmd, args): &&(String, Vec<String>)| {
                cmd == "chmod" && args.iter().any(|a| a == "/boot")
            })
            .unwrap_or_else(|| panic!("chmod for /boot: {:?}", log.commands_executed))
            .clone();
        args[0].clone()
    };

    // 0500 sets no bit outside the 0700 baseline, so it is the target.
    let tightening = loose_boot().with_command("chmod", &["0500", "/boot"], ok.clone());
    let mut ctx = Context::with_executor(Arc::new(tightening.clone()));
    let mut config = PluginConfig::default();
    config
        .directives
        .insert("/boot".to_string(), "500".to_string());
    PermissionsHardeningPlugin::new()
        .apply(&mut ctx, &config)
        .await
        .expect("apply");
    assert_eq!(
        chmod_mode_for(&tightening),
        "0500",
        "a tightening override is the target apply chmods to",
    );

    // 0755 adds group and world read and execute, so the baseline stands.
    let loosening = loose_boot().with_command("chmod", &["0700", "/boot"], ok);
    let mut ctx = Context::with_executor(Arc::new(loosening.clone()));
    let mut config = PluginConfig::default();
    config
        .directives
        .insert("/boot".to_string(), "755".to_string());
    PermissionsHardeningPlugin::new()
        .apply(&mut ctx, &config)
        .await
        .expect("apply");
    assert_eq!(
        chmod_mode_for(&loosening),
        "0700",
        "a loosening override is refused and the shipped baseline applies",
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
async fn apply_ignores_exception_whose_mode_does_not_match() {
    // /boot is 0777 on the mock; the exception documents 0755. The values
    // disagree, so the exception must not be honoured and /boot must be
    // hardened (chmod'd to the 0700 baseline) rather than skipped.
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
            &["0700", "/boot"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = PermissionsHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "/boot".to_string(),
        PolicyException {
            value: "0755".to_string(),
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

    // The path must actually have been hardened: a chmod to the 0700
    // baseline for /boot was issued, not merely some chmod naming /boot.
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
    assert_eq!(
        args,
        &vec!["0700".to_string(), "/boot".to_string()],
        "chmod should harden /boot to the 0700 baseline with no extra args, got: {:?}",
        args
    );
}

/// A regression test for the `.filter(|m| m.exists)` fix in the apply loop's
/// `current_mode` read. `/etc/gshadow` is deliberately left unregistered, so
/// `MockExecutor::file_metadata` returns its sentinel `Ok(exists: false, mode:
/// 0)` for it - reproducing a host where `stat` fails but the read still
/// "succeeds" with a mode of zero. The exception below documents "0000",
/// exactly that sentinel value: without the `.filter` guard, an unverified
/// mode would satisfy this exception and record a bogus skipped-exception
/// change for a path that was never actually observed to be 0000. With the
/// guard restored, an unverified mode never matches any exception, and since
/// `/etc/gshadow` does not exist in this fixture, `apply_path_permissions`
/// also declines to act on it (`path_exists` is the authority there) - so no
/// change at all is recorded for it.
///
/// Uses `.remote()` so a would-be chmod (if the regression were present)
/// goes through the mock's `execute_command` rather than a real local
/// `fchmod` syscall.
#[tokio::test]
async fn apply_ignores_exception_when_mode_is_unverified() {
    let executor = MockExecutor::new().remote().with_file_metadata(
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

    let mut ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "/etc/gshadow".to_string(),
        PolicyException {
            value: "0000".to_string(),
            allowed: true,
            reason: "Bogus exception matching the unverified-mode sentinel".to_string(),
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
            .any(|c| c.change_description.contains("/etc/gshadow")),
        "an unverified mode must not match an exception, and a path that \
         does not exist must not otherwise be acted on, got: {:?}",
        result
            .apply_changes
            .iter()
            .map(|c| &c.change_description)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn scan_honours_directive_override() {
    // Baseline for /root is already compliant (0700), but a stricter
    // directive override (0500) makes it non-compliant -> a finding appears
    // even though the host already meets the hardcoded baseline.
    let executor = secure_permissions_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config
        .directives
        .insert("/root".to_string(), "500".to_string());

    let result = plugin.scan(&ctx, &config).await.unwrap();

    let finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "perm--root")
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

    // Target-dependent field must reflect the override value (0500), not the
    // hardcoded baseline (0700) - otherwise the finding would self-contradict
    // by recommending the value the host is already at.
    assert_eq!(
        finding.finding_recommended_value, "0500",
        "recommended value should reflect the directive override, not the baseline"
    );
}

#[tokio::test]
async fn validate_honours_directive_override() {
    // The counterpart of scan_honours_directive_override on the dry-run path,
    // which had no test of its own while carrying its own copy of the override
    // rule. /root already sits at the 0700 baseline, so nothing is pending
    // without the override: a stricter 0500 is the only thing that can put the
    // path in the preview at all, and the target the preview names is the only
    // place the override's value can surface.
    let executor = secure_permissions_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config
        .directives
        .insert("/root".to_string(), "500".to_string());

    let report = plugin.validate(&ctx, &config).await.unwrap();

    let pending = report
        .validation_report_estimated_changes
        .iter()
        .find(|c| c.contains("/root"))
        .unwrap_or_else(|| {
            panic!(
                "a stricter override makes a compliant path pending, got: {:?}",
                report.validation_report_estimated_changes
            )
        });
    assert!(
        pending.contains("0500"),
        "the preview must name the override as the target rather than the \
         baseline, got: {pending}"
    );
}

#[tokio::test]
async fn scan_annotates_valid_exception() {
    // /root violates baseline (0755 vs 0700) with a valid exception recorded:
    // exceptions annotate findings, they never drop them, so the finding
    // stays present and carries the exception annotation.
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

    let result = plugin.scan(&ctx, &config).await.unwrap();

    let finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "perm--root")
        .expect("non-compliant path should still produce a finding");
    assert!(
        finding.finding_policy_exception.is_some(),
        "finding should be annotated with the valid exception"
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

#[tokio::test]
async fn validate_reports_a_path_left_alone_by_a_policy_exception() {
    // The sibling above pins that an excepted path is not a pending change.
    // It is not, however, nothing. Every other renderer labels a documented
    // deviation rather than hiding it, and the sweep in 2ae9e4a gave six
    // plugins exactly that while this one kept an empty vector, so a dry run
    // whose only drift was excepted rendered byte-identically to a host that
    // needed nothing doing.
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

    // The mode is spelled the way every other line this plugin emits spells
    // one, so a bare `{:o}` would fail here rather than reach an operator.
    assert!(
        report.validation_report_exceptions.iter().any(|e| {
            e.contains("/root") && e.contains("0755") && e.contains("Shared admin access")
        }),
        "an excepted path must be reported, naming the mode it keeps and why, got: {:?}",
        report.validation_report_exceptions
    );

    // /boot violates its baseline on this fixture and carries no exception,
    // so a fix that reports every path rather than every excepted one fails
    // here.
    assert!(
        !report
            .validation_report_exceptions
            .iter()
            .any(|e| e.contains("/boot")),
        "a path with no exception must not be reported as excepted, got: {:?}",
        report.validation_report_exceptions
    );
}

#[tokio::test]
async fn validate_ignores_exception_whose_mode_does_not_match() {
    // insecure_permissions_executor's /root is genuinely 0755; the exception
    // documents 0750, a value the host does not actually have.
    let executor = insecure_permissions_executor();
    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();

    let mut config = PluginConfig::default();
    config.exceptions.insert(
        "/root".to_string(),
        PolicyException {
            value: "0750".to_string(),
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
            .any(|c| c.contains("/root")),
        "a non-matching exception must leave the change in the preview"
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
    let result = PermissionsHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

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
    let result = PermissionsHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

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

/// Covers the branch `apply_path_permissions` takes when a path is confirmed
/// present (`path_exists` true) but its mode could not be read (`file_metadata`
/// errors), the state a real `SshExecutor` produces when `stat` fails mid-scan.
/// `/etc/passwd` is an exact directive (`permission_max_mask: false`, baseline
/// 0o644 per `CRITICAL_PERMISSIONS`), so `unverified_mode_target` yields
/// `Some(0o644)` regardless of the unknown current mode, and apply must still
/// harden it rather than give up. `target_mode` for an exact directive ignores
/// `current_mode` entirely, so the registered chmod is `0644` (the baseline),
/// not derived from any observed mode.
#[tokio::test]
async fn apply_hardens_an_exact_directive_with_an_unverifiable_mode() {
    let executor = MockExecutor::new()
        .remote()
        .with_metadata_error("/etc/passwd")
        .with_path_exists("/etc/passwd", true)
        .with_command(
            "chmod",
            &["0644", "/etc/passwd"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = PermissionsHardeningPlugin::new();

    plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply succeeds");

    let log = executor.log();
    let chmods: Vec<_> = log
        .commands_executed
        .iter()
        .filter(|(program, args)| program == "chmod" && args.iter().any(|a| a == "/etc/passwd"))
        .collect();
    assert!(
        !chmods.is_empty(),
        "an exact directive with an unverifiable mode must still be hardened"
    );
}

/// The max-mask counterpart of the test above. `/etc/shadow` is a max-mask
/// directive (`permission_max_mask: true`, mask 0o640), whose target is
/// `current_mode & mask` - uncomputable when `current_mode` is unknown, per
/// `unverified_mode_target` returning `None` for max-mask directives. Apply
/// must not guess (that could loosen an already-stricter host); it records a
/// Skipped change instead of vanishing the path or attempting a chmod.
#[tokio::test]
async fn apply_records_a_skip_for_an_unverifiable_max_mask_directive() {
    let executor = MockExecutor::new()
        .remote()
        .with_metadata_error("/etc/shadow")
        .with_path_exists("/etc/shadow", true);
    let mut ctx = Context::with_executor(Arc::new(executor.clone()));
    let plugin = PermissionsHardeningPlugin::new();

    let result = plugin
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("apply succeeds");

    assert!(
        result
            .apply_changes
            .iter()
            .any(|c| c.change_description.contains("/etc/shadow") && c.is_skipped()),
        "an unverifiable max-mask path must record a skip, not vanish"
    );

    let log = executor.log();
    let chmods: Vec<_> = log
        .commands_executed
        .iter()
        .filter(|(program, args)| program == "chmod" && args.iter().any(|a| a == "/etc/shadow"))
        .collect();
    assert!(chmods.is_empty(), "a max-mask target is uncomputable here");
}

#[tokio::test]
async fn scan_reports_a_critical_path_it_cannot_read_instead_of_staying_silent() {
    // /etc/shadow whose mode cannot be read used to produce neither a finding
    // nor an unchecked entry: total silence, identical to a verified-compliant
    // result. These are exactly the paths where that is least acceptable.
    let executor = MockExecutor::new()
        .with_path_exists("/etc/shadow", true)
        .with_metadata_error("/etc/shadow");
    let ctx = Context::with_executor(Arc::new(executor) as Arc<dyn SystemExecutor>);
    let plugin = PermissionsHardeningPlugin::new();

    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    assert!(
        result
            .scan_unchecked
            .iter()
            .any(|u| u.unchecked_reason.contains("/etc/shadow")),
        "an unreadable /etc/shadow must be reported as unchecked, got unchecked={:?}",
        result
            .scan_unchecked
            .iter()
            .map(|u| &u.unchecked_check_id)
            .collect::<Vec<_>>()
    );
}

/// openSUSE ships `sudoers` at `/usr/etc/sudoers` and nothing at `/etc/sudoers`,
/// measured on the test container 2026-07-30 at mode 0444. The directive targets
/// 0440 exactly, at Critical, so the file in force is world-readable and the
/// control is violated. Before this was fixed the plugin took its confirmed
/// absence branch and reported neither a finding nor an unchecked entry, which
/// is the silence `PermissionCheck::Unverifiable` was introduced to avoid for
/// this very path.
#[tokio::test]
async fn vendor_layer_violation_is_reported_when_etc_holds_nothing() {
    let executor = MockExecutor::new().with_file_metadata(
        "/usr/etc/sudoers",
        "",
        FileMetadata {
            exists: true,
            is_file: true,
            is_dir: false,
            mode: 0o444,
            size: 5292,
            uid: 0,
            gid: 0,
        },
    );

    let ctx = Context::with_executor(Arc::new(executor));
    let plugin = PermissionsHardeningPlugin::new();
    let result = plugin.scan(&ctx, &PluginConfig::default()).await.unwrap();

    let finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "perm--etc-sudoers")
        .unwrap_or_else(|| {
            panic!(
                "the vendor file violates its directive and must be reported; findings: {:?}, unchecked: {:?}",
                result
                    .scan_findings
                    .iter()
                    .map(|f| &f.finding_id)
                    .collect::<Vec<_>>(),
                result
                    .scan_unchecked
                    .iter()
                    .map(|u| &u.unchecked_check_id)
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(finding.finding_current_value, "0444");
    assert_eq!(finding.finding_recommended_value, "0440");
    assert_eq!(finding.finding_severity, Severity::Critical);
    assert!(
        finding.finding_title.contains("/usr/etc/sudoers"),
        "the finding names the file actually in force, got: {}",
        finding.finding_title
    );
    assert!(
        finding
            .finding_remediation_steps
            .iter()
            .all(|s| !s.contains("chmod 0440 /usr/etc/sudoers")),
        "this tool never writes the vendor file, so it must not tell the operator it will, got: {:?}",
        finding.finding_remediation_steps
    );
}

/// The vendor copy at the target mode is compliant, and compliance is silence.
#[tokio::test]
async fn vendor_layer_at_the_target_mode_reports_nothing() {
    let executor = MockExecutor::new().with_file_metadata(
        "/usr/etc/sudoers",
        "",
        FileMetadata {
            exists: true,
            is_file: true,
            is_dir: false,
            mode: 0o440,
            size: 5292,
            uid: 0,
            gid: 0,
        },
    );

    let ctx = Context::with_executor(Arc::new(executor));
    let result = PermissionsHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        result.scan_findings.is_empty() && result.scan_unchecked.is_empty(),
        "a compliant vendor file is nothing to report, got findings {:?} and unchecked {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| &f.finding_id)
            .collect::<Vec<_>>(),
        result
            .scan_unchecked
            .iter()
            .map(|u| &u.unchecked_check_id)
            .collect::<Vec<_>>()
    );
}

/// `/etc` wins. The vendor layer is consulted only on a confirmed absence, so a
/// host holding both must be judged on the file that takes precedence, and a
/// violating vendor copy underneath a compliant override is not a finding.
#[tokio::test]
async fn an_etc_file_is_judged_and_the_vendor_copy_beneath_it_is_not() {
    let executor = MockExecutor::new()
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
            "/usr/etc/sudoers",
            "",
            FileMetadata {
                exists: true,
                is_file: true,
                is_dir: false,
                mode: 0o444,
                size: 5292,
                uid: 0,
                gid: 0,
            },
        );

    let ctx = Context::with_executor(Arc::new(executor));
    let result = PermissionsHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        result.scan_findings.is_empty(),
        "the /etc copy is compliant and it is the file in force, got: {:?}",
        result
            .scan_findings
            .iter()
            .map(|f| (&f.finding_id, &f.finding_current_value))
            .collect::<Vec<_>>()
    );
}

/// Absent from both layers is the only shape where silence is the whole truth,
/// and it is what `/etc/gshadow` reads on the openSUSE container.
#[tokio::test]
async fn absent_from_both_layers_reports_nothing() {
    let ctx = Context::with_executor(Arc::new(MockExecutor::new()));
    let result = PermissionsHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        result.scan_findings.is_empty() && result.scan_unchecked.is_empty(),
        "no file at either layer is nothing to report"
    );
}

/// A vendor probe that errors says nothing either way, and must not join the
/// absence it cannot rule out. The same three-outcome contract the admin path has.
#[tokio::test]
async fn an_unreadable_vendor_path_is_unchecked_rather_than_silent() {
    let executor = MockExecutor::new().with_path_exists_error("/usr/etc/sudoers");

    let ctx = Context::with_executor(Arc::new(executor));
    let result = PermissionsHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    let unchecked = result
        .scan_unchecked
        .iter()
        .find(|u| u.unchecked_check_id == "perm--etc-sudoers")
        .expect("an existence probe that failed is not an absence");
    assert!(
        unchecked.unchecked_reason.contains("/usr/etc/sudoers"),
        "the reason names the path it could not read, got: {}",
        unchecked.unchecked_reason
    );
}

/// The directive override reaches the vendor path, which is the property the
/// extracted `effective_directive` exists for: 0440 satisfies the built-in
/// baseline and violates an operator override of 0400, so a finding here can only
/// come from the override having been applied to the vendor comparison.
#[tokio::test]
async fn a_directive_override_applies_to_the_vendor_layer_too() {
    let executor = MockExecutor::new().with_file_metadata(
        "/usr/etc/sudoers",
        "",
        FileMetadata {
            exists: true,
            is_file: true,
            is_dir: false,
            mode: 0o440,
            size: 5292,
            uid: 0,
            gid: 0,
        },
    );
    let mut config = PluginConfig::default();
    config
        .directives
        .insert("/etc/sudoers".to_string(), "400".to_string());

    let ctx = Context::with_executor(Arc::new(executor));
    let result = PermissionsHardeningPlugin::new()
        .scan(&ctx, &config)
        .await
        .unwrap();

    let finding = result
        .scan_findings
        .iter()
        .find(|f| f.finding_id == "perm--etc-sudoers")
        .expect("0440 violates an override of 0400");
    assert_eq!(finding.finding_recommended_value, "0400");
}

/// Every finding this plugin reports must name the key that silences it, and
/// a permission finding renders `perm--etc-ssh-sshd_config` from a key of
/// `/etc/ssh/sshd_config`, collapsing `/` and `-` onto `-`.
///
/// The loop is the point: asserting one finding would leave every other
/// directive in this plugin free to advertise a key that does nothing. The
/// emptiness check is the control, because a fixture reporting nothing would
/// satisfy a loop that never runs.
#[tokio::test]
async fn every_permissions_finding_names_the_exception_key_that_silences_it() {
    let scan = async |config: &PluginConfig| {
        PermissionsHardeningPlugin::new()
            .scan(
                &Context::with_executor(Arc::new(insecure_permissions_executor())),
                config,
            )
            .await
            .expect("permissions scan should not error")
    };

    let result = scan(&PluginConfig::default()).await;
    assert!(
        !result.scan_findings.is_empty(),
        "the fixture must report something, or the loop below measures nothing",
    );

    let mut config = PluginConfig::default();
    let mut sampled = Vec::new();
    for finding in &result.scan_findings {
        let key = finding
            .finding_exception_key
            .clone()
            .unwrap_or_else(|| panic!("{} advertises no exception key", finding.finding_id));
        assert_ne!(
            key, finding.finding_id,
            "the key is not the id; an id is derived from the key and loses information",
        );
        sampled.push(key.clone());
        config.exceptions.insert(
            key,
            PolicyException {
                value: finding.finding_current_value.clone(),
                allowed: true,
                reason: "measured deviation".to_string(),
                approved_by: None,
                approved_date: None,
                ticket: None,
                expires: None,
            },
        );
    }

    assert!(
        sampled.iter().any(|key| key.starts_with('/')),
        "every permissions key is the absolute path of the file it guards",
    );

    for finding in &scan(&config).await.scan_findings {
        assert!(
            finding.finding_policy_exception.is_some(),
            "{} was not annotated by an exception written under the key it named",
            finding.finding_id,
        );
    }
}
