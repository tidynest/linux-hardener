#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`audit`].
//!
//! Split out of `audit.rs`. This file sits in the `audit/` directory
//! beside it, so `super` still resolves to `crate::audit` and every
//! import carried across unchanged, private items included.

use super::*;

use hardener_core::{CommandOutput, MockExecutor, SystemExecutor};
use std::sync::Arc;

/// A backup that fails must stop the write. Overwriting a rules file this
/// tool could not copy destroys the operator's audit rules with nothing to
/// restore from, and `execute_command` returns Ok for a command that ran
/// and failed, so the exit code is the only signal there is.
#[tokio::test]
async fn a_failed_backup_aborts_before_the_rules_file_is_written() {
    let backup_failed = CommandOutput {
        stdout: String::new(),
        stderr: "cp: cannot create regular file: Read-only file system".to_string(),
        exit_code: 1,
    };
    let executor = MockExecutor::new()
        .with_file(AUDIT_RULES_PATH, "-w /etc/passwd -p wa -k identity\n")
        .with_path_exists(AUDIT_RULES_PATH, true)
        // No mkdir is registered because this function no longer runs one:
        // its caller ensures the directory above the checkpoint. Nothing
        // else here can abort the write, so removing the cp check under
        // test would let the write through and fail this test, which is
        // what it is for.
        .with_command_program("cp", backup_failed);
    let executor = Arc::new(executor);
    let ctx = Context::with_executor(executor.clone() as Arc<dyn SystemExecutor>);

    let result = write_audit_rules_file(&ctx, "-w /etc/new -p wa -k new").await;

    assert!(result.is_err(), "a failed cp must surface as an error");
    assert!(
        executor.log().files_written.is_empty(),
        "the rules file must not be written when its backup failed, but these writes happened: {:?}",
        executor.log().files_written
    );
}

/// `systemctl is-enabled` is judged on its word and never on its exit
/// status, because the two disagree by design.
///
/// Measured on a live systemd host rather than taken from the manual:
/// `static` and `indirect` each print their own word and exit **0**, while
/// `disabled` and `masked` print theirs and exit 1. `enabled-runtime` is
/// documented by systemd as exiting 0 and is the case this plugin most
/// needs to get right, because it is enablement made in
/// `/run/systemd/system`, which the next boot discards.
///
/// Reading the exit status therefore reports auditd as enabled at boot on
/// a host where nothing will start it, and the apply skips the enable that
/// would have repaired it. Both directions are asserted so that a helper
/// which simply always answered "not enabled" would fail here too.
#[tokio::test]
async fn boot_enablement_is_read_from_the_word_and_not_the_exit_status() {
    for (state, exit_code, wanted) in [
        ("enabled", 0, true),
        ("enabled-runtime", 0, false),
        ("static", 0, false),
        ("indirect", 0, false),
        ("disabled", 1, false),
        ("masked", 1, false),
    ] {
        let executor = Arc::new(MockExecutor::new().with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: format!("{state}\n"),
                stderr: String::new(),
                exit_code,
            },
        ));
        let ctx = Context::with_executor(executor as Arc<dyn SystemExecutor>);

        let enabled = is_auditd_enabled(&ctx)
            .await
            .expect("a registered systemctl answer must not error");

        assert_eq!(
            enabled, wanted,
            "systemctl is-enabled auditd answering '{state}' with exit \
             {exit_code} must read as enabled={wanted}"
        );
    }
}

/// A backup is only worth taking if it is a copy of the thing about to be
/// replaced, at the mode that thing carries.
///
/// This file is the one the plugin insists on holding at 0640, because the
/// rules name every path and syscall the host watches; a backup restored
/// without `-p` lands at whatever the umask gives it and hands that map to
/// anyone. `--no-dereference` copies a symlink as a symlink, so a rules
/// file that is a link elsewhere is backed up as the object about to be
/// overwritten rather than as its target.
///
/// Asserted on the recorded argv rather than on the run succeeding, and
/// against a mock that answers any `cp` by program name. A test that leaned
/// on an exact-argument registration missing would fail with "command not
/// registered", which is a different failure wearing this one's clothes.
#[tokio::test]
async fn the_backup_copy_keeps_the_mode_and_does_not_follow_a_symlink() {
    let ok = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    let executor = Arc::new(
        MockExecutor::new()
            .with_file(AUDIT_RULES_PATH, "-w /etc/passwd -p wa -k identity\n")
            .with_path_exists(AUDIT_RULES_PATH, true)
            .with_command_program("cp", ok),
    );
    let ctx = Context::with_executor(executor.clone() as Arc<dyn SystemExecutor>);

    let backup = write_audit_rules_file(&ctx, "-w /etc/new -p wa -k new")
        .await
        .expect("a mock that answers any cp must let the write through")
        .expect("an existing rules file must be backed up");

    let log = executor.log();
    let (_, args) = log
        .commands_executed
        .iter()
        .find(|(program, _)| program == "cp")
        .expect("the backup must be taken with cp");
    for flag in ["-p", "--no-dereference"] {
        assert!(
            args.iter().any(|argument| argument == flag),
            "the backup cp must pass {flag}, got: {args:?}"
        );
    }
    // Checked separately from the flags because "the flag is present" and
    // "the flag is a flag" are different claims: an argument added after
    // the source would be read by cp as another file to copy.
    assert_eq!(
        &args[args.len() - 2..],
        &[AUDIT_RULES_PATH.to_string(), backup],
        "source and destination must stay the last two arguments, got: {args:?}"
    );
}

/// A representative audit check (`not_installed`) must now carry
/// multi-framework mappings: the existing CIS control plus NIST 800-53,
/// STIG, and PCI-DSS sourced from SSG `package_audit_installed`.
#[test]
fn auditd_install_has_multi_framework_mappings() {
    let mappings = get_audit_compliance_mappings("not_installed");

    let has = |fw| mappings.iter().any(|m| m.compliance_framework == fw);
    assert!(
        has(ComplianceFramework::CIS),
        "CIS mapping must be retained"
    );
    assert!(
        has(ComplianceFramework::NIST),
        "NIST mapping must be present"
    );
    assert!(
        has(ComplianceFramework::STIG),
        "STIG mapping must be present"
    );
    assert!(
        has(ComplianceFramework::PCIDSS),
        "PCI-DSS mapping must be present"
    );

    // Verify the exact SSG-sourced STIG and NIST identifiers.
    let stig = mappings
        .iter()
        .find(|m| m.compliance_framework == ComplianceFramework::STIG)
        .unwrap();
    assert_eq!(stig.compliance_control_id, "OL08-00-030180");
    let nist = mappings
        .iter()
        .find(|m| m.compliance_framework == ComplianceFramework::NIST)
        .unwrap();
    assert_eq!(nist.compliance_control_id, "AU-2(a)");
}

/// Audit findings must also carry HIPAA, GDPR and ISO/IEC 27001:2022
/// logging mappings alongside the existing CIS/NIST/STIG/PCI-DSS set.
#[test]
fn auditd_install_has_privacy_and_iso_mappings() {
    let mappings = get_audit_compliance_mappings("not_installed");

    let has = |fw| mappings.iter().any(|m| m.compliance_framework == fw);
    assert!(has(ComplianceFramework::HIPAA), "HIPAA must be present");
    assert!(has(ComplianceFramework::GDPR), "GDPR must be present");
    assert!(
        has(ComplianceFramework::ISO27001),
        "ISO 27001 must be present"
    );

    // ISO logging clause for audit controls.
    let iso = mappings
        .iter()
        .find(|m| m.compliance_framework == ComplianceFramework::ISO27001)
        .unwrap();
    assert_eq!(iso.compliance_control_id, "8.15");

    // HIPAA must include the Audit Controls safeguard.
    assert!(
        mappings
            .iter()
            .any(|m| m.compliance_framework == ComplianceFramework::HIPAA
                && m.compliance_control_id == "164.312(b)")
    );
}

/// The audit-rules bucket additionally maps to ISO 8.16 (monitoring
/// activities), since live rules actively monitor security events.
#[test]
fn audit_rules_map_to_iso_monitoring() {
    let mappings = get_audit_compliance_mappings("rules");
    assert!(
        mappings
            .iter()
            .any(|m| m.compliance_framework == ComplianceFramework::ISO27001
                && m.compliance_control_id == "8.16"),
        "audit rules must map to ISO 8.16 monitoring activities"
    );
}

/// Confirms the SOC 2 mappings: every auditd service-state finding carries
/// the anomaly-monitoring criterion CC7.2, and the rules bucket adds the
/// configuration-change detection criterion CC7.1; both filed under the
/// "System Operations" TSC series.
#[test]
fn audit_findings_map_soc2_monitoring_criteria() {
    for finding_type in ["not_installed", "not_running"] {
        let soc2 = get_audit_compliance_mappings(finding_type)
            .into_iter()
            .find(|m| m.compliance_framework == ComplianceFramework::SOC2)
            .unwrap_or_else(|| panic!("{finding_type} must carry a SOC 2 mapping"));
        assert_eq!(soc2.compliance_control_id, "CC7.2");
        assert_eq!(
            soc2.compliance_section.as_deref(),
            Some("System Operations")
        );
    }

    let rule_ids: Vec<String> = get_audit_compliance_mappings("rules")
        .into_iter()
        .filter(|m| m.compliance_framework == ComplianceFramework::SOC2)
        .map(|m| m.compliance_control_id)
        .collect();
    assert!(rule_ids.contains(&"CC7.1".to_string()));
    assert!(rule_ids.contains(&"CC7.2".to_string()));
}

/// Confirms the 800-171r3 crosswalk: AU-2 → 3.3.1 for the install check
/// and AU-12 → 3.3.3 for the service and rules checks, filed under the
/// official Audit and Accountability family.
#[test]
fn audit_findings_map_nist_800_171_requirements() {
    for (finding_type, id) in [
        ("not_installed", "3.3.1"),
        ("not_running", "3.3.3"),
        ("rules", "3.3.3"),
    ] {
        let mapping = get_audit_compliance_mappings(finding_type)
            .into_iter()
            .find(|m| m.compliance_framework == ComplianceFramework::NIST800171)
            .unwrap_or_else(|| panic!("{finding_type} must carry an 800-171 mapping"));
        assert_eq!(mapping.compliance_control_id, id, "{finding_type}");
        assert_eq!(
            mapping.compliance_section.as_deref(),
            Some("Audit and Accountability")
        );
    }
}

/// Confirms the FedRAMP derivation: AU-2 and AU-12 are both GSA rev5
/// Moderate baseline members, so each finding mirrors its existing 800-53
/// entry verbatim under the Audit and Accountability family.
#[test]
fn audit_findings_map_fedramp_moderate_controls() {
    for (finding_type, id) in [
        ("not_installed", "AU-2(a)"),
        ("not_running", "AU-12(c)"),
        ("rules", "AU-12(c)"),
    ] {
        let mapping = get_audit_compliance_mappings(finding_type)
            .into_iter()
            .find(|m| m.compliance_framework == ComplianceFramework::FedRAMP)
            .unwrap_or_else(|| panic!("{finding_type} must carry a FedRAMP mapping"));
        assert_eq!(mapping.compliance_control_id, id, "{finding_type}");
        assert_eq!(
            mapping.compliance_section.as_deref(),
            Some("Audit and Accountability")
        );
    }
}

/// When auditctl requires root to list rules, the scan must report each
/// expected audit rule as unchecked rather than creating false missing-rule
/// findings.
#[tokio::test]
async fn scan_reports_rules_unchecked_when_auditctl_needs_root() {
    use hardener_core::{CommandOutput, MockExecutor};

    // Mock all commands needed for the scan: auditd is present and running,
    // but auditctl requires root to list rules. The audit_rule_* unchecked
    // entries must appear without false missing-rule findings.
    let mock = MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "auditctl",
            &["-l"],
            CommandOutput {
                stdout: String::new(),
                stderr: "You must be root to run this program.".to_string(),
                exit_code: 4,
            },
        );
    let ctx = Context::with_executor(std::sync::Arc::new(mock));
    let result = AuditHardeningPlugin::new()
        .scan(&ctx, &PluginConfig::default())
        .await
        .unwrap();

    assert!(
        !result
            .scan_findings
            .iter()
            .any(|f| f.finding_id.starts_with("audit_rule_")),
        "no false missing-rule findings"
    );
    assert_eq!(result.scan_unchecked.len(), AUDIT_RULES.len());
    assert!(
        result
            .scan_unchecked
            .iter()
            .all(|u| u.unchecked_check_id.starts_with("audit_rule_"))
    );
}

/// `validate` must fold `AuditRulesResult::UnrecognisedFailure` back to
/// `Rules(Vec::new())`, exactly as scan does at its own `read_current_audit_rules`
/// call, and exactly as this collapsed before that variant existed (#142).
///
/// Before commit 9f31ea46 introduced the variant, an `auditctl -l` failure
/// that was neither a recognised permission refusal nor an unspawnable binary
/// read as `Rules(Vec::new())` here too, so validate reported every one of the
/// 25 `AUDIT_RULES` entries as missing. The `if let AuditRulesResult::Rules(_)`
/// pattern added by that commit only matches the `Rules` arm, so an
/// unrecognised failure now falls through the whole rule-estimation block
/// silently: a dry-run preview on a host in this state shows no pending rule
/// changes while `apply` (which never calls this function at all) would still
/// write all 25. Asserted against the exact count so a regression that drops
/// only some rules would also fail here.
#[tokio::test]
async fn validate_folds_unrecognised_auditctl_failure_to_empty_rules() {
    let mock = MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command(
            "systemctl",
            &["is-enabled", "auditd"],
            CommandOutput {
                stdout: "enabled\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "systemctl",
            &["is-active", "auditd"],
            CommandOutput {
                stdout: "active\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "auditctl",
            &["-l"],
            CommandOutput {
                stdout: String::new(),
                stderr: "unexpected internal error".to_string(),
                exit_code: 2,
            },
        );
    let ctx = Context::with_executor(Arc::new(mock));

    let report = AuditHardeningPlugin::new()
        .validate(&ctx, &PluginConfig::default())
        .await
        .expect("validate must not error on an unrecognised auditctl failure");

    assert_eq!(
        report.validation_report_estimated_changes,
        vec![format!("Add {} audit-rules", AUDIT_RULES.len())],
        "an unrecognised auditctl failure must be folded to Rules(Vec::new()), \
         reporting every configured audit rule as a pending change, got: {:?}",
        report.validation_report_estimated_changes
    );
}

/// Names only audit's own paths, so a failure here cannot come from another
/// plugin's entry in a shared list.
#[test]
fn audit_reloads_for_its_own_paths_and_no_others() {
    let plugin = AuditHardeningPlugin::new();
    assert!(plugin.reloads_for_path(Path::new("/etc/audit/auditd.conf")));
    assert!(plugin.reloads_for_path(Path::new("/etc/audit/rules.d/hardening.rules")));
    assert!(plugin.reloads_for_path(Path::new("/etc/audit/audit.rules")));
    assert!(!plugin.reloads_for_path(Path::new("/etc/pam.d/system-auth")));
}

/// Ties the predicate to the literals `apply` actually checkpoints, so the
/// two cannot drift apart unnoticed.
#[test]
fn every_path_audit_checkpoints_is_one_it_reloads_for() {
    let plugin = AuditHardeningPlugin::new();
    for path in [
        "/etc/audit/auditd.conf",
        AUDIT_RULES_DIR,
        AUDIT_RULES_PATH,
        AUDIT_COMPILED_RULES,
        AUDIT_COMPILED_RULES_PREV,
    ] {
        assert!(
            plugin.reloads_for_path(Path::new(path)),
            "audit checkpoints {path} but would not reload for it"
        );
    }
}

/// The guard at the top of `divergences_after_rollback` is deletable in
/// silence unless something exercises it directly: with the guard removed by
/// hand, `cargo test -p hardener-plugins` still passed, because the generic
/// self-scoping probe in `reload_tests.rs` exercises only a stub, never this
/// plugin's own predicate. Both halves are asserted, because the empty-result
/// half alone would also pass against a probe that can never report anything.
#[tokio::test]
async fn audit_divergences_after_rollback_is_scoped_to_restored_audit_paths() {
    let ctx = Context::with_executor(Arc::new(MockExecutor::new()));
    let plugin = AuditHardeningPlugin::new();

    let unrelated = plugin
        .divergences_after_rollback(&ctx, &[std::path::PathBuf::from("/etc/ssh/sshd_config")])
        .await;
    assert!(
        unrelated.is_empty(),
        "no restored path was under /etc/audit, so the probe must not have run"
    );

    let owned = plugin
        .divergences_after_rollback(&ctx, &[std::path::PathBuf::from(AUDIT_RULES_PATH)])
        .await;
    assert!(
        !owned.is_empty(),
        "a restored path under /etc/audit must let the probe run"
    );
}

/// A rollback that did everything the host allows must not exit as a failure.
///
/// `apply` already treats an unloadable rule set as a skip when the kernel
/// audit config is locked (`-e 2`): the rules file is written and correct, it
/// simply cannot go live before the next reboot. The rollback path asked the
/// same question of the same host and called it a failed reload, so restoring
/// an audit checkpoint on a locked host exited 1 and told the operator a
/// service was still on the previous configuration. Both halves have to read
/// the host the same way.
#[tokio::test]
async fn a_locked_audit_config_is_a_reported_skip_rather_than_a_failed_reload() {
    let executor = Arc::new(
        MockExecutor::new()
            .with_command_exists("augenrules", true)
            .with_command_program(
                "augenrules",
                CommandOutput {
                    stdout: String::new(),
                    stderr: "Error sending add rule request (Operation not permitted)".to_string(),
                    exit_code: 1,
                },
            )
            .with_command_program(
                "systemctl",
                CommandOutput {
                    stdout: String::new(),
                    stderr: "Failed to restart auditd.service".to_string(),
                    exit_code: 1,
                },
            )
            .with_command(
                "auditctl",
                &["-s"],
                CommandOutput {
                    stdout: "enabled 2\nfailure 1\npid 0\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            ),
    );
    let ctx = Context::with_executor(executor);

    let reloaded = AuditHardeningPlugin::new()
        .reload_after_rollback(&ctx)
        .await
        .expect("a locked audit config is not a rollback failure");

    let action = reloaded.expect("the operator is still told why nothing was loaded");
    assert!(
        action.contains("reboot"),
        "the row must say the restored rules take effect at the next reboot, got: {action}"
    );
}

/// The other direction, so the skip above cannot swallow a genuine failure: a
/// host whose audit config is not locked and whose reload was refused anyway
/// has a running daemon on the previous rules, and the rollback must say so.
#[tokio::test]
async fn an_unlocked_audit_config_still_fails_a_refused_reload() {
    let executor = Arc::new(
        MockExecutor::new()
            .with_command_exists("augenrules", true)
            .with_command_program(
                "augenrules",
                CommandOutput {
                    stdout: String::new(),
                    stderr: "augenrules: failure".to_string(),
                    exit_code: 1,
                },
            )
            .with_command_program(
                "systemctl",
                CommandOutput {
                    stdout: String::new(),
                    stderr: "Failed to restart auditd.service: access denied".to_string(),
                    exit_code: 1,
                },
            )
            .with_command(
                "auditctl",
                &["-s"],
                CommandOutput {
                    stdout: "enabled 1\nfailure 1\npid 942\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            ),
    );
    let ctx = Context::with_executor(executor);

    let error = AuditHardeningPlugin::new()
        .reload_after_rollback(&ctx)
        .await
        .expect_err("an unlocked host that refused the reload has genuinely failed");

    assert!(
        error.to_string().contains("Failed to reload audit rules"),
        "the error must name the reload as the thing that failed, got: {error}"
    );
}
