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

    // The mock holds no rules file, so the file estimate (#180) is the create.
    assert_eq!(
        report.validation_report_estimated_changes,
        vec![
            format!("Add {} audit-rules", AUDIT_RULES.len()),
            format!("Create {AUDIT_RULES_PATH}"),
        ],
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

/// A backup taken on every apply and never removed is unbounded growth in
/// `/etc`, and the growth is not confined to `/etc`: the checkpoint captures
/// the whole rules directory, so each apply copies every backup that has ever
/// been taken into another checkpoint, and every rollback restores the lot.
/// Seventeen had accumulated on the development host, fourteen of them from a
/// single afternoon, and a rollback of one apply reported 24 files of which 17
/// were dead backups (#154).
///
/// Retention counts what is on disk after the copy, so the file this apply
/// just wrote is one of the survivors. The mock's `cp` writes nothing, so the
/// six seeded here stand for the state a real host reaches immediately after
/// its own copy.
///
/// Asserted on which paths `rm` was given rather than on how many, because
/// "three were removed" is also true of a prune that removed the three newest.
#[tokio::test]
async fn writing_the_rules_file_prunes_all_but_the_newest_backups() {
    let ok = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    let oldest: Vec<String> = ["20260718_090000.00000001", "20260718_091500.00000002"]
        .iter()
        .map(|stamp| format!("{AUDIT_RULES_PATH}.backup.{stamp}"))
        .collect();
    let newest: Vec<String> = [
        "20260718_093000.00000003",
        "20260810_120000.00000004",
        "20260810_120001.00000005",
    ]
    .iter()
    .map(|stamp| format!("{AUDIT_RULES_PATH}.backup.{stamp}"))
    .collect();

    let mut executor = MockExecutor::new()
        .with_file(AUDIT_RULES_PATH, "-w /etc/passwd -p wa -k identity\n")
        .with_path_exists(AUDIT_RULES_PATH, true)
        .with_command_program("cp", ok.clone())
        .with_command_program("rm", ok);
    // Seeded in an order that is neither oldest-first nor newest-first, so a
    // prune that trusted the directory's iteration order rather than sorting
    // cannot pass by luck.
    for backup in newest.iter().chain(oldest.iter()) {
        executor = executor.with_file(backup, "-w /etc/passwd -p wa -k identity\n");
    }
    let executor = Arc::new(executor);
    let ctx = Context::with_executor(executor.clone() as Arc<dyn SystemExecutor>);

    write_audit_rules_file(&ctx, "-w /etc/new -p wa -k new")
        .await
        .expect("a mock that answers any cp must let the write through")
        .expect("an existing rules file must be backed up");

    let kept_count = crate::BACKUPS_KEPT;
    let log = executor.log();
    let (_, args) = log
        .commands_executed
        .iter()
        .find(|(program, _)| program == "rm")
        .expect("a directory over the retention limit must be pruned");
    for backup in &oldest {
        assert!(
            args.iter().any(|argument| argument == backup),
            "the prune must remove the older backup {backup}, got: {args:?}"
        );
    }
    for backup in &newest {
        assert!(
            !args.iter().any(|argument| argument == backup),
            "the prune must keep the newest {kept_count} backups, \
             but it removed {backup}: {args:?}"
        );
    }
}

/// The rules file itself, and any other file the audit package ships in that
/// directory, are not backups and must survive a prune. Only the names this
/// plugin generates are its to remove.
///
/// The same fixture proves the count guard: five files sit in the directory
/// and only two of them are backups, so a prune that counted entries rather
/// than backups would be over its limit and delete something.
#[tokio::test]
async fn the_prune_removes_only_this_plugin_s_own_backups() {
    let ok = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    let executor = Arc::new(
        MockExecutor::new()
            .with_file(AUDIT_RULES_PATH, "-w /etc/passwd -p wa -k identity\n")
            .with_path_exists(AUDIT_RULES_PATH, true)
            .with_file(
                &format!("{AUDIT_RULES_PATH}.backup.20260718_090000.00000001"),
                "old\n",
            )
            .with_file(
                &format!("{AUDIT_RULES_PATH}.backup.20260718_091500.00000002"),
                "older\n",
            )
            .with_file(&format!("{AUDIT_RULES_DIR}/audit.rules"), "-D\n")
            .with_file(
                &format!("{AUDIT_RULES_DIR}/30-ospp-v42.rules"),
                "-a never\n",
            )
            .with_command_program("cp", ok.clone())
            .with_command_program("rm", ok),
    );
    let ctx = Context::with_executor(executor.clone() as Arc<dyn SystemExecutor>);

    write_audit_rules_file(&ctx, "-w /etc/new -p wa -k new")
        .await
        .expect("a mock that answers any cp must let the write through")
        .expect("an existing rules file must be backed up");

    let log = executor.log();
    assert!(
        !log.commands_executed
            .iter()
            .any(|(program, _)| program == "rm"),
        "a directory holding fewer backups than the retention limit must not be \
         pruned at all, but rm ran: {:?}",
        log.commands_executed
    );
}

/// The two finding-type tables must partition, with `not_installed` the only
/// member on the presence side.
///
/// `AUDIT_POST_INSTALL_FINDING_TYPES` is maintained by hand as a subset of
/// `AUDIT_FINDING_TYPES`, and it decides which controls the not-installed arm
/// reports unchecked. A fifth post-install id added to the wider table alone
/// would map a control that `coverage()` declares assessed and that nothing
/// then records as unevaluable, which is exactly the construction that made
/// CIS 4.1.1.2 pass on a host with no auditd (#166).
#[test]
fn audit_finding_type_tables_partition() {
    for finding_type in AUDIT_POST_INSTALL_FINDING_TYPES {
        assert!(
            AUDIT_FINDING_TYPES.contains(finding_type),
            "{finding_type} is declared a post-install finding but is not an \
             audit finding type at all, so coverage() never sees it"
        );
    }

    let presence: Vec<&&str> = AUDIT_FINDING_TYPES
        .iter()
        .filter(|t| !AUDIT_POST_INSTALL_FINDING_TYPES.contains(t))
        .collect();

    assert_eq!(
        presence,
        vec![&"not_installed"],
        "every audit finding type is either about auditd being installed or \
         about the state of an auditd that is. A new id on the presence side \
         needs its mappings answered by the not_installed finding; one on the \
         post-install side belongs in AUDIT_POST_INSTALL_FINDING_TYPES so the \
         not-installed arm reports it unchecked"
    );
}

/// Every control this plugin declares assessed must have a route to being
/// reported unchecked, or be one a finding answers on every host. See
/// [`crate::tests::assert_every_covered_control_is_reportable`] for why.
///
/// Nothing is excused. The four ids that used to be (`3.3.1`, `4.1.1.1`,
/// `AU-2(a)`, `OL08-00-030180`) are the ones `not_installed` maps and no
/// post-install finding does, and they were excused because the probe resolved
/// a failure to `false`, so the plugin raised `not_installed` on a host it
/// could not read and a finding fails a control rather than passing it. That
/// was fail-closed rather than wrong, which is why it survived; it was also
/// the plugin telling an operator a package was missing when what had actually
/// happened was that it could not look. The probe now reports
/// [`AuditdPresence::Indeterminate`] instead, which reaches these four through
/// an unchecked entry, so the excuses are retired rather than merely reworded.
///
/// The unchecked entries come from a real scan rather than a list composed
/// here, for the reason given on the MAC plugin's copy of this test:
/// hand-building them restates `coverage()`'s own definition and survives the
/// production arm being deleted.
#[tokio::test]
async fn every_covered_audit_control_can_be_reported_unchecked() {
    // The probe fails, which is the arm that reports both the presence check
    // and the post-install checks unchecked. The absent arm reaches only the
    // post-install half, and is asserted separately below.
    let executor = MockExecutor::new().with_command_exists_error("auditd");
    let scanned = AuditHardeningPlugin::new()
        .scan(
            &Context::with_executor(Arc::new(executor)),
            &PluginConfig::default(),
        )
        .await
        .expect("a failed probe is reported, not returned as an error");

    crate::tests::assert_every_covered_control_is_reportable(
        "audit",
        &coverage(),
        &scanned.scan_unchecked,
        &[],
    );
}

/// A failed probe must not be reported as an absent package.
///
/// The two states are one keystroke apart in the source and worlds apart for
/// an operator: one says "install auditd", the other says "this scan could not
/// tell". Asserting only that the controls reach manual review would pass
/// against a build that raised the `not_installed` finding as well, so the
/// absence of that finding is asserted directly.
#[tokio::test]
async fn a_failed_probe_is_not_reported_as_an_absent_auditd() {
    let executor = MockExecutor::new().with_command_exists_error("auditd");
    let scanned = AuditHardeningPlugin::new()
        .scan(
            &Context::with_executor(Arc::new(executor)),
            &PluginConfig::default(),
        )
        .await
        .expect("a failed probe is reported, not returned as an error");

    assert!(
        !scanned
            .scan_findings
            .iter()
            .any(|finding| finding.finding_id == "audit_not_installed"),
        "a scan that could not run the probe claimed auditd was not installed"
    );

    let presence = scanned
        .scan_unchecked
        .iter()
        .find(|entry| entry.unchecked_check_id == "audit_not_installed")
        .expect("the presence check is reported unchecked when the probe fails");
    assert!(
        presence.unchecked_reason.contains("mock probe error"),
        "the unchecked entry drops the probe's own reason: {}",
        presence.unchecked_reason
    );
}

/// An auditd that is genuinely absent still reports the post-install checks
/// unchecked. This is #166: the `not_installed` finding answers whether the
/// package is there and nothing else, and without this entry the generator
/// read four assessed controls carrying no finding and passed them on the
/// absence alone.
#[tokio::test]
async fn an_absent_auditd_still_reports_the_post_install_checks_unchecked() {
    // Nothing registered, so `command_exists("auditd")` answers false rather
    // than failing, which is the absent arm.
    let scanned = AuditHardeningPlugin::new()
        .scan(
            &Context::with_executor(Arc::new(MockExecutor::new())),
            &PluginConfig::default(),
        )
        .await
        .expect("an absent auditd is not an error");

    assert!(
        scanned
            .scan_findings
            .iter()
            .any(|finding| finding.finding_id == "audit_not_installed"),
        "an absent auditd did not raise the finding that says so"
    );
    assert!(
        scanned
            .scan_unchecked
            .iter()
            .any(|entry| entry.unchecked_check_id == "auditd-post-install"),
        "an absent auditd left the service and rule checks reading as compliant"
    );
}

// A rollback ends with the host as it was, and `augenrules` does not know
// that: it writes a compiled rule set whenever it runs, so the reload a
// rollback performs puts back whichever of the two compiled files the restore
// had just removed. On the five distributions whose audit package ships a
// compiled rule set the file exists either way and nothing looked wrong. Arch
// ships none, and a rollback there left an /etc/audit/audit.rules the host
// never had, which is what the cross-distribution suite caught.
//
// Tested from data rather than through the plugin. A mock executor cannot make
// `augenrules` create a file part-way through a call, so driving this through
// `reload_after_rollback` would only ever exercise the case where nothing
// changed, which is the half that was never in doubt.

#[test]
fn a_compiled_file_the_reload_created_is_removed() {
    let before = [
        (AUDIT_COMPILED_RULES, false),
        (AUDIT_COMPILED_RULES_PREV, false),
    ];
    let after = [
        (AUDIT_COMPILED_RULES, true),
        (AUDIT_COMPILED_RULES_PREV, false),
    ];

    assert_eq!(
        paths_the_reload_created(&before, &after),
        vec![AUDIT_COMPILED_RULES],
        "the reload created the compiled rule set on a host that had none"
    );
}

#[test]
fn a_compiled_file_the_distribution_ships_is_left_alone() {
    // The dangerous direction. Removing a compiled rule set the audit package
    // ships would take the host further from its pre-apply state than the
    // rollback found it, which is the opposite of the point.
    let before = [
        (AUDIT_COMPILED_RULES, true),
        (AUDIT_COMPILED_RULES_PREV, false),
    ];
    let after = [
        (AUDIT_COMPILED_RULES, true),
        (AUDIT_COMPILED_RULES_PREV, false),
    ];

    assert!(
        paths_the_reload_created(&before, &after).is_empty(),
        "a file present before the reload is not this function's to remove"
    );
}

#[test]
fn a_prev_copy_the_reload_wrote_is_removed_too() {
    // `augenrules` writes a fresh .prev whenever it has a compiled file to
    // displace, so a rollback on a host that had one and no .prev ends with a
    // .prev the apply's reload never left either.
    let before = [
        (AUDIT_COMPILED_RULES, true),
        (AUDIT_COMPILED_RULES_PREV, false),
    ];
    let after = [
        (AUDIT_COMPILED_RULES, true),
        (AUDIT_COMPILED_RULES_PREV, true),
    ];

    assert_eq!(
        paths_the_reload_created(&before, &after),
        vec![AUDIT_COMPILED_RULES_PREV],
        "the .prev the reload wrote is as much its doing as the compiled file"
    );
}

#[test]
fn a_file_the_reload_removed_is_not_resurrected() {
    // The function only ever names things to delete. A path that went away
    // across the reload is not its business, and must not appear in the list
    // that feeds `rm`.
    let before = [
        (AUDIT_COMPILED_RULES, true),
        (AUDIT_COMPILED_RULES_PREV, true),
    ];
    let after = [
        (AUDIT_COMPILED_RULES, false),
        (AUDIT_COMPILED_RULES_PREV, false),
    ];

    assert!(
        paths_the_reload_created(&before, &after).is_empty(),
        "a path that disappeared across the reload is not one the reload created"
    );
}

/// The delete and perm-mod families are the two that fire on every build
/// and every browser cache sweep, and the shape that let them saturate the
/// kernel backlog was a b32 mirror plus no scope. Pinning the shape here
/// keeps a benchmark-driven "add the 32-bit rule back" from reintroducing
/// the flood without a test going red.
#[test]
fn the_high_volume_families_are_64_bit_only_and_scoped_to_users() {
    let high_volume: Vec<_> = AUDIT_RULES
        .iter()
        .filter(|r| matches!(r.audit_rule_category, "delete" | "perm-mod"))
        .collect();
    assert_eq!(
        high_volume.len(),
        4,
        "three perm-mod rules and one delete rule; a fifth is a mirror creeping back"
    );
    for rule in high_volume {
        let content = rule.audit_rule_content;
        assert!(
            content.contains("arch=b64") && !content.contains("arch=b32"),
            "{content}: high-volume rules have no 32-bit mirror"
        );
        assert!(
            content.contains("-F auid>=1000 -F auid!=unset"),
            "{content}: high-volume rules carry the CIS user scope"
        );
    }
}

/// The backlog prelude is what keeps a burst from becoming a lost-event
/// counter, so it has to be in the file the apply writes and ahead of the
/// first rule, where augenrules and `auditctl -R` both expect control
/// options.
#[tokio::test]
async fn the_written_rules_open_with_the_backlog_prelude() {
    let ok = |stdout: &str| CommandOutput {
        stdout: stdout.to_string(),
        stderr: String::new(),
        exit_code: 0,
    };
    let executor = Arc::new(
        MockExecutor::new()
            .with_command_exists("auditd", true)
            .with_command_exists("augenrules", true)
            .with_command("systemctl", &["is-enabled", "auditd"], ok("enabled\n"))
            .with_command("systemctl", &["is-active", "auditd"], ok("active\n"))
            .with_command("chmod", &[AUDIT_RULES_MODE, AUDIT_RULES_PATH], ok(""))
            .with_command("augenrules", &["--load"], ok(""))
            .with_directory(AUDIT_RULES_DIR),
    );
    let mut ctx = Context::with_executor(executor.clone());

    AuditHardeningPlugin::new()
        .apply(&mut ctx, &PluginConfig::default())
        .await
        .expect("audit apply should not error");

    let log = executor.log();
    let (_, written) = log
        .files_written
        .iter()
        .find(|(path, _)| path == Path::new(AUDIT_RULES_PATH))
        .expect("the apply writes the rules file");
    let prelude_at = written
        .find(AUDIT_BACKLOG_PRELUDE)
        .expect("the written rules carry the backlog prelude");
    let first_rule_at = written.find("\n-").expect("the written rules carry a rule");
    assert!(
        prelude_at < first_rule_at,
        "the prelude must precede the first rule, got:\n{written}"
    );
}

/// The host #180 was measured on: auditd installed, enabled and running, and
/// every rule already loaded, so the category count has nothing to add and
/// the rules file is the only estimate left to make.
fn validate_mock_with_every_rule_loaded() -> MockExecutor {
    let ok = |stdout: &str| CommandOutput {
        stdout: stdout.to_string(),
        stderr: String::new(),
        exit_code: 0,
    };
    let loaded: String = AUDIT_RULES
        .iter()
        .map(|rule| format!("{}\n", rule.audit_rule_content))
        .collect();
    MockExecutor::new()
        .with_command_exists("auditd", true)
        .with_command("systemctl", &["is-enabled", "auditd"], ok("enabled\n"))
        .with_command("systemctl", &["is-active", "auditd"], ok("active\n"))
        .with_command("auditctl", &["-l"], ok(&loaded))
}

async fn validate_estimates(mock: MockExecutor) -> Vec<String> {
    let ctx = Context::with_executor(Arc::new(mock));
    AuditHardeningPlugin::new()
        .validate(&ctx, &PluginConfig::default())
        .await
        .expect("validate must not error")
        .validation_report_estimated_changes
}

/// #180. The apply compares the whole file and rewrites on any difference,
/// while the dry-run counted loaded categories and saw nothing to do. The
/// file here differs from the rendered one in the prelude only, with every
/// category loaded, which is the exact state the issue was measured in.
#[tokio::test]
async fn validate_estimates_a_rewrite_when_only_the_prelude_differs() {
    let (desired, _) = rendered_rules_file(&PluginConfig::default());
    let stale = desired.replace(AUDIT_BACKLOG_PRELUDE, "");
    assert_ne!(
        stale, desired,
        "the fixture must differ from the rendered file"
    );
    let estimates = validate_estimates(
        validate_mock_with_every_rule_loaded().with_file(AUDIT_RULES_PATH, &stale),
    )
    .await;
    assert_eq!(estimates, vec![format!("Rewrite {AUDIT_RULES_PATH}")]);
}

/// The green half: a file that already matches must estimate nothing, or the
/// test above would pass against a validate that always says "rewrite".
#[tokio::test]
async fn validate_estimates_nothing_when_the_rules_file_matches() {
    let (desired, _) = rendered_rules_file(&PluginConfig::default());
    let estimates = validate_estimates(
        validate_mock_with_every_rule_loaded().with_file(AUDIT_RULES_PATH, &desired),
    )
    .await;
    assert!(estimates.is_empty(), "{estimates:?}");
}

/// A first apply creates the file; the preview says so in that word.
#[tokio::test]
async fn validate_estimates_a_create_when_the_rules_file_is_absent() {
    let estimates = validate_estimates(validate_mock_with_every_rule_loaded()).await;
    assert_eq!(estimates, vec![format!("Create {AUDIT_RULES_PATH}")]);
}

/// The apply fails toward "differs" when the file cannot be read, so the
/// preview estimates the rewrite the apply will make and names why it could
/// not compare, rather than estimating nothing.
#[tokio::test]
async fn validate_names_the_reason_when_the_rules_file_cannot_be_read() {
    let estimates = validate_estimates(
        validate_mock_with_every_rule_loaded()
            .with_path_exists(AUDIT_RULES_PATH, true)
            .with_read_permission_denied(AUDIT_RULES_PATH),
    )
    .await;
    assert_eq!(estimates.len(), 1, "{estimates:?}");
    assert!(
        estimates[0].starts_with(&format!("Rewrite {AUDIT_RULES_PATH}"))
            && estimates[0].contains("could not be read"),
        "{estimates:?}"
    );
}
