#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for the crate root.
//!
//! Split out of `lib.rs`, which held these seven modules interleaved with the
//! types they exercise rather than in one block at the end: 543 lines of test
//! across 1627, not the 1369 a first measurement suggested. That measurement
//! counted from the first `#[cfg(test)]` to the end of the file, which sweeps up
//! every production item sitting between one test module and the next.
//!
//! Every module here is still a child of the crate root, so it still reaches
//! private items. `use super::*` became `use crate::*` because `super` is now
//! this file rather than the crate root.

mod compliance_framework_tests {
    use crate::*;

    #[test]
    fn from_id_accepts_every_canonical_id() {
        // The canonical list is the single source the pickers, the CLI parser and
        // this layer all build from, so a framework added to or removed from it
        // must be re-checked here rather than silently skipping this layer. The
        // count is pinned to say so: the loop below covers whatever ALL holds,
        // and an ALL that changed size is exactly the case nobody looked at.
        assert_eq!(
            ComplianceFramework::ALL.len(),
            10,
            "the canonical framework list changed size; confirm every id still parses here"
        );
        for framework in ComplianceFramework::ALL {
            assert_eq!(
                ComplianceFramework::from_id(framework.id()),
                Some(framework),
                "canonical id '{}' must parse to its framework",
                framework.id()
            );
        }
    }

    #[test]
    fn from_id_is_case_insensitive() {
        assert_eq!(
            ComplianceFramework::from_id("CIS"),
            Some(ComplianceFramework::CIS)
        );
        assert_eq!(
            ComplianceFramework::from_id("Pci-Dss"),
            Some(ComplianceFramework::PCIDSS)
        );
    }

    #[test]
    fn from_id_accepts_legacy_aliases_from_both_parsers() {
        // Union of legacy alias spellings from both old parsers
        // (crates/hardener-cli/src/commands/report.rs and
        // src-tauri/src/commands.rs); of these, only "iso" was CLI-only.
        for alias in [
            "pcidss",
            "pci",
            "iso",
            "soc-2",
            "nist800171",
            "nist-800-171",
            "fed-ramp",
        ] {
            assert!(
                ComplianceFramework::from_id(alias).is_some(),
                "CLI alias '{alias}' must still parse"
            );
        }
        // Desktop-only spelling (src-tauri/src/commands.rs, matched
        // uppercase there but from_id normalises to lowercase).
        assert_eq!(
            ComplianceFramework::from_id("iso-27001"),
            Some(ComplianceFramework::ISO27001),
            "desktop alias 'iso-27001' must still parse"
        );
    }

    #[test]
    fn from_id_rejects_unknown() {
        assert_eq!(ComplianceFramework::from_id("nonsense"), None);
        assert_eq!(ComplianceFramework::from_id(""), None);
    }
}
mod apply_change_tests {
    use crate::*;

    fn change(change_type: ChangeType, description: &str) -> Change {
        Change {
            change_description: description.to_string(),
            change_type,
            change_success: true,
            change_error: None,
        }
    }

    fn failed_change(change_type: ChangeType, description: &str) -> Change {
        Change {
            change_success: false,
            change_error: Some("nft: command failed".to_string()),
            ..change(change_type, description)
        }
    }

    /// 1 success + 4 failures + 1 skip: the mixed shape the live tour hit.
    fn mixed_result() -> ApplyResult {
        apply_result(vec![
            change(ChangeType::FirewallRule, "set default drop policy"),
            failed_change(ChangeType::FirewallRule, "add ssh allow rule"),
            failed_change(ChangeType::FirewallRule, "add loopback rule"),
            failed_change(ChangeType::FirewallRule, "add established rule"),
            failed_change(ChangeType::FirewallRule, "add icmp rule"),
            change(ChangeType::Skipped, "stateful by default"),
        ])
    }

    fn apply_result(changes: Vec<Change>) -> ApplyResult {
        ApplyResult {
            apply_plugin_id: PluginId::new("test"),
            apply_success: true,
            apply_changes: changes,
            apply_checkpoint_id: None,
            apply_error: None,
        }
    }

    #[test]
    fn applied_change_count_excludes_skipped() {
        let result = apply_result(vec![
            change(ChangeType::ConfigFile, "wrote sshd_config"),
            change(ChangeType::Skipped, "no MAC system detected"),
        ]);
        assert_eq!(result.applied_change_count(), 1);
    }

    #[test]
    fn applied_change_count_all_applied() {
        let result = apply_result(vec![
            change(ChangeType::ConfigFile, "wrote sshd_config"),
            change(ChangeType::Service, "restarted sshd"),
        ]);
        assert_eq!(result.applied_change_count(), 2);
    }

    #[test]
    fn applied_change_count_all_skipped() {
        let result = apply_result(vec![change(ChangeType::Skipped, "no MAC system detected")]);
        assert_eq!(result.applied_change_count(), 0);
    }

    #[test]
    fn applied_change_count_excludes_failures() {
        assert_eq!(mixed_result().applied_change_count(), 1);
    }

    #[test]
    fn failed_change_count_excludes_skips_and_successes() {
        assert_eq!(mixed_result().failed_change_count(), 4);
    }

    #[test]
    fn skipped_change_count_counts_only_skips() {
        assert_eq!(mixed_result().skipped_change_count(), 1);
    }

    #[test]
    fn is_skipped_reflects_change_type() {
        assert!(change(ChangeType::Skipped, "skip").is_skipped());
        assert!(!change(ChangeType::ConfigFile, "real").is_skipped());
    }

    #[test]
    fn is_checkpoint_reflects_change_type() {
        let cp = change(ChangeType::Checkpoint, "Created checkpoint for rollback");
        assert!(cp.is_checkpoint());
        assert!(!cp.is_skipped());
        assert!(!change(ChangeType::ConfigFile, "real").is_checkpoint());
    }

    /// A checkpoint entry is bookkeeping: with 3 successes and 1 failure
    /// alongside it, applied is 3 and failed is 1, never 4 or 5.
    #[test]
    fn counts_exclude_checkpoint_bookkeeping() {
        let result = apply_result(vec![
            change(ChangeType::Checkpoint, "Created checkpoint for rollback"),
            change(ChangeType::KernelParameter, "set kptr_restrict"),
            change(ChangeType::KernelParameter, "set dmesg_restrict"),
            change(ChangeType::ConfigFile, "wrote 99-hardening.conf"),
            failed_change(ChangeType::KernelParameter, "set bpf_hardened"),
        ]);
        assert_eq!(result.applied_change_count(), 3);
        assert_eq!(result.failed_change_count(), 1);
        assert_eq!(result.skipped_change_count(), 0);
    }

    /// A plugin whose only recorded action was the checkpoint hardened nothing.
    #[test]
    fn checkpoint_only_result_counts_zero_applied() {
        let result = apply_result(vec![change(
            ChangeType::Checkpoint,
            "Created checkpoint for rollback",
        )]);
        assert_eq!(result.applied_change_count(), 0);
        assert_eq!(result.failed_change_count(), 0);
        assert_eq!(result.skipped_change_count(), 0);
    }
}
mod fleet_mutation_tests {
    use crate::*;

    #[test]
    fn apply_status_deserialises_by_state_tag() {
        let validated: ApplyStatus = serde_json::from_str(
            r#"{"state":"validated","plugins":3,"would_change":5,"failed":0}"#,
        )
        .unwrap();
        assert!(matches!(
            validated,
            ApplyStatus::Validated {
                plugins: 3,
                would_change: 5,
                compliant: 0,
                failed: 0
            }
        ));
        let applied: ApplyStatus =
            serde_json::from_str(r#"{"state":"applied","ok":2,"failed":1}"#).unwrap();
        assert!(matches!(applied, ApplyStatus::Applied { ok: 2, failed: 1 }));
    }

    #[test]
    fn rollback_status_deserialises_by_state_tag() {
        let previewed: RollbackStatus =
            serde_json::from_str(r#"{"state":"previewed","checkpoints":4}"#).unwrap();
        assert!(matches!(
            previewed,
            RollbackStatus::Previewed { checkpoints: 4 }
        ));
        let nothing: RollbackStatus = serde_json::from_str(r#"{"state":"nothingtodo"}"#).unwrap();
        assert!(matches!(nothing, RollbackStatus::NothingToDo));
    }
}
mod fleet_tests {
    use crate::*;

    fn finding(severity: Severity) -> Finding {
        Finding {
            finding_category: FindingCategory::Kernel,
            finding_current_value: String::new(),
            finding_description: String::new(),
            finding_explanation: String::new(),
            finding_id: String::new(),
            finding_impact: String::new(),
            finding_recommended_value: String::new(),
            finding_remediation_steps: Vec::new(),
            finding_severity: severity,
            finding_title: String::new(),
            finding_compliance: Vec::new(),
            finding_policy_exception: None,
            finding_exception_key: None,
        }
    }

    fn result(findings: Vec<Finding>) -> ScanResult {
        ScanResult {
            scan_plugin_id: PluginId::new("test"),
            scan_success: true,
            scan_findings: findings,
            scan_unchecked: vec![],
            scan_duration_us: 0,
            scan_error: None,
        }
    }

    #[test]
    fn tallies_count_by_severity_across_results() {
        let results = vec![
            result(vec![finding(Severity::Critical), finding(Severity::High)]),
            result(vec![
                finding(Severity::High),
                finding(Severity::Low),
                finding(Severity::Info),
            ]),
        ];
        let t = SeverityTallies::from_results(&results);
        assert_eq!(t.critical, 1);
        assert_eq!(t.high, 2);
        assert_eq!(t.medium, 0);
        assert_eq!(t.low, 1);
        assert_eq!(t.info, 1);
    }
}
mod compliance_profile_tests {
    use crate::*;

    #[test]
    fn profile_serde_round_trips_both_variants() {
        for (profile, json) in [
            (ComplianceProfile::Generic, "\"generic\""),
            (ComplianceProfile::Rhel10, "\"rhel10\""),
        ] {
            assert_eq!(serde_json::to_string(&profile).unwrap(), json);
            let back: ComplianceProfile = serde_json::from_str(json).unwrap();
            assert_eq!(back, profile);
        }
    }

    #[test]
    fn profile_defaults_to_generic() {
        assert_eq!(ComplianceProfile::default(), ComplianceProfile::Generic);
    }

    #[test]
    fn profile_displays_as_lowercase() {
        assert_eq!(ComplianceProfile::Generic.to_string(), "generic");
        assert_eq!(ComplianceProfile::Rhel10.to_string(), "rhel10");
    }

    #[test]
    fn profile_parses_case_insensitively_with_alias() {
        assert_eq!(
            "Generic".parse::<ComplianceProfile>().unwrap(),
            ComplianceProfile::Generic
        );
        assert_eq!(
            "rhel10".parse::<ComplianceProfile>().unwrap(),
            ComplianceProfile::Rhel10
        );
        assert_eq!(
            "RHEL-10".parse::<ComplianceProfile>().unwrap(),
            ComplianceProfile::Rhel10
        );
    }

    #[test]
    fn profile_parse_error_lists_valid_values() {
        let err = "centos".parse::<ComplianceProfile>().unwrap_err();
        assert!(err.contains("centos"));
        assert!(err.contains("generic"));
        assert!(err.contains("rhel10"));
    }
}
mod serde_compatibility_tests {
    use crate::*;

    #[test]
    fn scan_result_deserialises_without_unchecked_field() {
        let old_json = r#"{
            "scan_plugin_id": "kernel-hardening",
            "scan_success": true,
            "scan_findings": [],
            "scan_duration_us": 42,
            "scan_error": null
        }"#;
        let result: ScanResult = serde_json::from_str(old_json).expect("old JSON must parse");
        assert!(result.scan_unchecked.is_empty());
    }

    #[test]
    fn unchecked_check_round_trips() {
        let check = UncheckedCheck {
            unchecked_check_id: "pam-minlen".to_string(),
            unchecked_title: "PAM setting: minlen".to_string(),
            unchecked_category: FindingCategory::Authentication,
            unchecked_reason: "reading /etc/security/pwquality.conf requires root".to_string(),
            unchecked_blocker: UncheckedBlocker::Privilege,
            unchecked_compliance: vec![],
        };
        let json = serde_json::to_string(&check).unwrap();
        let back: UncheckedCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(back.unchecked_check_id, check.unchecked_check_id);
    }

    /// A scan persisted before the field existed must claim nothing rather
    /// than inherit a remedy nobody recorded.
    #[test]
    fn unchecked_check_deserialises_without_the_privilege_field() {
        let old_json = r#"{
            "unchecked_check_id": "pam-minlen",
            "unchecked_title": "PAM setting: minlen",
            "unchecked_category": "Authentication",
            "unchecked_reason": "reading /etc/security/pwquality.conf requires root",
            "unchecked_compliance": []
        }"#;
        let check: UncheckedCheck = serde_json::from_str(old_json).expect("old JSON must parse");
        assert_eq!(
            check.unchecked_blocker,
            UncheckedBlocker::Unknown,
            "an absent field must not be read as a promise that sudo helps"
        );
    }

    /// The lossy direction, asserted rather than left to be discovered. A scan
    /// persisted under the previous boolean carried `unchecked_needs_privilege`,
    /// which no longer exists; serde ignores the unknown key and the new field
    /// takes its default. The old `true` is therefore dropped on purpose, since
    /// four producers were writing it without checking anything.
    #[test]
    fn a_scan_persisted_under_the_old_boolean_claims_nothing() {
        let old_json = r#"{
            "unchecked_check_id": "firewall-disabled",
            "unchecked_title": "Active firewall ruleset",
            "unchecked_category": "Network",
            "unchecked_reason": "verifying the active nftables ruleset requires root",
            "unchecked_needs_privilege": true,
            "unchecked_compliance": []
        }"#;
        let check: UncheckedCheck = serde_json::from_str(old_json).expect("old JSON must parse");
        assert_eq!(
            check.unchecked_blocker,
            UncheckedBlocker::Unknown,
            "a claim made by the field that was removed must not survive the rename"
        );
        assert_eq!(
            UncheckedTally::from_checks(&[check]).needing_privilege,
            0,
            "and it must not reach the tally that decides whether to offer sudo"
        );
    }

    fn unchecked(id: &str, reason: &str, blocker: UncheckedBlocker) -> UncheckedCheck {
        UncheckedCheck {
            unchecked_check_id: id.to_string(),
            unchecked_title: id.to_string(),
            unchecked_category: FindingCategory::Authentication,
            unchecked_reason: reason.to_string(),
            unchecked_blocker: blocker,
            unchecked_compliance: vec![],
        }
    }

    /// The roll-up must not name a cause no entry carries. Reasons sudo cannot
    /// fix are produced today: a plugin the operator disabled, a path on a
    /// filesystem with no POSIX modes, a service list that could not be read.
    /// Naming root for those sends the operator to a remedy that changes
    /// nothing, and it was seen live on a container already running as root.
    #[test]
    fn unchecked_summary_does_not_blame_root_for_a_check_root_cannot_reach() {
        let disabled = unchecked(
            "ssh-hardening-not-assessed",
            "disabled by configuration, so the controls it covers were not assessed",
            UncheckedBlocker::Environment,
        );

        let summary = unchecked_summary(&[disabled]).expect("one entry must be summarised");

        assert!(
            !summary.contains("root") && !summary.contains("sudo"),
            "a check no privilege can reach must not be summarised as needing one, got: {summary}"
        );
        assert!(
            summary.contains('1'),
            "the count must survive whatever the cause is, got: {summary}"
        );
    }

    /// The mixed run is the realistic one: a disabled plugin beside a file only
    /// root can read. Reporting either cause alone loses the other.
    #[test]
    fn unchecked_summary_separates_what_sudo_fixes_from_what_it_does_not() {
        let entries = [
            unchecked(
                "ssh-hardening-not-assessed",
                "disabled by configuration",
                UncheckedBlocker::Environment,
            ),
            unchecked(
                "pam-minlen",
                "reading /etc/security/pwquality.conf requires root",
                UncheckedBlocker::Privilege,
            ),
            unchecked(
                "pam-dcredit",
                "reading /etc/security/pwquality.conf requires root",
                UncheckedBlocker::Privilege,
            ),
        ];

        let summary = unchecked_summary(&entries).expect("three entries must be summarised");

        assert_eq!(
            summary,
            "3 check(s) could not be verified, 2 of them for want of root; \
             run with sudo for a fuller scan"
        );
    }

    /// Guard, not evidence. It discriminates nothing about the defect: the
    /// unfixed roll-up blamed root for every run, so it was already right about
    /// this one. It is here so a fix cannot buy honesty by dropping the sudo
    /// offer altogether, on the run where sudo is the whole answer.
    #[test]
    fn unchecked_summary_still_offers_sudo_when_every_check_wants_it() {
        let entries = [
            unchecked(
                "pam-minlen",
                "reading /etc/security/pwquality.conf requires root",
                UncheckedBlocker::Privilege,
            ),
            unchecked(
                "audit-rules",
                "auditctl -l requires root",
                UncheckedBlocker::Privilege,
            ),
        ];

        let summary = unchecked_summary(&entries).expect("two entries must be summarised");

        assert_eq!(
            summary,
            "2 check(s) require root; run with sudo for a full scan"
        );
    }

    /// Nothing to say is said as nothing, so a renderer cannot print an empty
    /// note beside a clean host.
    #[test]
    fn unchecked_summary_is_none_when_there_is_nothing_unchecked() {
        assert!(unchecked_summary(&[]).is_none());
    }

    /// The desktop offers a "Run with sudo" button rather than a sentence, so
    /// it needs the decision rather than the wording. A run whose unchecked
    /// entries are all beyond privilege must not get the button: pressing it
    /// runs a full privileged scan, prompts for a password through polkit, and
    /// comes back with the same count.
    #[test]
    fn a_run_privilege_cannot_help_does_not_offer_privilege() {
        let tally = UncheckedTally::from_checks(&[unchecked(
            "ssh-hardening-not-assessed",
            "disabled by configuration, so the controls it covers were not assessed",
            UncheckedBlocker::Environment,
        )]);

        assert_eq!(tally.total, 1);
        assert_eq!(tally.needing_privilege, 0);
        assert!(
            !tally.privilege_would_help(),
            "a check no privilege can reach must not be offered a privileged re-run"
        );
    }

    /// The other two directions, so the fix cannot be "never offer it".
    #[test]
    fn a_run_privilege_can_help_offers_privilege() {
        let all = UncheckedTally::from_checks(&[unchecked(
            "pam-minlen",
            "requires root",
            UncheckedBlocker::Privilege,
        )]);
        assert!(all.privilege_would_help());

        let mixed = UncheckedTally::from_checks(&[
            unchecked(
                "ssh-hardening-not-assessed",
                "disabled by configuration",
                UncheckedBlocker::Environment,
            ),
            unchecked("pam-minlen", "requires root", UncheckedBlocker::Privilege),
        ]);
        assert!(
            mixed.privilege_would_help(),
            "one reachable check is reason enough to offer the re-run"
        );

        assert!(!UncheckedTally::default().privilege_would_help());
    }

    /// The reason the boolean was replaced rather than corrected. Both of these
    /// suppress the offer, so a tally cannot tell them apart and does not need
    /// to, but they are different answers to the operator's next question and
    /// the entry itself must keep them separate. `Environment` says the host
    /// cannot answer this and a privileged re-run will not change that;
    /// `Unknown` says nobody looked. Under one boolean both were `false`, and a
    /// producer that had not looked was indistinguishable from one that had.
    #[test]
    fn environment_and_unknown_suppress_the_offer_but_stay_distinct() {
        let blocked = unchecked(
            "boot-mode",
            "/boot is on vfat",
            UncheckedBlocker::Environment,
        );
        let undetermined = unchecked(
            "audit-rules",
            "auditctl -l failed",
            UncheckedBlocker::Unknown,
        );

        assert_ne!(
            blocked.unchecked_blocker, undetermined.unchecked_blocker,
            "the entry must record which of the two it is"
        );

        let tally = UncheckedTally::from_checks(&[blocked, undetermined]);
        assert_eq!(tally.total, 2);
        assert_eq!(
            tally.needing_privilege, 0,
            "neither is reachable by privilege, so neither may be counted towards the offer"
        );
        assert!(!tally.privilege_would_help());
    }
}
mod policy_exception_tests {
    use crate::*;

    fn finding(severity: Severity, excepted: bool) -> Finding {
        Finding {
            finding_category: FindingCategory::Network,
            finding_current_value: String::new(),
            finding_description: String::new(),
            finding_explanation: String::new(),
            finding_id: "test".to_string(),
            finding_impact: String::new(),
            finding_recommended_value: String::new(),
            finding_remediation_steps: Vec::new(),
            finding_severity: severity,
            finding_title: "Test".to_string(),
            finding_compliance: Vec::new(),
            finding_policy_exception: excepted.then(FindingPolicyException::default),
            finding_exception_key: None,
        }
    }

    /// The whole point of the label: a deviation the operator documented must
    /// not read as a violation, and must not vanish either.
    #[test]
    fn a_documented_deviation_is_not_labelled_as_a_violation() {
        let excepted = finding(Severity::Critical, true);
        assert!(excepted.is_policy_excepted());
        assert_eq!(excepted.evidence_label(), POLICY_EXCEPTION_LABEL);
    }

    #[test]
    fn a_live_violation_keeps_its_severity() {
        let live = finding(Severity::Critical, false);
        assert!(!live.is_policy_excepted());
        assert_eq!(live.evidence_label(), "CRITICAL");
    }
}
mod exception_declined_tests {
    use crate::*;

    #[test]
    fn declined_line_for_a_value_mismatch_names_both_values() {
        let declined = FindingExceptionDeclined {
            exception_declined_reason: DeclineReason::ValueMismatch {
                documented: "yes".to_string(),
                observed: "prohibit-password".to_string(),
            },
            exception_reason: "legacy jump host".to_string(),
        };

        let line = exception_declined_line(&declined);

        assert!(
            line.contains("'yes'"),
            "the documented value must appear: {line}"
        );
        assert!(
            line.contains("'prohibit-password'"),
            "the observed value must appear: {line}"
        );
        assert!(
            line.contains("legacy jump host"),
            "the operator's own reason must appear so they can tell which exception this was: {line}"
        );
    }

    #[test]
    fn declined_line_for_an_expiry_names_the_date() {
        let declined = FindingExceptionDeclined {
            exception_declined_reason: DeclineReason::Expired {
                expired_on: "2026-01-01".to_string(),
            },
            exception_reason: "temporary waiver".to_string(),
        };

        let line = exception_declined_line(&declined);

        assert!(
            line.contains("2026-01-01"),
            "the expiry date must appear: {line}"
        );
        assert!(
            line.contains("temporary waiver"),
            "the operator's own reason must appear: {line}"
        );
    }
}
mod rollback_result_tests {
    use crate::*;

    #[test]
    fn reloads_ok_is_true_when_every_reload_succeeded() {
        let result = RollbackResult {
            rollback_checkpoint_id: "cp_1".to_string(),
            rollback_checkpoint_name: "before-upgrade".to_string(),
            rollback_success: true,
            rollback_files: Vec::new(),
            rollback_reloads: vec![ReloadResult {
                reload_plugin_id: "ssh-hardening".to_string(),
                reload_action: "sshd restarted".to_string(),
                reload_success: true,
                reload_error: None,
            }],
        };
        assert!(result.reloads_ok());
    }

    #[test]
    fn reloads_ok_is_false_when_any_reload_failed() {
        let result = RollbackResult {
            rollback_checkpoint_id: "cp_1".to_string(),
            rollback_checkpoint_name: "before-upgrade".to_string(),
            rollback_success: true,
            rollback_files: Vec::new(),
            rollback_reloads: vec![
                ReloadResult {
                    reload_plugin_id: "ssh-hardening".to_string(),
                    reload_action: "sshd restarted".to_string(),
                    reload_success: true,
                    reload_error: None,
                },
                ReloadResult {
                    reload_plugin_id: "audit-hardening".to_string(),
                    reload_action: "audit rules reloaded".to_string(),
                    reload_success: false,
                    reload_error: Some("augenrules exited 1".to_string()),
                },
            ],
        };
        assert!(!result.reloads_ok());
        assert!(
            result.rollback_success,
            "file restores are reported separately"
        );
    }

    /// A payload written by a binary that predates the reload field must read as
    /// "nothing failed", never as a failure.
    #[test]
    fn a_payload_without_reloads_reports_reloads_ok() {
        let json = r#"{
            "rollback_checkpoint_id": "cp_1",
            "rollback_checkpoint_name": "before-upgrade",
            "rollback_success": true,
            "rollback_files": []
        }"#;
        let result: RollbackResult = serde_json::from_str(json).expect("older payload must parse");
        assert!(result.rollback_reloads.is_empty());
        assert!(result.reloads_ok());
    }

    /// The CLI's text report and the desktop's fleet table both draw the
    /// failed half of a rollback outcome from here, so the two wordings are
    /// one string rather than two that have to be kept in step by hand.
    #[test]
    fn a_rollback_failure_label_names_the_reload_share_only_when_there_is_one() {
        assert_eq!(crate::rollback_failed_label(3, 0), "3 failed");
        assert_eq!(
            crate::rollback_failed_label(3, 2),
            "3 failed (2 due to reload)"
        );
    }
}
