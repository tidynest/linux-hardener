#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`batch`](super).
//!
//! Split out of `commands/batch.rs`. This file sits in the `batch/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::commands::batch` and every import carried
//! across unchanged, private items included.
//!
//! 1671 test lines across 70 tests, the largest inline block anywhere in the workspace and the reason this crate was left until last.

use super::*;
use hardener_common::types::{ComplianceFramework, ComplianceMapping, FindingCategory, Severity};
use hardener_compliance::Scenario;
use hardener_core::ValidationReport;
use hardener_types::{DivergenceState, ExceptionOutcome, RollbackDivergence};

/// Every `batch` subcommand accepted the global `--config` flag and threw
/// it away, so a fleet was assessed and hardened against whatever config
/// the controller happened to have on disk, never the one the operator
/// named on the command line.
#[test]
fn batch_honours_an_explicit_config_path() {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    writeln!(file, "[global]\ndisabled_plugins = [\"ssh-hardening\"]").unwrap();

    // `writes` is the writing verb's answer, so this covers the arm a fleet
    // `apply --execute` takes: a named config that loads is used, not refused.
    let config = load_batch_config(Some(&file.path().to_path_buf()), true, true);

    assert!(
        !config.is_plugin_enabled("ssh-hardening"),
        "the config named by --config must be the one the fleet is judged against"
    );
}

/// Fleet scan and report were pinned to the compiled-in defaults, so a
/// fleet was assessed against the raw baseline and then hardened to the
/// operator's actual policy: the two verbs disagreed about what compliant
/// even meant.
#[tokio::test]
async fn a_remote_host_is_scanned_against_the_config_it_is_given() {
    use hardener_core::MockExecutor;
    let mut config = HardenerConfig::default();
    config.ssh.enabled = Some(false);

    let outcome = scan_with_executor(
        "h".into(),
        "u@h:22".into(),
        "u@h:22".into(),
        Arc::new(MockExecutor::new()),
        None,
        &config,
    )
    .await;

    let HostStatus::Scanned { unchecked, .. } = outcome.status else {
        panic!("a mock executor should yield a Scanned outcome");
    };
    // Disabled, so it never ran. Pinned to the defaults it would have run
    // and failed against the bare mock, reported as an incomplete scan.
    assert!(
        unchecked
            .iter()
            .any(|u| u.unchecked_check_id == "ssh-hardening-not-assessed"),
        "a plugin the config disables must be reported as unassessed: {:?}",
        unchecked
            .iter()
            .map(|u| u.unchecked_check_id.as_str())
            .collect::<Vec<_>>()
    );
}

/// A host where the config disabled every selected plugin applied nothing,
/// and "0 ok, 0 failed" is how a fleet row spells complete success. The
/// single-host `apply` refuses this situation outright, so the fleet row
/// has to carry it as an error rather than a tidy pair of zeroes.
#[test]
fn a_host_whose_config_disabled_every_plugin_is_not_a_clean_apply() {
    let result = super::super::apply::ApplyHostResult {
        results: vec![],
        validation_reports: vec![],
        had_failure: false,
        skipped: vec![PluginId::new("ssh-hardening")],
    };

    match status_from_result(true, &result) {
        ApplyStatus::Failed { error } => assert!(
            error.contains("ssh-hardening"),
            "the error must name what was skipped: {error}"
        ),
        other => panic!("a run that applied nothing must not report success: {other:?}"),
    }
}

/// One report, one host, two verbs, one answer.
///
/// `apply --dry-run` and `batch apply --dry-run` ask the same question of
/// the same `ValidationReport` and used to answer it differently: the
/// single-host path fails a dry run on Critical and High only, calling
/// anything lower advisory precisely so a note cannot become a non-zero
/// exit, while the fleet path counted any issue at all. A Medium note, of
/// the kind PAM layer drift now produces on every drifted host, therefore
/// exited 0 through one verb and 1 through the other.
///
/// Asserted against the single-host rule rather than against a literal, so
/// the two cannot drift apart again by someone changing one of them.
#[test]
fn a_severity_the_single_host_dry_run_calls_advisory_is_not_a_fleet_failure() {
    for severity in [Severity::Medium, Severity::Low, Severity::Info] {
        let report = ValidationReport {
            validation_report_plugin_id: PluginId::new("pam-hardening"),
            validation_report_is_valid: false,
            validation_report_issues: vec![hardener_core::ValidationIssue {
                validation_issue_severity: severity,
                validation_issue_config_key: None,
                validation_issue_message: "/etc/login.defs masks 2 key(s)".to_string(),
            }],
            validation_report_estimated_changes: vec![],
            validation_report_compliant_count: 0,
            validation_report_exceptions: vec![],
        };
        let result = super::super::apply::ApplyHostResult {
            results: vec![],
            validation_reports: vec![report],
            had_failure: false,
            skipped: vec![],
        };

        match status_from_result(false, &result) {
            ApplyStatus::Validated { failed, .. } => assert_eq!(
                failed, 0,
                "{severity:?} is advisory to the single-host dry run, so the fleet \
                 row must not count it as a failed validation"
            ),
            other => panic!("a dry run must render as Validated: {other:?}"),
        }
    }
}

/// The other direction, so the fix cannot be "never count anything".
#[test]
fn a_severity_the_single_host_dry_run_blocks_on_is_a_fleet_failure() {
    for severity in [Severity::High, Severity::Critical] {
        let report = ValidationReport {
            validation_report_plugin_id: PluginId::new("ssh-hardening"),
            validation_report_is_valid: false,
            validation_report_issues: vec![hardener_core::ValidationIssue {
                validation_issue_severity: severity,
                validation_issue_config_key: None,
                validation_issue_message: "Failed to read /etc/ssh/sshd_config".to_string(),
            }],
            validation_report_estimated_changes: vec![],
            validation_report_compliant_count: 0,
            validation_report_exceptions: vec![],
        };
        let result = super::super::apply::ApplyHostResult {
            results: vec![],
            validation_reports: vec![report],
            had_failure: false,
            skipped: vec![],
        };

        match status_from_result(false, &result) {
            ApplyStatus::Validated { failed, .. } => assert_eq!(
                failed, 1,
                "{severity:?} fails the single-host dry run, so the fleet row must \
                 count it too"
            ),
            other => panic!("a dry run must render as Validated: {other:?}"),
        }
    }
}

// assertions-in-helper: asserts nothing by design. This is the printing half
// of the renderers' coverage, not a test: it renders all four verbs to stdout
// for a human to look at colour and alignment, which no assertion can judge.
// What each renderer must *say* is asserted elsewhere in this same file:
//   render_text          -> text_render_has_rollup,
//                           text_render_scanned_section_shows_counts,
//                           text_render_unchecked_line_only_when_nonzero,
//                           text_render_failed_row_shows_error
//   render_report_text   -> report_text_render_has_sections_and_rollup
//   render_apply_text    -> render_apply_text_sections_and_summary,
//                           render_apply_text_validation_states
//   render_rollback_text -> render_rollback_text_sections_and_summary,
//                           render_rollback_text_partial_and_nothing_to_do,
//                           render_rollback_text_names_a_reload_failure_separately_from_a_file_failure
// so the exemption removes no coverage. The names are written out rather than
// globbed because a grep for this marker is meant to land on tests that exist:
// the previous wording pointed at render_text_* and render_report_*, and
// neither prefix has ever matched a test in this file.
// It is `#[ignore]`d and never runs in a suite.
#[test]
#[ignore = "visual eyeball helper, run with --ignored --nocapture"]
fn eyeball_render_all_verbs() {
    colored::control::set_override(true);
    let scan = render_text(&[
        scanned_named(
            "web-01",
            SeverityCounts {
                critical: 7,
                high: 13,
                medium: 16,
                low: 2,
            },
        ),
        failed_named("cache"),
    ]);
    let report = render_report_text(&[
        assessed_report("web-01", vec![posture(18), posture(0)]),
        failed_report("cache"),
    ]);
    let mk = |name: &str, status| ApplyOutcome {
        name: name.into(),
        target: format!("root@{name}:22"),
        status,
    };
    let apply = render_apply_text(&[
        mk("web-01", ApplyStatus::Applied { ok: 5, failed: 0 }),
        mk("db-02", ApplyStatus::Applied { ok: 3, failed: 2 }),
        mk(
            "cache",
            ApplyStatus::Failed {
                error: "connection refused".into(),
            },
        ),
    ]);
    let rollback = render_rollback_text(&[
        ro(RollbackStatus::Previewed { checkpoints: 2 }),
        ro(RollbackStatus::NothingToDo),
    ]);
    println!(
        "--- scan ---\n{scan}\n--- report ---\n{report}\n--- apply ---\n{apply}\n--- rollback ---\n{rollback}"
    );
    colored::control::unset_override();
}

fn ro(status: RollbackStatus) -> RollbackOutcome {
    RollbackOutcome {
        name: "n".to_string(),
        target: "t".to_string(),
        status,
    }
}

#[test]
fn strip_ansi_removes_colour_escapes_and_keeps_text() {
    // Bold-cyan + reset around the name, multi-parameter and plain runs.
    let coloured =
        "==== \x1b[1;36mweb-01\x1b[0m  u@web-01:22 ====\n  status:    \x1b[32mok\x1b[0m\n";
    let plain = strip_ansi(coloured);
    assert_eq!(
        plain, "==== web-01  u@web-01:22 ====\n  status:    ok\n",
        "escapes stripped, text and layout intact"
    );
    assert!(!plain.contains('\x1b'), "no ESC bytes remain");
    // A string with no escapes passes through byte-identical (JSON path).
    let json = "{\n  \"hosts\": []\n}";
    assert_eq!(strip_ansi(json), json);
}

#[test]
fn write_output_saves_colour_free_file() {
    use tempfile::TempDir;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("fleet.txt");
    let path = path.to_str().unwrap();
    write_output(path, "\x1b[1;36mweb-01\x1b[0m  \x1b[31mFAILED\x1b[0m\n").unwrap();
    let saved = std::fs::read_to_string(path).unwrap();
    assert_eq!(
        saved, "web-01  FAILED\n",
        "--output files carry no ANSI escapes"
    );
}

#[test]
fn rollback_exit_code_follows_precedence() {
    assert_eq!(
        rollback_exit_code(&[ro(RollbackStatus::Previewed { checkpoints: 3 })]),
        0
    );
    assert_eq!(rollback_exit_code(&[ro(RollbackStatus::NothingToDo)]), 0);
    assert_eq!(
        rollback_exit_code(&[ro(RollbackStatus::RolledBack {
            restored: 2,
            failed: 0,
            reload_failed: 0,
            diverged: 0
        })]),
        0
    );
    assert_eq!(
        rollback_exit_code(&[ro(RollbackStatus::RolledBack {
            restored: 1,
            failed: 1,
            reload_failed: 0,
            diverged: 0
        })]),
        1
    );
    assert_eq!(
        rollback_exit_code(&[ro(RollbackStatus::Failed {
            error: "x".to_string()
        })]),
        2
    );
    assert_eq!(
        rollback_exit_code(&[
            ro(RollbackStatus::RolledBack {
                restored: 0,
                failed: 1,
                reload_failed: 0,
                diverged: 0
            }),
            ro(RollbackStatus::Failed {
                error: "x".to_string()
            }),
        ]),
        2
    );
}

#[test]
fn render_rollback_text_sections_and_summary() {
    colored::control::set_override(false);
    let text = render_rollback_text(&[
        ro(RollbackStatus::Previewed { checkpoints: 2 }),
        ro(RollbackStatus::Failed {
            error: "down".to_string(),
        }),
    ]);
    assert!(
        text.contains("==== n"),
        "host header names the host: {text}"
    );
    assert!(text.contains("  t "), "header carries the target: {text}");
    assert!(
        text.contains("status:    previewed"),
        "preview status line: {text}"
    );
    assert!(
        text.contains("would restore 2 checkpoint(s)"),
        "preview result: {text}"
    );
    assert!(text.contains("status:    FAILED"), "failed status: {text}");
    assert!(text.contains("error:     down"), "error line: {text}");
    assert!(
        text.contains("---\n2 host(s): 1 previewed, 1 failed"),
        "summary footer omits zero categories: {text}"
    );
}

#[test]
fn render_rollback_text_partial_and_nothing_to_do() {
    colored::control::set_override(false);
    let text = render_rollback_text(&[
        ro(RollbackStatus::RolledBack {
            restored: 1,
            failed: 1,
            reload_failed: 0,
            diverged: 0,
        }),
        ro(RollbackStatus::NothingToDo),
    ]);
    assert!(
        text.contains("status:    partially rolled back"),
        "partial restore is flagged: {text}"
    );
    assert!(text.contains("1 restored, 1 failed"), "counts: {text}");
    assert!(
        text.contains("nothing to roll back"),
        "nothing-to-do host says so: {text}"
    );
    assert!(
        text.contains("2 host(s): 1 rolled back, 1 nothing to do"),
        "summary footer: {text}"
    );
}

/// A checkpoint whose files never came back and a checkpoint whose files came
/// back but whose plugin refused to reload them are both "1 failed" by the
/// per-checkpoint counter, but they are different problems for the operator:
/// one means "the restore did not happen", the other means "the restore
/// happened but the service is still running the old configuration". The
/// fleet row must say which one it is, the way the single-host `rollback`
/// command already does via `FailureReason`.
#[test]
fn render_rollback_text_names_a_reload_failure_separately_from_a_file_failure() {
    colored::control::set_override(false);

    let file_failure = render_rollback_text(&[ro(RollbackStatus::RolledBack {
        restored: 2,
        failed: 1,
        reload_failed: 0,
        diverged: 0,
    })]);
    assert!(
        file_failure.contains("2 restored, 1 failed"),
        "plain counts: {file_failure}"
    );
    assert!(
        !file_failure.contains("reload"),
        "a restore failure with no reload involved must not mention reload: {file_failure}"
    );

    let reload_failure = render_rollback_text(&[ro(RollbackStatus::RolledBack {
        restored: 2,
        failed: 1,
        reload_failed: 1,
        diverged: 0,
    })]);
    assert!(
        reload_failure.contains("2 restored, 1 failed") && reload_failure.contains("reload"),
        "a reload failure must be named rather than folded silently into the same \
         count as a file failure: {reload_failure}"
    );
    assert_ne!(
        file_failure, reload_failure,
        "the two failure kinds must render distinguishably"
    );
}

/// A checkpoint that fails both its file restore and its reload must still
/// be counted as a reload failure: the service is left on the old
/// configuration exactly as it is when only the reload fails, and an
/// operator reading `reload_failed: 0` on a checkpoint that also failed to
/// restore would wrongly conclude no service is stuck on stale config.
#[test]
fn classify_rollback_outcome_counts_reload_failure_in_every_failing_arm() {
    assert_eq!(classify_rollback_outcome(true, true), (true, false, false));
    assert_eq!(classify_rollback_outcome(true, false), (false, true, true));
    assert_eq!(classify_rollback_outcome(false, true), (false, true, false));
    assert_eq!(
        classify_rollback_outcome(false, false),
        (false, true, true),
        "both the file restore and the reload failed - reload_failed must still be set"
    );
}

#[test]
fn render_rollback_json_tags_state() {
    let json = render_rollback_json(&[ro(RollbackStatus::RolledBack {
        restored: 2,
        failed: 0,
        reload_failed: 0,
        diverged: 0,
    })]);
    assert!(json.contains("\"state\": \"rolledback\""), "json: {json}");
}

#[test]
fn pre_apply_names_maps_ids_to_checkpoint_names() {
    let ids = vec![
        PluginId::new("ssh-hardening"),
        PluginId::new("kernel-hardening"),
    ];
    assert_eq!(
        pre_apply_names(&ids),
        vec![
            "ssh-hardening-pre-apply".to_string(),
            "kernel-hardening-pre-apply".to_string(),
        ]
    );
}

#[test]
fn pre_apply_names_covers_every_registered_plugin() {
    // Guards the writer<->reader naming contract: rollback derives each
    // plugin's checkpoint name as `{plugin_id}-pre-apply`, which every
    // plugin's apply path must honour (see create_checkpoint_for_apply).
    // Regression for the services plugin, whose id (`service-minimisation`)
    // does not follow the `<x>-hardening` shape and once mismatched its
    // checkpoint name (`services-hardening-pre-apply`), making rollback a
    // silent no-op for it.
    let registry = hardener_plugins::create_plugin_registry();
    let ids: Vec<PluginId> = registry
        .list()
        .unwrap_or_default()
        .iter()
        .map(|m| m.plugin_id.clone())
        .collect();
    assert!(!ids.is_empty(), "registry should list plugins");
    let names = pre_apply_names(&ids);
    for (id, name) in ids.iter().zip(&names) {
        assert_eq!(name, &format!("{}-pre-apply", id.as_str()));
    }
    assert!(
        names.iter().any(|n| n == "service-minimisation-pre-apply"),
        "services plugin must be covered by rollback selection: {names:?}"
    );
}

fn posture(failing: usize) -> FrameworkPosture {
    FrameworkPosture {
        framework: "CIS".into(),
        score: 90.0,
        passing: 10,
        failing,
        manual_review: 2,
        not_applicable: 0,
        total: 12 + failing,
    }
}
fn assessed_report(name: &str, frameworks: Vec<FrameworkPosture>) -> HostReport {
    HostReport {
        name: name.into(),
        target: format!("u@{name}:22"),
        profile: ComplianceProfile::Generic,
        status: HostReportStatus::Assessed { frameworks },
    }
}
fn failed_report(name: &str) -> HostReport {
    HostReport {
        name: name.into(),
        target: format!("u@{name}:22"),
        profile: ComplianceProfile::Generic,
        status: HostReportStatus::Failed {
            error: "refused".into(),
        },
    }
}

fn report_config_server() -> ReportConfig {
    ReportConfig {
        scenario: Scenario::Server,
        formats: vec![],
        output_dir: None,
        profile: ComplianceProfile::default(),
    }
}

#[test]
fn host_report_assesses_scanned_and_passes_failures_through() {
    let generator = ReportGenerator::new(
        report_config_server(),
        hardener_plugins::compliance_coverage(),
    );

    // A failed host is carried through untouched (no generator call).
    let failed = host_report(failed(), &generator);
    assert!(matches!(failed.status, HostReportStatus::Failed { .. }));

    // A scanned host (empty findings) is assessed: every framework posture has
    // coherent counts that sum to its total.
    let scanned = HostOutcome {
        name: "web-01".into(),
        target: "u@web-01:22".into(),
        profile: ComplianceProfile::Generic,
        status: HostStatus::Scanned {
            counts: SeverityCounts::default(),
            findings: vec![],
            unchecked: vec![],
        },
    };
    let report = host_report(scanned, &generator);
    match report.status {
        HostReportStatus::Assessed { frameworks } => {
            assert!(!frameworks.is_empty(), "server scenario yields frameworks");
            for f in &frameworks {
                assert_eq!(
                    f.passing + f.failing + f.manual_review + f.not_applicable,
                    f.total,
                    "posture counts sum to total",
                );
            }
        }
        HostReportStatus::Failed { .. } => panic!("scanned host should be assessed"),
    }
}

#[test]
fn host_report_treats_unchecked_covered_control_as_manual_review_not_pass() {
    // STIG has no curated catalogue, so with a single-mapping coverage set
    // the resulting report has exactly one control: whatever the pam-minlen
    // check covers. This isolates the assertion from the curated CIS/ISO
    // catalogues, which always carry unrelated ManualReview entries.
    let stig_mapping = ComplianceMapping {
        compliance_framework: ComplianceFramework::STIG,
        compliance_control_id: "RHEL-08-020230".into(),
        compliance_control_title: "RHEL 8 passwords must have a minimum of 15 characters".into(),
        compliance_section: None,
    };
    let generator = ReportGenerator::new(
        ReportConfig {
            scenario: Scenario::Custom(vec![ComplianceFramework::STIG]),
            formats: vec![],
            output_dir: None,
            profile: ComplianceProfile::Generic,
        },
        vec![stig_mapping.clone()],
    );

    // A host that scanned with zero findings but flagged the minlen check as
    // unchecked (unreadable pwquality.conf without root) must not silently
    // report the control it covers as Pass: the absence of a finding proves
    // nothing when the check never ran.
    let unchecked = vec![UncheckedCheck {
        unchecked_check_id: "pam-minlen".into(),
        unchecked_title: "PAM setting: minlen".into(),
        unchecked_category: FindingCategory::Authentication,
        unchecked_reason: "reading /etc/security/pwquality.conf requires root".into(),
        unchecked_blocker: hardener_types::UncheckedBlocker::Privilege,
        unchecked_compliance: vec![stig_mapping],
    }];
    let outcome = HostOutcome {
        name: "web-01".into(),
        target: "u@web-01:22".into(),
        profile: ComplianceProfile::Generic,
        status: HostStatus::Scanned {
            counts: SeverityCounts::default(),
            findings: vec![],
            unchecked,
        },
    };
    let report = host_report(outcome, &generator);
    let HostReportStatus::Assessed { frameworks } = report.status else {
        panic!("scanned host should be assessed");
    };
    let stig = frameworks
        .iter()
        .find(|f| f.framework == "STIG")
        .expect("STIG framework present in the custom scenario");
    assert_eq!(stig.total, 1, "single-mapping coverage yields one control");
    assert_eq!(
        stig.manual_review, 1,
        "unchecked control must land in manual_review, not silently pass: {stig:?}"
    );
    assert_eq!(
        stig.passing, 0,
        "must not auto-pass on absence of a finding"
    );
}

#[test]
fn report_rollup_aggregates_failing_per_framework() {
    let reports = vec![
        assessed_report("web-01", vec![posture(18)]),
        assessed_report("db-02", vec![posture(6)]),
        failed_report("cache"),
    ];
    let r = ReportRollup::from_reports(&reports);
    assert_eq!(r.hosts_total, 3);
    assert_eq!(r.hosts_assessed, 2);
    assert_eq!(r.hosts_failed, 1);
    assert_eq!(r.frameworks.len(), 1);
    assert_eq!(r.frameworks[0].framework, "CIS");
    assert_eq!(r.frameworks[0].failing, 24, "18 + 6 across the fleet");
}

#[test]
fn report_rollup_groups_multiple_frameworks_per_host() {
    // The default `server` scenario assesses each host against CIS + STIG, so
    // the rollup must group per framework, accumulating across hosts.
    let fw = |name: &str, failing: usize| FrameworkPosture {
        framework: name.into(),
        score: 90.0,
        passing: 10,
        failing,
        manual_review: 0,
        not_applicable: 0,
        total: 10 + failing,
    };
    let reports = vec![
        assessed_report("web", vec![fw("CIS", 3), fw("STIG", 1)]),
        assessed_report("db", vec![fw("CIS", 2), fw("STIG", 4)]),
    ];
    let r = ReportRollup::from_reports(&reports);
    assert_eq!(r.hosts_assessed, 2);
    assert_eq!(r.frameworks.len(), 2, "CIS and STIG grouped separately");
    assert_eq!(
        r.frameworks[0].framework, "CIS",
        "first-seen order preserved"
    );
    assert_eq!(r.frameworks[0].failing, 5, "CIS 3 + 2");
    assert_eq!(r.frameworks[1].framework, "STIG");
    assert_eq!(r.frameworks[1].failing, 5, "STIG 1 + 4");
}

#[test]
fn report_text_render_has_sections_and_rollup() {
    colored::control::set_override(false);
    let text = render_report_text(&[
        assessed_report("web-01", vec![posture(18)]),
        failed_report("cache"),
    ]);
    assert!(
        text.contains("==== web-01  u@web-01:22  [generic profile] "),
        "header carries name, target and profile: {text}"
    );
    assert!(
        text.contains("status:    ok (1 framework(s) assessed)"),
        "assessed status line: {text}"
    );
    assert!(
        text.contains("CIS:        90.0%  10 pass, 18 fail, 2 manual, 0 n/a"),
        "per-framework posture line: {text}"
    );
    assert!(text.contains("status:    FAILED"), "failed status: {text}");
    assert!(
        text.contains("error:     refused"),
        "failed section surfaces the error: {text}"
    );
    assert!(
        text.contains("---\n1 of 2 hosts assessed, 1 failed"),
        "rollup footer kept: {text}"
    );
    assert!(text.contains("CIS: 18 failing controls"));
}

#[test]
fn report_json_render_is_valid_and_discriminates_status() {
    let json = render_report_json(&[
        assessed_report("web-01", vec![posture(18)]),
        failed_report("cache"),
    ]);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["hosts"][0]["status"], "assessed");
    assert_eq!(v["hosts"][0]["frameworks"][0]["framework"], "CIS");
    assert_eq!(v["hosts"][1]["status"], "failed");
    assert!(
        v["hosts"][1]["frameworks"].is_null(),
        "failed host has no frameworks"
    );
    assert_eq!(v["summary"]["hosts_assessed"], 1);
    assert_eq!(v["summary"]["frameworks"][0]["failing"], 18);
}

#[test]
fn report_exit_code_tiers() {
    // All compliant -> 0
    assert_eq!(
        report_exit_code(&[assessed_report("a", vec![posture(0)])]),
        0
    );
    // A failing control -> 1
    assert_eq!(
        report_exit_code(&[assessed_report("a", vec![posture(3)])]),
        1
    );
    // A host error dominates a failing control -> 2 (failed last)
    assert_eq!(
        report_exit_code(&[assessed_report("a", vec![posture(3)]), failed_report("b")]),
        2
    );
    // A host error dominates regardless of order -> 2 (failed first)
    assert_eq!(
        report_exit_code(&[failed_report("b"), assessed_report("a", vec![posture(3)])]),
        2
    );
    // Manual-review present but zero failing is NOT a failure -> 0
    let manual_only = FrameworkPosture {
        framework: "CIS".into(),
        score: 80.0,
        passing: 7,
        failing: 0,
        manual_review: 5,
        not_applicable: 0,
        total: 12,
    };
    assert_eq!(
        report_exit_code(&[assessed_report("a", vec![manual_only])]),
        0
    );
    // Empty -> 0
    assert_eq!(report_exit_code(&[]), 0);
}

fn finding(sev: Severity) -> Finding {
    Finding {
        finding_category: FindingCategory::Kernel,
        finding_current_value: String::new(),
        finding_description: String::new(),
        finding_explanation: String::new(),
        finding_id: "x".into(),
        finding_impact: String::new(),
        finding_recommended_value: String::new(),
        finding_remediation_steps: vec![],
        finding_severity: sev,
        finding_title: "t".into(),
        finding_compliance: vec![],
        finding_exception: ExceptionOutcome::NotConfigured,
        finding_exception_key: None,
    }
}

fn scanned(total_high: usize) -> HostOutcome {
    HostOutcome {
        name: "h".into(),
        target: "u@h:22".into(),
        profile: ComplianceProfile::Generic,
        status: HostStatus::Scanned {
            counts: SeverityCounts {
                high: total_high,
                ..Default::default()
            },
            findings: vec![],
            unchecked: vec![],
        },
    }
}

fn failed() -> HostOutcome {
    HostOutcome {
        name: "h".into(),
        target: "u@h:22".into(),
        profile: ComplianceProfile::Generic,
        status: HostStatus::Failed {
            error: "boom".into(),
        },
    }
}

fn scanned_named(name: &str, counts: SeverityCounts) -> HostOutcome {
    HostOutcome {
        name: name.into(),
        target: format!("u@{name}:22"),
        profile: ComplianceProfile::Generic,
        status: HostStatus::Scanned {
            counts,
            findings: vec![],
            unchecked: vec![],
        },
    }
}

fn failed_named(name: &str) -> HostOutcome {
    HostOutcome {
        name: name.into(),
        target: format!("u@{name}:22"),
        profile: ComplianceProfile::Generic,
        status: HostStatus::Failed {
            error: "did not complete".into(),
        },
    }
}

#[test]
fn exit_code_tiers() {
    assert_eq!(exit_code(&[scanned(0)]), 0);
    assert_eq!(exit_code(&[scanned(0), scanned(3)]), 1);
    assert_eq!(exit_code(&[scanned(3), failed()]), 2);
    assert_eq!(exit_code(&[]), 0);
}

fn inv() -> HostsConfig {
    HostsConfig {
        hosts: vec![profile("web-01"), profile("db-02")],
    }
}
fn profile(name: &str) -> RemoteHostProfile {
    RemoteHostProfile {
        name: name.into(),
        hostname: format!("{name}.local"),
        user: Some("admin".into()),
        port: 22,
        key_file: None,
        host_key_checking: true,
    }
}

#[test]
fn resolve_all_returns_inventory() {
    let r = resolve_hosts(&inv(), true, &[], vec![]).unwrap();
    assert_eq!(r.len(), 2);
}
#[test]
fn resolve_named_subset() {
    let r = resolve_hosts(&inv(), false, &["db-02".into()], vec![]).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].name, "db-02");
}
#[test]
fn resolve_unknown_name_errors() {
    assert!(resolve_hosts(&inv(), false, &["nope".into()], vec![]).is_err());
}
#[test]
fn resolve_dedups_inline_against_inventory() {
    // The fixture's `web-01` connects to `web-01.local`, so this is the same
    // endpoint reached two ways and one of them is redundant.
    let inline = vec![parse_inline("admin@web-01.local", 22, None, true)];
    let r = resolve_hosts(&inv(), true, &[], inline).unwrap();
    assert_eq!(r.len(), 2, "inline duplicate of inventory host is dropped");
}
#[test]
fn resolve_keeps_an_inline_host_the_inventory_only_appears_to_hold() {
    // `web-01` is the fixture's *nickname* for `web-01.local`. An operator who
    // types `--ssh admin@web-01` is naming a different DNS name, and nothing
    // else in the tree resolves names to decide two hosts are one.
    let inline = vec![parse_inline("admin@web-01", 22, None, true)];
    let r = resolve_hosts(&inv(), true, &[], inline).unwrap();
    assert_eq!(
        r.len(),
        3,
        "an inventory nickname is not a hostname, so this host was never named twice"
    );
}
#[test]
fn resolve_keeps_ad_hoc_targets_that_differ_only_by_port() {
    let inline = vec![
        parse_inline("admin@web-01:22", 22, None, true),
        parse_inline("admin@web-01:2222", 22, None, true),
    ];
    let r = resolve_hosts(&HostsConfig::default(), false, &[], inline).unwrap();
    assert_eq!(
        r.len(),
        2,
        "two ports are two endpoints; dropping one scans a host the operator never named"
    );
}
#[test]
fn resolve_keeps_ad_hoc_targets_that_differ_only_by_user() {
    let inline = vec![
        parse_inline("root@web-01", 22, None, true),
        parse_inline("admin@web-01", 22, None, true),
    ];
    let r = resolve_hosts(&HostsConfig::default(), false, &[], inline).unwrap();
    assert_eq!(
        r.len(),
        2,
        "the account decides which checks can run at all, so two users are two scans"
    );
}
#[test]
fn resolve_empty_errors() {
    assert!(resolve_hosts(&HostsConfig::default(), false, &[], vec![]).is_err());
}
#[test]
fn parse_inline_splits_user() {
    let p = parse_inline("root@10.0.0.5", 2222, None, false);
    assert_eq!(p.user.as_deref(), Some("root"));
    assert_eq!(p.hostname, "10.0.0.5");
    assert_eq!(p.port, 2222);
    assert!(!p.host_key_checking);
}

#[test]
fn parse_inline_port_suffix_overrides_default() {
    let p = parse_inline("root@10.0.0.5:2200", 22, None, true);
    assert_eq!(p.user.as_deref(), Some("root"));
    assert_eq!(p.hostname, "10.0.0.5", "host stripped of :port");
    assert_eq!(p.port, 2200, ":port suffix overrides the default");
}

#[test]
fn parse_inline_port_suffix_without_user() {
    let p = parse_inline("web-01:2022", 22, None, true);
    assert_eq!(p.user, None);
    assert_eq!(p.hostname, "web-01");
    assert_eq!(p.port, 2022);
}

#[test]
fn parse_inline_non_numeric_suffix_is_part_of_host() {
    // A trailing ":word" is not a port; keep it in the host, use the default.
    let p = parse_inline("host:notaport", 22, None, true);
    assert_eq!(p.hostname, "host:notaport");
    assert_eq!(p.port, 22);
}

#[test]
fn parse_inline_bare_ipv6_keeps_default_port() {
    // Unbracketed IPv6 has no unambiguous :port form; leave it intact.
    let p = parse_inline("::1", 22, None, true);
    assert_eq!(p.hostname, "::1");
    assert_eq!(p.port, 22);
}

#[test]
fn counts_tally_by_severity() {
    let f = vec![
        finding(Severity::Critical),
        finding(Severity::High),
        finding(Severity::High),
        finding(Severity::Low),
    ];
    let c = SeverityCounts::from_findings(&f);
    assert_eq!(
        c,
        SeverityCounts {
            critical: 1,
            high: 2,
            medium: 0,
            low: 1
        }
    );
    assert_eq!(c.total(), 4);
}

#[test]
fn summary_aggregates() {
    let outcomes = vec![scanned(2), failed(), scanned(0)];
    let s = BatchSummary::from_outcomes(&outcomes);
    assert_eq!(s.hosts_total, 3);
    assert_eq!(s.hosts_scanned, 2);
    assert_eq!(s.hosts_failed, 1);
    assert_eq!(s.high, 2);
    assert_eq!(s.total, 2);
}

#[test]
fn text_render_has_rollup() {
    let text = render_text(&[scanned(1), failed()]);
    assert!(text.contains("FAILED"));
    assert!(text.contains("2 host(s): 1 scanned, 1 failed"));
}

#[test]
fn json_render_is_valid() {
    let json = render_json(&[scanned(1)]);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["summary"]["hosts_scanned"], 1);
    assert_eq!(v["hosts"][0]["status"], "scanned");
}

#[tokio::test]
async fn scan_with_mock_executor_yields_scanned() {
    use hardener_core::MockExecutor;
    use std::sync::Arc;
    let exec = Arc::new(MockExecutor::new());
    let outcome = scan_with_executor(
        "h".into(),
        "u@h:22".into(),
        "u@h:22".into(),
        exec,
        None,
        &HardenerConfig::default(),
    )
    .await;
    assert!(
        matches!(outcome.status, HostStatus::Scanned { .. }),
        "a mock executor should yield a Scanned outcome, not a connection failure",
    );
    assert_eq!(
        outcome.profile,
        ComplianceProfile::Generic,
        "no os-release on the mock host resolves to Generic, never an error",
    );
}

/// Scans a mock host whose `/etc/os-release` declares Rocky Linux 10.
async fn rocky10_outcome() -> HostOutcome {
    use hardener_core::MockExecutor;
    let exec = Arc::new(MockExecutor::new().with_file(
        "/etc/os-release",
        "NAME=\"Rocky Linux\"\nID=\"rocky\"\nVERSION_ID=\"10.0\"\n",
    ));
    scan_with_executor(
        "r10".into(),
        "u@r10:22".into(),
        "r10".into(),
        exec,
        None,
        &HardenerConfig::default(),
    )
    .await
}

#[tokio::test]
async fn scan_resolves_rocky_10_profile_and_report_carries_it() {
    let outcome = rocky10_outcome().await;
    assert!(matches!(outcome.status, HostStatus::Scanned { .. }));
    assert_eq!(outcome.profile, ComplianceProfile::Rhel10);

    // Without an override the host's own profile rides into its report
    // row, and the JSON document exposes it per host.
    let reports = assess_outcomes(vec![outcome], Scenario::Server, None);
    assert_eq!(reports[0].profile, ComplianceProfile::Rhel10);
    let json = render_report_json(&reports);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["hosts"][0]["profile"], "rhel10");
}

#[tokio::test]
async fn batch_report_profile_override_forces_every_host() {
    let outcome = rocky10_outcome().await;
    assert_eq!(outcome.profile, ComplianceProfile::Rhel10);

    let reports = assess_outcomes(
        vec![outcome],
        Scenario::Server,
        Some(ComplianceProfile::Generic),
    );
    assert_eq!(
        reports[0].profile,
        ComplianceProfile::Generic,
        "an explicit --profile beats per-host detection",
    );
}

#[tokio::test]
async fn scan_all_empty_is_empty() {
    let out = scan_all(vec![], 4, 1, None, Arc::new(HardenerConfig::default())).await;
    assert!(out.is_empty());
}

#[test]
fn parse_inline_without_user() {
    let p = parse_inline("host.only", 22, None, true);
    assert!(p.user.is_none());
    assert_eq!(p.hostname, "host.only");
    assert_eq!(p.name, "host.only");
    assert!(p.host_key_checking);
}

#[test]
fn resolve_inline_only() {
    let r = resolve_hosts(
        &HostsConfig::default(),
        false,
        &[],
        vec![parse_inline("ops@cache", 22, None, true)],
    )
    .unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].name, "cache");
}

#[test]
fn resolve_multiple_names_preserve_order() {
    let r = resolve_hosts(&inv(), false, &["db-02".into(), "web-01".into()], vec![]).unwrap();
    let names: Vec<&str> = r.iter().map(|h| h.name.as_str()).collect();
    assert_eq!(names, ["db-02", "web-01"]);
}

#[test]
fn resolve_all_plus_noncolliding_inline() {
    let r = resolve_hosts(
        &inv(),
        true,
        &[],
        vec![parse_inline("u@extra", 22, None, true)],
    )
    .unwrap();
    assert_eq!(r.len(), 3);
    assert_eq!(r[2].name, "extra");
}

#[test]
fn counts_exclude_info() {
    let f = vec![finding(Severity::Info), finding(Severity::Critical)];
    let c = SeverityCounts::from_findings(&f);
    assert_eq!(c.critical, 1);
    assert_eq!(c.total(), 1);
}

#[test]
fn summary_mixed_severities() {
    let s = BatchSummary::from_outcomes(&[scanned_named(
        "a",
        SeverityCounts {
            critical: 1,
            high: 2,
            medium: 3,
            low: 4,
        },
    )]);
    assert_eq!(s.critical, 1);
    assert_eq!(s.high, 2);
    assert_eq!(s.medium, 3);
    assert_eq!(s.low, 4);
    assert_eq!(s.total, 10);
    assert_eq!(s.hosts_scanned, 1);
    assert_eq!(s.hosts_failed, 0);
}

#[test]
fn text_render_scanned_section_shows_counts() {
    colored::control::set_override(false);
    let text = render_text(&[scanned_named(
        "web-01",
        SeverityCounts {
            high: 2,
            ..Default::default()
        },
    )]);
    assert!(
        text.contains("==== web-01  u@web-01:22 "),
        "header carries name and target: {text}"
    );
    assert!(text.contains("status:    ok"), "status line: {text}");
    assert!(
        text.contains("findings:  2 total (0 crit, 2 high, 0 med, 0 low)"),
        "findings line breaks down severities: {text}"
    );
}

#[test]
fn text_render_unchecked_line_only_when_nonzero() {
    colored::control::set_override(false);
    use hardener_common::types::FindingCategory;
    let unchecked = vec![UncheckedCheck {
        unchecked_check_id: "pam-minlen".into(),
        unchecked_title: "PAM setting: minlen".into(),
        unchecked_category: FindingCategory::Authentication,
        unchecked_reason: "requires root".into(),
        unchecked_blocker: hardener_types::UncheckedBlocker::Privilege,
        unchecked_compliance: vec![],
    }];
    let with = render_text(&[HostOutcome {
        name: "web-01".into(),
        target: "u@web-01:22".into(),
        profile: ComplianceProfile::Generic,
        status: HostStatus::Scanned {
            counts: SeverityCounts::default(),
            findings: vec![],
            unchecked,
        },
    }]);
    assert!(
        with.contains("unchecked: 1 check(s) require root; run with sudo for a full scan"),
        "non-zero unchecked is listed: {with}"
    );

    let without = render_text(&[scanned_named("web-01", SeverityCounts::default())]);
    assert!(
        !without.contains("unchecked"),
        "zero unchecked prints no line: {without}"
    );
    assert!(
        without.contains("findings:  none"),
        "clean host reads none: {without}"
    );
    assert!(without.contains("---\n"), "summary footer kept: {without}");
}

#[test]
fn json_failed_host_shape() {
    let json = render_json(&[failed_named("cache")]);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["hosts"][0]["status"], "failed");
    assert!(v["hosts"][0]["error"].is_string());
    assert!(
        v["hosts"][0]["counts"].is_null(),
        "failed host has no counts"
    );
    assert!(
        v["hosts"][0]["findings"].is_null(),
        "failed host has no findings"
    );
}

#[test]
fn assemble_ordered_preserves_order_and_keeps_placeholder() {
    let prefill = vec![failed_named("a"), failed_named("b"), failed_named("c")];
    // completed out of order, and index 1 ("b") never reports
    let completed = vec![
        (2, scanned_named("c", SeverityCounts::default())),
        (0, scanned_named("a", SeverityCounts::default())),
    ];
    let out = assemble_ordered(prefill, completed);
    assert_eq!(out.len(), 3);
    assert_eq!(out[0].name, "a");
    assert_eq!(out[1].name, "b");
    assert_eq!(out[2].name, "c");
    assert!(matches!(out[0].status, HostStatus::Scanned { .. }));
    assert!(
        matches!(out[1].status, HostStatus::Failed { .. }),
        "dropped task keeps placeholder"
    );
    assert!(matches!(out[2].status, HostStatus::Scanned { .. }));
}

#[tokio::test]
async fn scan_all_preserves_order_and_isolates_failures() {
    // Three unreachable hosts (loopback port 1 is always refused). Each must
    // come back Failed, in input order, with none lost, exercising the real
    // spawn -> bounded-collect -> assemble_ordered wiring end to end.
    let hosts: Vec<RemoteHostProfile> = ["alpha", "bravo", "charlie"]
        .iter()
        .map(|name| RemoteHostProfile {
            name: (*name).to_string(),
            hostname: "127.0.0.1".to_string(),
            user: Some("nobody".to_string()),
            port: 1,
            key_file: None,
            host_key_checking: false,
        })
        .collect();

    let out = scan_all(hosts, 2, 1, None, Arc::new(HardenerConfig::default())).await;

    assert_eq!(out.len(), 3, "every host appears, none dropped");
    assert_eq!(
        out.iter().map(|o| o.name.as_str()).collect::<Vec<_>>(),
        ["alpha", "bravo", "charlie"],
        "output preserves input order despite concurrent completion",
    );
    assert!(
        out.iter()
            .all(|o| matches!(o.status, HostStatus::Failed { .. })),
        "unreachable hosts are isolated as Failed, not aborting the batch",
    );
}

#[test]
fn text_render_failed_row_shows_error() {
    let out = render_text(&[HostOutcome {
        name: "cache".into(),
        target: "u@cache:22".into(),
        profile: ComplianceProfile::Generic,
        status: HostStatus::Failed {
            error: "connection refused".into(),
        },
    }]);
    assert!(out.contains("cache"));
    assert!(
        out.contains("connection refused"),
        "failed row must surface the error"
    );
    assert!(out.contains("FAILED"));
}

#[tokio::test]
async fn batch_scan_persists_session_per_host() {
    use hardener_core::MockExecutor;
    use hardener_scheduler::ScanHistoryManager;
    use hardener_scheduler::db::SessionFilter;
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let mgr = Arc::new(
        ScanHistoryManager::new(&dir.path().join("scheduler.db"))
            .await
            .unwrap(),
    );

    let exec = Arc::new(MockExecutor::new());
    let outcome = scan_with_executor(
        "web-01".into(),
        "root@web-01:22".into(),
        "web-01".into(),
        exec,
        Some(mgr.clone()),
        &HardenerConfig::default(),
    )
    .await;
    assert!(matches!(outcome.status, HostStatus::Scanned { .. }));

    // One completed session was persisted under the host_key.
    let sessions = mgr
        .list_sessions(&SessionFilter {
            host: Some("web-01".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(sessions.len(), 1, "one session persisted for the host");
    assert_eq!(sessions[0].host_identifier, "web-01");
    assert_eq!(sessions[0].status, "completed");
}

#[tokio::test]
async fn run_on_all_preserves_order_and_prefill() {
    let profiles: Vec<RemoteHostProfile> = (0..3)
        .map(|i| RemoteHostProfile {
            name: format!("h{i}"),
            hostname: format!("h{i}"),
            user: None,
            port: 22,
            key_file: None,
            host_key_checking: true,
        })
        .collect();
    let out = run_on_all(
        profiles,
        2,
        |p| format!("missing:{}", p.name),
        |p| async move { p.name.clone() },
    )
    .await;
    assert_eq!(out, vec!["h0", "h1", "h2"], "results stay in input order");
}

#[test]
fn host_key_of_uses_name_for_inventory_and_target_for_adhoc() {
    // Inventory host: friendly name differs from hostname -> keyed by name.
    let inv = RemoteHostProfile {
        name: "web1".into(),
        hostname: "10.0.0.5".into(),
        user: Some("admin".into()),
        port: 22,
        key_file: None,
        host_key_checking: true,
    };
    assert_eq!(host_key_of(&inv, "root@10.0.0.5:22"), "web1");

    // Ad-hoc host: name == hostname (set by parse_inline) -> keyed by the
    // full target string so different users/ports remain distinct.
    let adhoc = RemoteHostProfile {
        name: "10.0.0.9".into(),
        hostname: "10.0.0.9".into(),
        user: Some("root".into()),
        port: 22,
        key_file: None,
        host_key_checking: false,
    };
    assert_eq!(host_key_of(&adhoc, "root@10.0.0.9:22"), "root@10.0.0.9:22");
}

#[test]
fn resolve_plugin_ids_empty_means_all() {
    let all = resolve_plugin_ids(&[]).expect("empty filter is valid");
    assert!(!all.is_empty(), "empty filter selects every plugin");
    let one = resolve_plugin_ids(&["kernel".to_string()]).expect("kernel is a real plugin");
    assert_eq!(one.len(), 1, "short name resolves to one plugin");
    assert!(one[0].as_str().starts_with("kernel"));
}

#[test]
fn resolve_plugin_ids_refuses_a_name_that_matches_nothing() {
    // A fleet-wide apply that silently hardened nothing on every host is
    // the failure this refusal exists to prevent.
    let err = resolve_plugin_ids(&["services".to_string()])
        .expect_err("an unmatched name must fail, not select nothing");
    assert!(err.to_string().contains("services"), "{err}");
}

#[test]
fn apply_exit_code_precedence() {
    let mk = |status| ApplyOutcome {
        name: "h".into(),
        target: "h".into(),
        status,
    };
    assert_eq!(
        apply_exit_code(&[mk(ApplyStatus::Applied { ok: 3, failed: 0 })]),
        0
    );
    assert_eq!(
        apply_exit_code(&[mk(ApplyStatus::Validated {
            plugins: 3,
            would_change: 1,
            compliant: 0,
            failed: 0
        })]),
        0
    );
    assert_eq!(
        apply_exit_code(&[mk(ApplyStatus::Applied { ok: 2, failed: 1 })]),
        1
    );
    assert_eq!(
        apply_exit_code(&[mk(ApplyStatus::Validated {
            plugins: 2,
            would_change: 0,
            compliant: 0,
            failed: 1
        })]),
        1
    );
    assert_eq!(
        apply_exit_code(&[
            mk(ApplyStatus::Applied { ok: 0, failed: 2 }),
            mk(ApplyStatus::Failed {
                error: "connect".into()
            }),
        ]),
        2
    );
}

#[test]
fn render_apply_text_sections_and_summary() {
    colored::control::set_override(false);
    let mk = |name: &str, status| ApplyOutcome {
        name: name.into(),
        target: format!("root@{name}:22"),
        status,
    };
    let text = render_apply_text(&[
        mk("web-01", ApplyStatus::Applied { ok: 5, failed: 0 }),
        mk("db-02", ApplyStatus::Applied { ok: 3, failed: 2 }),
        mk(
            "cache",
            ApplyStatus::Failed {
                error: "connection refused".into(),
            },
        ),
    ]);
    assert!(
        text.contains("==== web-01  root@web-01:22 "),
        "header carries name and target: {text}"
    );
    assert!(
        text.contains("status:    applied"),
        "clean apply is green ok: {text}"
    );
    assert!(text.contains("result:    5 ok, 0 failed"), "counts: {text}");
    assert!(
        text.contains("status:    partially applied"),
        "partial apply is flagged: {text}"
    );
    assert!(text.contains("status:    FAILED"), "failed status: {text}");
    assert!(
        text.contains("error:     connection refused"),
        "error surfaces: {text}"
    );
    assert!(
        text.contains("---\n3 host(s): 2 applied, 1 failed"),
        "summary footer: {text}"
    );
}

#[test]
fn render_apply_text_validation_states() {
    colored::control::set_override(false);
    let mk = |name: &str, status| ApplyOutcome {
        name: name.into(),
        target: format!("root@{name}:22"),
        status,
    };
    let text = render_apply_text(&[
        mk(
            "web-01",
            ApplyStatus::Validated {
                plugins: 8,
                would_change: 4,
                compliant: 14,
                failed: 0,
            },
        ),
        mk(
            "db-02",
            ApplyStatus::Validated {
                plugins: 8,
                would_change: 0,
                compliant: 18,
                failed: 0,
            },
        ),
    ]);
    assert!(
        text.contains("status:    validated (changes pending)"),
        "pending validation is flagged: {text}"
    );
    assert!(
        text.contains("status:    validated (no changes needed)"),
        "clean validation reads clean: {text}"
    );
    assert!(
        text.contains("8 plugin(s) checked, 4 change(s) pending, 0 failed (14 already compliant)"),
        "validation detail carries the compliant count: {text}"
    );
    assert!(
        text.contains("0 change(s) pending, 0 failed (18 already compliant)"),
        "a fully compliant host reads 0 pending with the compliant tally: {text}"
    );
    assert!(
        text.contains("---\n2 host(s): 2 validated"),
        "summary footer: {text}"
    );
}

#[test]
fn render_apply_json_has_state_tags() {
    let out = render_apply_json(&[ApplyOutcome {
        name: "web".into(),
        target: "root@web".into(),
        status: ApplyStatus::Applied { ok: 5, failed: 0 },
    }]);
    assert!(
        out.contains("\"state\": \"applied\""),
        "json tags the status state: {out}"
    );
    assert!(out.contains("\"ok\": 5"));
}

#[tokio::test]
async fn batch_persistence_handles_concurrent_hosts() {
    use hardener_core::MockExecutor;
    use hardener_scheduler::ScanHistoryManager;
    use hardener_scheduler::db::SessionFilter;
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let mgr = Arc::new(
        ScanHistoryManager::new(&dir.path().join("scheduler.db"))
            .await
            .unwrap(),
    );

    // Persist three hosts concurrently through the shared manager (exercises WAL).
    let mut set = tokio::task::JoinSet::new();
    for i in 0..3 {
        let mgr = mgr.clone();
        set.spawn(async move {
            let exec = Arc::new(MockExecutor::new());
            let key = format!("host-{i}");
            scan_with_executor(
                key.clone(),
                format!("u@{key}:22"),
                key,
                exec,
                Some(mgr),
                &HardenerConfig::default(),
            )
            .await
        });
    }
    while set.join_next().await.is_some() {}

    let all = mgr.list_sessions(&SessionFilter::default()).await.unwrap();
    assert_eq!(all.len(), 3, "all concurrent host sessions persisted");
}

/// Two selections that really would write under one key are refused, and the
/// refusal names the key and both targets.
///
/// The pair used to be `web-01` against `root@web-01`, which collided because
/// the key fabricated a `root` for the bare form. That fabrication is gone: a
/// bare target now resolves through the operator's ssh configuration, so
/// whether those two collide depends on whose machine the suite runs on, which
/// is not a thing to assert. Two inventory entries for one endpoint collide on
/// every machine and exercise the same code, so that is the pair here.
///
/// A run that selects both still has to be refused: under `--execute` each
/// captures a pre-apply checkpoint under `(host_key, name)` and
/// `select_latest_named` keeps the newest per key, so the survivor can hold
/// content the other selection had already hardened. A later rollback then
/// reports the host restored while restoring the hardened state, and the
/// cross-host guard cannot refuse it because by its measure the keys are equal.
#[test]
fn colliding_host_key_catches_two_selections_that_write_under_one_key() {
    // The pair is deliberately NOT adjacent. A check that compared each target
    // only against the one before it would still catch the adjacent case, and
    // a collision between the first and third selection is the same collision.
    let profiles = vec![
        parse_inline("admin@web-01", 22, None, true),
        parse_inline("web-02", 22, None, true),
        parse_inline("admin@web-01", 22, None, true),
    ];

    let collision = colliding_host_key(&profiles);

    assert_eq!(
        collision.as_ref().map(|c| c.key.as_str()),
        Some("ssh://admin@web-01:22"),
        "the one key both selections would write under is named, so the refusal \
         can say what collided"
    );
}

/// The control against the refusal being made too broad. Distinct machines, and
/// distinct accounts on one machine, are exactly what a fleet run is for: only
/// the pair that a fabricated `root` collapses may be refused.
#[test]
fn colliding_host_key_passes_targets_that_stay_distinct() {
    let distinct = vec![
        parse_inline("web-01", 22, None, true),
        parse_inline("web-02", 22, None, true),
        parse_inline("admin@web-01", 22, None, true),
        parse_inline("root@web-01:2222", 22, None, true),
    ];

    assert!(
        colliding_host_key(&distinct).is_none(),
        "two machines, a second account, and a second port are four keys; \
         refusing any of them would refuse a fleet the operator may legitimately run"
    );
    assert!(
        colliding_host_key(&[]).is_none(),
        "an empty selection collides with nothing"
    );
}

/// `batch report --output fleet.json` under the default text format wrote a
/// human fleet table into a file named `.json`, the same contradiction
/// `hardener report --output` refuses, and it was only noticed at the point of
/// writing: after the whole fleet had been scanned.
///
/// This pins the mapping the fleet verbs judge against. Batch renders text and
/// JSON only, so getting it wrong would either refuse a correct path or accept
/// a contradicting one, and neither is visible without it.
#[test]
fn a_fleet_verb_judges_a_path_against_the_document_its_format_selects() {
    use hardener_compliance::OutputFormat;

    assert_eq!(
        selected_document(CliOutputFormat::Json),
        OutputFormat::Json,
        "--format json selects the JSON document, so a .json path agrees with it"
    );
    assert_eq!(
        selected_document(CliOutputFormat::Text),
        OutputFormat::Text,
        "and the default selects text, which is what made `--output fleet.json` \
         a contradiction rather than a preference"
    );
}

fn rollback_result_fixture() -> RollbackResult {
    RollbackResult {
        rollback_checkpoint_id: "cp-1".to_string(),
        rollback_checkpoint_name: "before apply".to_string(),
        rollback_success: true,
        rollback_files: Vec::new(),
        rollback_reloads: Vec::new(),
        rollback_divergences: Vec::new(),
    }
}

/// A fleet rollback names the hosts worth looking at. Without the count, an
/// operator rolling back twenty hosts has no way to find the one that is
/// still enforcing what they undid.
#[test]
fn a_hosts_divergences_reach_the_fleet_summary() {
    let mut result = rollback_result_fixture();
    result.rollback_divergences = vec![RollbackDivergence {
        divergence_plugin_id: "firewall-hardening".to_string(),
        divergence_subject: "ufw".to_string(),
        divergence_state: DivergenceState::Diverged,
        divergence_detail: "still enforcing".to_string(),
    }];

    let status = rollback_status_for(&[result], 0);

    match status {
        RollbackStatus::RolledBack { diverged, .. } => assert_eq!(diverged, 1),
        other => panic!("expected RolledBack, got {other:?}"),
    }
}

/// The count is a count and nothing more: it must not move the exit code.
#[test]
fn a_divergence_does_not_change_the_fleet_exit_code() {
    let clean = RollbackStatus::RolledBack {
        restored: 3,
        failed: 0,
        reload_failed: 0,
        diverged: 0,
    };
    let diverged = RollbackStatus::RolledBack {
        restored: 3,
        failed: 0,
        reload_failed: 0,
        diverged: 2,
    };

    assert_eq!(
        rollback_exit_code(&[ro(clean)]),
        rollback_exit_code(&[ro(diverged)]),
    );
}
