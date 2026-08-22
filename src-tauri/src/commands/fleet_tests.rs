#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Fleet command tests for [`commands`](super).
//!
//! Split out of `commands.rs`, which carried three test modules under three
//! different names. Each keeps its own name in its own file, following
//! `acl_tests.rs`, which has sat beside `main.rs` since 2026-07-18 and is
//! this repository's precedent for a split-out unit test module. `super`
//! still resolves to `crate::commands`.

use super::*;

fn privileged_output(exit_code: Option<i32>, stdout: &str, stderr: &str) -> PrivilegedOutput {
    PrivilegedOutput {
        stdout: stdout.to_string(),
        stderr: stderr.to_string(),
        exit_code,
    }
}

#[test]
fn exit_code_may_carry_json_accepts_only_zero_and_one() {
    assert!(exit_code_may_carry_json(Some(0)));
    assert!(exit_code_may_carry_json(Some(1)));
    assert!(!exit_code_may_carry_json(Some(2)));
    assert!(!exit_code_may_carry_json(Some(126)));
    assert!(!exit_code_may_carry_json(None));
}

#[test]
fn accept_json_output_parses_exit_zero() {
    let raw = privileged_output(Some(0), r#"{"a":1}"#, "");
    let parsed: serde_json::Value = accept_json_output(&raw).expect("exit 0 must parse");
    assert_eq!(parsed["a"], 1);
}

#[test]
fn accept_json_output_parses_exit_one_with_a_partial_failure_payload() {
    // Mirrors `apply`/`rollback`: the CLI prints per-plugin JSON, then
    // `bail!`s with exit 1 because one plugin failed.
    let raw = privileged_output(Some(1), r#"[{"apply_success":false}]"#, "plugin error");
    let parsed: serde_json::Value = accept_json_output(&raw).expect("exit 1 with JSON must parse");
    assert_eq!(parsed[0]["apply_success"], false);
}

#[test]
fn accept_json_output_rejects_exit_one_with_unparseable_stdout() {
    let raw = privileged_output(Some(1), "", "root privileges required");
    let err = accept_json_output::<serde_json::Value>(&raw).unwrap_err();
    assert!(
        matches!(err, PrivilegedCommandError::ExecutionFailed(msg) if msg == "root privileges required")
    );
}

#[test]
fn accept_json_output_falls_back_to_exit_code_message_when_stderr_is_empty() {
    // Unparseable stdout and no stderr at all must not surface a bare
    // "Command failed: " with nothing after the colon.
    let raw = privileged_output(Some(1), "not json", "");
    let err = accept_json_output::<serde_json::Value>(&raw).unwrap_err();
    assert!(
        matches!(&err, PrivilegedCommandError::ExecutionFailed(msg) if msg.contains("CLI exited 1")
                && msg.contains("could not be parsed as results")),
        "expected a diagnosable fallback message, got: {err}"
    );
}

#[test]
fn accept_json_output_rejects_other_exit_codes_even_with_valid_json() {
    let raw = privileged_output(Some(2), r#"{"a":1}"#, "unexpected failure");
    let err = accept_json_output::<serde_json::Value>(&raw).unwrap_err();
    assert!(
        matches!(err, PrivilegedCommandError::ExecutionFailed(msg) if msg == "unexpected failure")
    );
}

fn plugin_result(
    plugin: &str,
    findings: Vec<Finding>,
    unchecked: Vec<UncheckedCheck>,
) -> ScanResult {
    ScanResult {
        scan_plugin_id: PluginId::new(plugin),
        scan_success: true,
        scan_findings: findings,
        scan_unchecked: unchecked,
        scan_duration_us: 0,
        scan_error: None,
    }
}

fn finding(id: &str) -> Finding {
    Finding {
        finding_id: id.to_string(),
        finding_category: hardener_types::FindingCategory::Kernel,
        finding_severity: hardener_types::Severity::Low,
        finding_title: String::new(),
        finding_description: String::new(),
        finding_explanation: String::new(),
        finding_impact: String::new(),
        finding_current_value: String::new(),
        finding_recommended_value: String::new(),
        finding_remediation_steps: vec![],
        finding_compliance: vec![],
        finding_exception: hardener_types::ExceptionOutcome::NotConfigured,
        finding_exception_key: None,
    }
}

fn unchecked_check(id: &str) -> UncheckedCheck {
    UncheckedCheck {
        unchecked_check_id: id.to_string(),
        unchecked_title: String::new(),
        unchecked_category: hardener_types::FindingCategory::Kernel,
        unchecked_reason: String::new(),
        unchecked_blocker: hardener_types::UncheckedBlocker::Environment,
        unchecked_compliance: vec![],
    }
}

#[test]
fn flatten_scan_results_preserves_findings_and_unchecked_across_plugins() {
    let results = vec![
        plugin_result("kernel", vec![finding("K-1"), finding("K-2")], vec![]),
        plugin_result("pam", vec![finding("P-1")], vec![unchecked_check("P-2")]),
        plugin_result("firewall", vec![], vec![unchecked_check("F-1")]),
    ];

    let (findings, unchecked) = flatten_scan_results(results);

    let finding_ids: Vec<&str> = findings.iter().map(|f| f.finding_id.as_str()).collect();
    assert_eq!(finding_ids, ["K-1", "K-2", "P-1"]);
    // Each result's own unchecked entries survive, in order. The list also
    // carries an entry per registered plugin this session never covered
    // (these fixtures use stand-in ids, so that is all of them), which is
    // the subject of `flattening_no_results_leaves_every_plugin_unassessed`.
    let unchecked_ids: Vec<&str> = unchecked
        .iter()
        .map(|u| u.unchecked_check_id.as_str())
        .collect();
    let carried: Vec<&str> = unchecked_ids
        .iter()
        .copied()
        .filter(|id| ["P-2", "F-1"].contains(id))
        .collect();
    assert_eq!(carried, ["P-2", "F-1"]);
}

/// A session that covered nothing must not hand every control a Pass.
///
/// This previously asserted the opposite, that flattening no results
/// yields no unchecked entries. The generator reads coverage statically,
/// so an empty unchecked list is exactly what makes every control the
/// engine assesses report `Pass` on evidence nobody collected. The same
/// rule covers a scan filtered to one plugin: the other seven assessed
/// nothing, whatever the reason.
#[test]
fn flattening_no_results_leaves_every_plugin_unassessed() {
    let registered = create_plugin_registry().list().unwrap();

    let (findings, unchecked) = flatten_scan_results(vec![]);

    assert!(findings.is_empty());
    assert_eq!(
        unchecked.len(),
        registered.len(),
        "every registered plugin must account for itself"
    );
    for metadata in &registered {
        assert!(
            unchecked.iter().any(|u| u
                .unchecked_check_id
                .starts_with(metadata.plugin_id.as_str())),
            "no entry for {}",
            metadata.plugin_id
        );
    }
}

fn completed_session() -> ScanSession {
    ScanSession {
        session_id: ScanSessionId::new("session-1".to_string()),
        session_started_at: 0,
        session_completed_at: Some(0),
        session_total_findings: 0,
        session_total_plugins: 1,
        session_status: ScanStatus::Completed,
    }
}

#[test]
fn persisted_scan_source_uses_a_session_with_results() {
    let results = vec![plugin_result("kernel", vec![finding("K-1")], vec![])];
    let source = persisted_scan_source(Some((completed_session(), results)));

    let (findings, _unchecked) = source.expect("a non-empty session must be used");
    assert_eq!(findings.len(), 1);
}

#[test]
fn persisted_scan_source_falls_back_on_an_empty_completed_session() {
    // A Completed session with zero results happens when
    // `persist_scan_results` logged a `store_results` failure but still
    // marked the session Completed. Flattening it would report zero
    // findings and zero unchecked checks - a false-green score - so it
    // must be treated the same as "no session".
    let source = persisted_scan_source(Some((completed_session(), vec![])));
    assert!(source.is_none());
}

#[test]
fn persisted_scan_source_falls_back_when_no_session_exists() {
    assert!(persisted_scan_source(None).is_none());
}

/// One CIS exclusion for `control_id`, covering `hosts` (empty means every
/// host), with a review date far enough out to be irrelevant to the assertion.
fn cis_exclusion(control_id: &str, hosts: &[&str]) -> ComplianceConfig {
    let mut controls = std::collections::HashMap::new();
    controls.insert(
        control_id.to_string(),
        hardener_core::config::scope::ScopeExclusion {
            reason: "No physical premises".into(),
            approved_by: Some("eric".into()),
            approved_date: Some("2026-08-18".into()),
            ticket: None,
            review_by: Some("2999-01-01".into()),
            hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
        },
    );
    let mut frameworks = std::collections::HashMap::new();
    frameworks.insert("cis".to_string(), controls);
    ComplianceConfig {
        not_applicable: frameworks,
    }
}

/// How many CIS controls one host's posture reports as not applicable.
fn cis_not_applicable(posture: &[FleetFrameworkPosture]) -> usize {
    posture
        .iter()
        .find(|p| p.framework == ComplianceFramework::CIS)
        .expect("CIS is a fleet framework")
        .summary
        .summary_not_applicable
}

/// The fleet view is scored from the controller's own `[compliance]` section,
/// which is one file describing a fleet. An empty set cost every remote host
/// its operator's untargeted declarations; the whole set applied ungated would
/// raise the score of hosts nobody made the claim about. The generator is
/// built per host, so it is told which host it is about.
///
/// CIS 5.1.8 is a curated control no plugin covers, so it is `ManualReview`
/// and therefore the only status an exclusion can convert. Should a plugin
/// gain coverage for it, the assessed arm wins and this test fails rather than
/// passing on a control that moved.
#[test]
fn fleet_posture_resolves_exclusions_against_the_host_it_is_about() {
    let web = RemoteHostProfile::from_target("ops@web-01:22", 22, None, true);
    let db = RemoteHostProfile::from_target("ops@db-01:22", 22, None, true);
    let posture_with = |exclusions: ComplianceConfig, host: &RemoteHostProfile| {
        let generator = fleet_report_generator(
            ComplianceProfile::Generic,
            hardener_plugins::compliance_coverage(),
            exclusions,
            host,
        );
        posture_for_findings(&generator, &[], &[])
    };

    let targeted = cis_exclusion("5.1.8", &["web-01"]);
    assert_eq!(
        cis_not_applicable(&posture_with(targeted.clone(), &web)),
        1,
        "the named host's own declaration leaves its denominator"
    );
    assert_eq!(
        cis_not_applicable(&posture_with(targeted, &db)),
        0,
        "a claim about web-01 must not raise db-01's score"
    );

    let estate_wide = cis_exclusion("5.1.8", &[]);
    assert_eq!(
        cis_not_applicable(&posture_with(estate_wide.clone(), &web)),
        1,
        "an untargeted declaration is a claim about the estate"
    );
    assert_eq!(cis_not_applicable(&posture_with(estate_wide, &db)), 1);
}

#[test]
fn posture_for_findings_returns_one_per_framework() {
    let generator = fleet_report_generator(
        ComplianceProfile::Generic,
        hardener_plugins::compliance_coverage(),
        ComplianceConfig::default(),
        &RemoteHostProfile::from_target("web-01", 22, None, true),
    );
    let scores = posture_for_findings(&generator, &[], &[]);
    assert_eq!(scores.len(), FLEET_FRAMEWORKS.len());
    assert!(
        scores
            .iter()
            .any(|s| s.framework == ComplianceFramework::CIS),
        "fleet posture must include CIS"
    );
}

#[tokio::test]
async fn detect_host_profile_resolves_rocky_10_and_defaults_generic() {
    use hardener_core::MockExecutor;
    let rocky = MockExecutor::new().with_file(
        "/etc/os-release",
        "NAME=\"Rocky Linux\"\nID=\"rocky\"\nVERSION_ID=\"10.0\"\n",
    );
    assert_eq!(detect_host_profile(&rocky).await, ComplianceProfile::Rhel10);
    assert_eq!(
        detect_host_profile(&MockExecutor::new()).await,
        ComplianceProfile::Generic,
        "no os-release on the host resolves to Generic, never an error"
    );
}

#[tokio::test]
async fn fleet_isolates_failures_and_preserves_order() {
    let hosts = vec!["a".to_string(), "b".to_string(), "c".to_string()];

    let results = scan_fleet(
        hosts,
        |name| async move {
            if name == "b" {
                Err("connection refused".to_string())
            } else {
                Ok((ComplianceProfile::Generic, Vec::new()))
            }
        },
        |_, _, _| {},
    )
    .await;

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].host_name, "a");
    assert_eq!(results[1].host_name, "b");
    assert_eq!(results[2].host_name, "c");
    assert!(matches!(results[0].status, FleetHostStatus::Ok));
    assert!(matches!(results[1].status, FleetHostStatus::Failed(_)));
    assert!(matches!(results[2].status, FleetHostStatus::Ok));
}

#[tokio::test]
async fn fleet_carries_per_host_profile_and_failed_hosts_stay_generic() {
    let results = scan_fleet(
        vec!["rocky10".to_string(), "down".to_string()],
        |name| async move {
            if name == "down" {
                Err("connection refused".to_string())
            } else {
                Ok((ComplianceProfile::Rhel10, Vec::new()))
            }
        },
        |_, _, _| {},
    )
    .await;

    assert_eq!(
        results[0].profile,
        ComplianceProfile::Rhel10,
        "a scanned host's resolved profile travels on its own row"
    );
    assert_eq!(
        results[1].profile,
        ComplianceProfile::Generic,
        "a failed host scores under Generic"
    );
}

#[tokio::test]
async fn fleet_progress_fires_once_per_host_with_monotonic_count() {
    let hosts = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    let mut events: Vec<(String, usize, usize, bool)> = Vec::new();

    scan_fleet(
        hosts,
        |name| async move {
            if name == "b" {
                Err("connection refused".to_string())
            } else {
                Ok((ComplianceProfile::Generic, Vec::new()))
            }
        },
        |scan, done, total| {
            events.push((
                scan.host_name.clone(),
                done,
                total,
                matches!(scan.status, FleetHostStatus::Failed(_)),
            ));
        },
    )
    .await;

    assert_eq!(events.len(), 3, "one event per host");
    assert!(events.iter().all(|(_, _, total, _)| *total == 3));
    let counts: Vec<usize> = events.iter().map(|(_, done, _, _)| *done).collect();
    assert_eq!(counts, vec![1, 2, 3], "done count is monotonic");
    let failed: Vec<&(String, usize, usize, bool)> =
        events.iter().filter(|(_, _, _, f)| *f).collect();
    assert_eq!(failed.len(), 1, "exactly one failed host");
    assert_eq!(failed[0].0, "b", "the failed event names the failed host");
}

#[test]
fn build_batch_args_apply_dry_run_and_execute() {
    let dry = build_batch_args(
        "apply",
        &["web-1".into(), "web-2".into()],
        &[],
        &["ssh".into()],
        false,
    );
    assert_eq!(
        dry,
        vec![
            "batch", "apply", "--host", "web-1", "--host", "web-2", "--plugin", "ssh", "--format",
            "json"
        ]
    );
    let exec = build_batch_args("apply", &["web-1".into()], &[], &[], true);
    assert_eq!(
        exec,
        vec![
            "batch",
            "apply",
            "--host",
            "web-1",
            "--execute",
            "--format",
            "json"
        ]
    );
}

// The scheduler's session row: distinct from hardener_state::ScanSession.
fn session(
    started_at: i64,
    counts: (i32, i32, i32, i32, i32),
) -> hardener_scheduler::db::ScanSession {
    hardener_scheduler::db::ScanSession {
        id: format!("s{started_at}"),
        started_at,
        completed_at: Some(started_at + 60),
        status: "completed".to_string(),
        trigger_type: "batch".to_string(),
        host_identifier: "web-1".to_string(),
        plugins_scanned: "[]".to_string(),
        total_findings: counts.0 + counts.1 + counts.2 + counts.3 + counts.4,
        critical_count: counts.0,
        high_count: counts.1,
        medium_count: counts.2,
        low_count: counts.3,
        info_count: counts.4,
        error_message: None,
        json_file_path: None,
        hash: None,
    }
}

#[test]
fn sessions_to_info_directions_follow_severity_priority() {
    // Newest-first: latest gained a critical (worse), the middle improved
    // on the oldest (better), the oldest has no comparator.
    let sessions = vec![
        session(300, (1, 0, 0, 0, 0)),
        session(200, (0, 1, 0, 0, 0)),
        session(100, (0, 2, 0, 0, 0)),
    ];
    let rows = sessions_to_info(&sessions, 3);
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].direction.as_deref(), Some("worse"));
    assert_eq!(rows[1].direction.as_deref(), Some("better"));
    assert_eq!(rows[2].direction, None, "oldest scan has no comparator");
    assert_eq!(rows[0].critical, 1);
}

#[test]
fn sessions_to_info_take_bounds_rows_but_keeps_last_direction() {
    // The +1 over-fetch: two sessions, take 1, the single shown row still
    // gets its direction from the older, hidden session.
    let sessions = vec![session(200, (0, 0, 1, 0, 0)), session(100, (0, 0, 1, 0, 0))];
    let rows = sessions_to_info(&sessions, 1);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].direction.as_deref(), Some("same"));
}

#[test]
fn build_batch_args_routes_adhoc_targets_to_ssh_flag() {
    let args = build_batch_args(
        "rollback",
        &["web-1".into()],
        &["root@10.0.0.5:2222".into()],
        &[],
        false,
    );
    assert_eq!(
        args,
        vec![
            "batch",
            "rollback",
            "--host",
            "web-1",
            "--ssh",
            "root@10.0.0.5:2222",
            "--format",
            "json"
        ]
    );
}

#[test]
fn adhoc_profile_parses_and_guards() {
    let p = adhoc_profile("admin@web-01:2222").unwrap();
    assert_eq!(p.hostname, "web-01");
    assert_eq!(p.port, 2222);
    assert!(
        adhoc_profile("-oProxyCommand=x").is_err(),
        "a leading dash must be rejected: ssh would read it as an option"
    );
    assert!(adhoc_profile("").is_err(), "empty target rejected");
    assert!(
        adhoc_profile("admin@").is_err(),
        "empty hostname after user split rejected"
    );
    assert!(
        adhoc_profile("root@10.242.117.2").is_ok(),
        "bare IP target accepted"
    );
    assert!(
        adhoc_profile("root@10.242.117.2:22").is_ok(),
        ":port suffix accepted"
    );
    assert!(
        adhoc_profile("root@10.242.117.2, scan:22").is_err(),
        "comma/space in hostname rejected (the live typo)"
    );
}

#[test]
fn parse_outcomes_reads_array_after_info_line() {
    let stdout = "info: assessing 1 host\n[{\"name\":\"web-1\",\"target\":\"u@web-1\",\"status\":{\"state\":\"applied\",\"ok\":2,\"failed\":0}}]";
    let parsed: Vec<ApplyOutcome> = parse_outcomes(stdout).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].name, "web-1");
}

#[test]
fn parse_outcomes_errors_without_array() {
    let parsed: Result<Vec<ApplyOutcome>, String> = parse_outcomes("usage error: no hosts");
    assert!(parsed.is_err());
}

#[test]
fn every_canonical_framework_id_parses() {
    // The UI builds pickers and auto-report requests from
    // ComplianceFramework::ALL; every canonical id must stay accepted by
    // this command layer or a framework silently drops from GUI reports.
    // The canonical list is the single source the pickers, the CLI parser and
    // this layer all build from, so a framework added to or removed from it
    // must be re-checked here rather than silently skipping this layer. The
    // count is pinned to say so: the loop below covers whatever ALL holds,
    // and an ALL that changed size is exactly the case nobody looked at.
    assert_eq!(
        ComplianceFramework::ALL.len(),
        10,
        "the canonical framework list changed size; confirm the fleet command's parse_frameworks \
         still accepts every id"
    );
    for framework in ComplianceFramework::ALL {
        let parsed = parse_frameworks(&[framework.id().to_string()]);
        assert_eq!(
            parsed,
            vec![framework],
            "canonical id '{}' must parse to its framework",
            framework.id()
        );
    }
}

#[test]
fn parse_frameworks_accepts_legacy_aliases() {
    // Every spelling this command layer historically accepted must keep
    // working now that parsing delegates to ComplianceFramework::from_id.
    let aliases = [
        "PCIDSS",
        "PCI-DSS",
        "PCI",
        "ISO27001",
        "ISO-27001",
        "SOC2",
        "SOC-2",
        "800-171",
        "NIST800171",
        "NIST-800-171",
        "FEDRAMP",
        "FED-RAMP",
    ]
    .map(String::from);
    let parsed = parse_frameworks(&aliases);
    assert_eq!(
        parsed,
        vec![
            ComplianceFramework::PCIDSS,
            ComplianceFramework::PCIDSS,
            ComplianceFramework::PCIDSS,
            ComplianceFramework::ISO27001,
            ComplianceFramework::ISO27001,
            ComplianceFramework::SOC2,
            ComplianceFramework::SOC2,
            ComplianceFramework::NIST800171,
            ComplianceFramework::NIST800171,
            ComplianceFramework::NIST800171,
            ComplianceFramework::FedRAMP,
            ComplianceFramework::FedRAMP,
        ]
    );
}

#[test]
fn parse_frameworks_drops_unknown_silently() {
    let parsed = parse_frameworks(&["nonsense".to_string(), "CIS".to_string()]);
    assert_eq!(parsed, vec![ComplianceFramework::CIS]);
}

#[test]
fn cli_scan_entries_parse_into_scan_results() {
    let json = r#"[{
            "plugin_id": "pam-hardening",
            "plugin_name": "PAM Hardening",
            "findings": [],
            "unchecked": [{
                "unchecked_check_id": "pam-minlen",
                "unchecked_title": "PAM setting: minlen",
                "unchecked_category": "Authentication",
                "unchecked_reason": "reading /etc/security/pwquality.conf requires root",
                "unchecked_compliance": []
            }],
            "scan_success": true,
            "scan_error": null
        }]"#;
    let entries: Vec<CliScanEntry> = serde_json::from_str(json).unwrap();
    let results: Vec<ScanResult> = entries
        .into_iter()
        .map(CliScanEntry::into_scan_result)
        .collect();
    assert_eq!(results[0].scan_unchecked.len(), 1);
    assert!(results[0].scan_success);
}

/// The desktop used to hardcode `scan_success: true`, so a plugin whose
/// scan failed arrived as a clean, finding-free result and the GUI showed
/// a compliant host. The outcome must come from the payload.
#[test]
fn a_failed_cli_scan_entry_stays_failed_through_the_desktop_parser() {
    let json = r#"[{
            "plugin_id": "ssh-hardening",
            "plugin_name": "SSH Hardening",
            "findings": [],
            "unchecked": [],
            "scan_success": false,
            "scan_error": "Failed to read /etc/ssh/sshd_config"
        }]"#;
    let entries: Vec<CliScanEntry> = serde_json::from_str(json).unwrap();
    let result = entries
        .into_iter()
        .map(CliScanEntry::into_scan_result)
        .next()
        .unwrap();

    assert!(
        !result.scan_success,
        "a failed scan must not arrive at the desktop as a success"
    );
    assert_eq!(
        result.scan_error.as_deref(),
        Some("Failed to read /etc/ssh/sshd_config")
    );
}

/// Output from a CLI predating the field must not be read as a pass.
#[test]
fn a_scan_entry_without_the_field_is_not_assumed_successful() {
    let json = r#"[{"plugin_id": "ssh-hardening", "findings": [], "unchecked": []}]"#;
    let entries: Vec<CliScanEntry> = serde_json::from_str(json).unwrap();
    let result = entries
        .into_iter()
        .map(CliScanEntry::into_scan_result)
        .next()
        .unwrap();
    assert!(!result.scan_success, "an unknown outcome must fail closed");
}

/// The per-control outcomes have to survive `posture_for_findings`, which is
/// the one place they were computed and dropped: `ReportGenerator::generate`
/// returns a full `ComplianceReport` per framework and only `report_framework`
/// and `report_summary` were kept. Without them the fleet view can show a
/// compliance count and nothing about what it counts, which is #50.
///
/// The findings are empty on purpose. A control this host was never assessed
/// for is `ManualReview` rather than `Pass`, so an empty scan still produces a
/// full catalogue of outcomes, and the assertion below is about the rows
/// travelling rather than about any particular verdict.
#[test]
fn the_fleet_posture_carries_one_outcome_per_control() {
    let generator = fleet_report_generator(
        ComplianceProfile::Generic,
        hardener_plugins::compliance_coverage(),
        ComplianceConfig::default(),
        &RemoteHostProfile::from_target("web-01", 22, None, true),
    );

    let posture = posture_for_findings(&generator, &[], &[]);

    assert_eq!(
        posture.len(),
        FLEET_FRAMEWORKS.len(),
        "one posture row per fleet framework"
    );
    for framework in &posture {
        assert_eq!(
            framework.controls.len(),
            framework.summary.summary_total_controls,
            "{:?} must carry an outcome for every control its own summary counted",
            framework.framework
        );
    }
    assert!(
        posture.iter().any(|f| !f.controls.is_empty()),
        "the control rows must not be uniformly empty, which every count-equality \
         assertion above would also satisfy"
    );
}

/// One saved inventory host, spelled out rather than parsed, so a test about
/// inventory-versus-ad-hoc precedence cannot accidentally build both sides of
/// the comparison through the same parser.
fn saved_host(name: &str, hostname: &str) -> RemoteHostProfile {
    RemoteHostProfile {
        name: name.to_string(),
        hostname: hostname.to_string(),
        user: Some("ops".to_string()),
        port: 2022,
        key_file: Some("/keys/inventory".to_string()),
        host_key_checking: true,
    }
}

#[test]
fn fleet_targets_keys_inventory_by_name_and_adhoc_by_full_target() {
    let targets = fleet_targets(
        vec![saved_host("web-01", "web-01.example.net")],
        &["root@db-01:2222".to_string()],
    )
    .expect("both targets are well formed");

    assert_eq!(targets.len(), 2);
    assert_eq!(targets["web-01"].hostname, "web-01.example.net");

    // The ad-hoc key is the target string as typed, not the parsed hostname:
    // the fleet rows are named by it and the history is keyed by it.
    let adhoc = &targets["root@db-01:2222"];
    assert_eq!(adhoc.hostname, "db-01");
    assert_eq!(adhoc.port, 2222);
    assert_eq!(adhoc.user.as_deref(), Some("root"));
}

#[test]
fn fleet_targets_lets_an_inventory_host_win_a_name_collision() {
    // An ad-hoc target that happens to spell a saved host's name must not
    // overwrite the saved profile, which carries the real hostname, port, user
    // and key file. Until now this was guarded by `or_insert` and a comment,
    // and swapping it for `insert` broke nothing any test could see.
    let targets = fleet_targets(
        vec![saved_host("db-01", "db-01.internal")],
        &["db-01".to_string()],
    )
    .expect("both targets are well formed");

    assert_eq!(targets.len(), 1, "one key, because both name the same host");
    let kept = &targets["db-01"];
    assert_eq!(
        kept.hostname, "db-01.internal",
        "the ad-hoc parse would have set hostname to the bare name"
    );
    assert_eq!(kept.port, 2022, "the saved port survives the collision");
    assert_eq!(kept.key_file.as_deref(), Some("/keys/inventory"));
}

#[test]
fn fleet_targets_rejects_an_invalid_adhoc_target() {
    // A rejected target fails the whole scan rather than being dropped: a
    // silently skipped host reads as a host with nothing to report.
    let err = fleet_targets(Vec::new(), &["-oProxyCommand=x".to_string()])
        .expect_err("a leading dash is an ssh option, not a hostname");
    assert!(err.contains("Invalid ad-hoc target"), "got: {err}");
}

#[test]
fn ssh_config_for_carries_the_profile_and_maps_host_key_checking() {
    let mut profile = RemoteHostProfile::from_target(
        "ops@db-01:2222",
        22,
        Some("/keys/id_ed25519".to_string()),
        true,
    );

    let strict = ssh_config_for(&profile);
    assert_eq!(strict.host, "db-01");
    assert_eq!(strict.port, 2222);
    assert_eq!(strict.user.as_deref(), Some("ops"));
    assert_eq!(strict.identity_file.as_deref(), Some("/keys/id_ed25519"));
    assert!(
        matches!(strict.known_hosts, hardener_core::KnownHosts::Strict),
        "a host that checks its key must verify it"
    );

    profile.host_key_checking = false;
    assert!(
        matches!(
            ssh_config_for(&profile).known_hosts,
            hardener_core::KnownHosts::Accept
        ),
        "an unchecked host key relaxes to Accept; staying Strict would fail \
         every host the user opted out for"
    );
}

/// Every plugin scanned over a `MockExecutor` that stubs nothing. Plugins that
/// error are logged and skipped by `scan_with_executor`, so this is the set of
/// plugins that survive a host with no files and no commands, and it is the
/// baseline the filter assertions below compare against.
async fn scan_over_empty_mock(plugin_ids: Option<&[String]>) -> Vec<ScanResult> {
    let executor: std::sync::Arc<dyn hardener_core::SystemExecutor> =
        std::sync::Arc::new(hardener_core::MockExecutor::new());
    scan_with_executor(executor, plugin_ids)
        .await
        .expect("a plugin that fails is skipped, never fatal")
}

#[tokio::test]
async fn scan_with_executor_filters_plugins_by_bare_id_prefix() {
    // The GUI sends "kernel"; the registry holds "kernel-hardening". The
    // prefix arm of the filter is what joins them.
    let filtered = scan_over_empty_mock(Some(&["kernel".to_string()])).await;
    assert_eq!(
        filtered.len(),
        1,
        "exactly the kernel plugin, got: {:?}",
        filtered
            .iter()
            .map(|r| r.scan_plugin_id.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(filtered[0].scan_plugin_id.as_str(), "kernel-hardening");
}

#[tokio::test]
async fn scan_with_executor_treats_an_empty_filter_as_no_filter() {
    let unfiltered = scan_over_empty_mock(None).await;
    let empty_filter = scan_over_empty_mock(Some(&[])).await;

    assert!(
        unfiltered.len() > 1,
        "an unfiltered scan that produced nothing would satisfy every equality \
         below whatever the filter did"
    );
    assert_eq!(
        unfiltered.len(),
        empty_filter.len(),
        "an empty id list means no filter, not no plugins"
    );
}
