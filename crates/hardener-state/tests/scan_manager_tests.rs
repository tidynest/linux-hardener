use hardener_state::{ScanHistoryManager, ScanStatus, init_db};
use hardener_types::{
    ComplianceFramework, ComplianceMapping, DeclineReason, ExceptionOutcome, Finding,
    FindingCategory, FindingExceptionDeclined, FindingPolicyException, PluginId, ScanResult,
    Severity, UncheckedCheck,
};
use tempfile::tempdir;

async fn create_test_manager() -> (ScanHistoryManager, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let pool = init_db(Some(&db_path)).await.unwrap();
    (ScanHistoryManager::new(pool), dir)
}

/// One successful plugin result holding a single finding.
fn sample_results() -> Vec<ScanResult> {
    vec![ScanResult {
        scan_plugin_id: PluginId::new("test_plugin"),
        scan_success: true,
        scan_findings: vec![Finding {
            finding_id: "TEST-001".to_string(),
            finding_category: FindingCategory::Kernel,
            finding_severity: Severity::High,
            finding_title: "Test Finding".to_string(),
            finding_description: "A test finding".to_string(),
            finding_explanation: "This is a test".to_string(),
            finding_impact: "None".to_string(),
            finding_current_value: "bad".to_string(),
            finding_recommended_value: "good".to_string(),
            finding_remediation_steps: vec!["Step 1".to_string()],
            finding_compliance: vec![],
            finding_exception: ExceptionOutcome::NotConfigured,
            finding_exception_key: Some("test-exception-key".to_string()),
        }],
        scan_duration_us: 1000,
        scan_error: None,
        scan_unchecked: vec![],
    }]
}

#[tokio::test]
async fn test_start_session() {
    let (manager, _dir) = create_test_manager().await;

    let session_id = manager.start_session().await.unwrap();
    assert!(session_id.as_str().starts_with("scan_"));
}

#[tokio::test]
async fn test_store_and_retrieve_results() {
    let (manager, _dir) = create_test_manager().await;

    // Start a session
    let session_id = manager.start_session().await.unwrap();

    // Create test results
    let results = sample_results();

    // Store results
    manager.store_results(&session_id, &results).await.unwrap();

    // Complete the session
    manager
        .complete_session(&session_id, ScanStatus::Completed, 1, 1)
        .await
        .unwrap();

    // Retrieve and verify
    let (session, retrieved_results) = manager.get_latest_scan().await.unwrap().unwrap();

    assert_eq!(session.session_status, ScanStatus::Completed);
    assert_eq!(session.session_total_findings, 1);
    assert_eq!(retrieved_results.len(), 1);
    assert_eq!(retrieved_results[0].scan_findings.len(), 1);
    assert_eq!(retrieved_results[0].scan_findings[0].finding_id, "TEST-001");
}

#[tokio::test]
async fn test_list_sessions() {
    let (manager, _dir) = create_test_manager().await;

    // Create multiple sessions
    for _ in 0..3 {
        let session_id = manager.start_session().await.unwrap();
        manager
            .complete_session(&session_id, ScanStatus::Completed, 0, 0)
            .await
            .unwrap();
    }

    let sessions = manager.list_sessions(10).await.unwrap();
    assert_eq!(sessions.len(), 3);
}

#[tokio::test]
async fn test_cleanup_old_sessions() {
    let (manager, _dir) = create_test_manager().await;

    // Create 5 sessions
    for _ in 0..5 {
        let session_id = manager.start_session().await.unwrap();
        manager
            .complete_session(&session_id, ScanStatus::Completed, 0, 0)
            .await
            .unwrap();
    }

    // Keep only 2
    let deleted = manager.cleanup_old_sessions(2).await.unwrap();
    assert_eq!(deleted, 3);

    let remaining = manager.list_sessions(10).await.unwrap();
    assert_eq!(remaining.len(), 2);
}

#[tokio::test]
async fn test_corrupted_policy_exception_json_surfaces_error() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let pool = init_db(Some(&db_path)).await.unwrap();
    let manager = ScanHistoryManager::new(pool.clone());

    let session_id = manager.start_session().await.unwrap();
    manager
        .store_results(&session_id, &sample_results())
        .await
        .unwrap();
    manager
        .complete_session(&session_id, ScanStatus::Completed, 1, 1)
        .await
        .unwrap();

    // Corrupt the stored row behind the manager's back.
    sqlx::query("UPDATE scan_findings SET policy_exception = 'not json'")
        .execute(&pool)
        .await
        .unwrap();

    let Err(err) = manager.get_latest_scan().await else {
        panic!("corrupted policy_exception JSON must surface an error");
    };
    assert!(
        err.to_string().contains("Corrupted policy_exception"),
        "error names the corrupted column: {err}"
    );
}

#[tokio::test]
async fn latest_scan_round_trips_findings_and_unchecked_together() {
    // The desktop compliance report reads the latest completed session via
    // get_latest_scan, so a session holding both findings and unchecked
    // checks must round-trip both through that exact path.
    let (manager, _dir) = create_test_manager().await;
    let session_id = manager.start_session().await.unwrap();

    let mut results = sample_results();
    results[0].scan_unchecked = vec![UncheckedCheck {
        unchecked_check_id: "kernel-kptr-restrict".to_string(),
        unchecked_title: "Kernel setting: kptr_restrict".to_string(),
        unchecked_category: FindingCategory::Kernel,
        unchecked_reason: "reading /proc/sys/kernel/kptr_restrict requires root".to_string(),
        unchecked_blocker: hardener_types::UncheckedBlocker::Environment,
        unchecked_compliance: vec![],
    }];

    manager.store_results(&session_id, &results).await.unwrap();
    manager
        .complete_session(&session_id, ScanStatus::Completed, 1, 1)
        .await
        .unwrap();

    let (session, restored) = manager.get_latest_scan().await.unwrap().unwrap();
    assert_eq!(session.session_status, ScanStatus::Completed);
    assert_eq!(restored.len(), 1);

    let finding = &restored[0].scan_findings[0];
    assert_eq!(finding.finding_id, "TEST-001");
    assert_eq!(finding.finding_severity, Severity::High);
    assert_eq!(finding.finding_current_value, "bad");
    assert_eq!(
        finding.finding_remediation_steps,
        vec!["Step 1".to_string()]
    );

    let unchecked = &restored[0].scan_unchecked[0];
    assert_eq!(unchecked.unchecked_check_id, "kernel-kptr-restrict");
    assert_eq!(
        unchecked.unchecked_reason,
        "reading /proc/sys/kernel/kptr_restrict requires root"
    );
}

#[tokio::test]
async fn fail_session_marks_status_failed_with_zeroed_totals() {
    let (manager, _dir) = create_test_manager().await;
    let session_id = manager.start_session().await.unwrap();

    manager.fail_session(&session_id).await.unwrap();

    let sessions = manager.list_sessions(10).await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_status, ScanStatus::Failed);
    assert_eq!(sessions[0].session_total_findings, 0);
    assert_eq!(sessions[0].session_total_plugins, 0);
}

#[tokio::test]
async fn failed_session_is_excluded_from_latest_scan_but_a_later_completed_one_is_returned() {
    // Mirrors an aborted GUI scan (e.g. a cancelled pkexec prompt): the
    // orphaned 'running' row gets marked Failed instead, and must stay
    // invisible to get_latest_scan while a later successful scan is found.
    let (manager, _dir) = create_test_manager().await;

    let failed_id = manager.start_session().await.unwrap();
    manager.fail_session(&failed_id).await.unwrap();

    assert!(
        manager.get_latest_scan().await.unwrap().is_none(),
        "a session with only a failed run must not be reported as the latest scan"
    );

    let completed_id = manager.start_session().await.unwrap();
    manager
        .store_results(&completed_id, &sample_results())
        .await
        .unwrap();
    manager
        .complete_session(&completed_id, ScanStatus::Completed, 1, 1)
        .await
        .unwrap();

    let (session, _) = manager.get_latest_scan().await.unwrap().unwrap();
    assert_eq!(session.session_id, completed_id);
    assert_eq!(session.session_status, ScanStatus::Completed);
}

#[tokio::test]
async fn get_latest_scan_breaks_a_same_second_tie_by_insertion_order() {
    // start_session records started_at at second resolution, so two
    // sessions completed back-to-back in a fast test run (or on a real
    // host that races two scans) commonly land on the same second. The
    // later-inserted session must still win the "latest" pick.
    let (manager, _dir) = create_test_manager().await;

    let first_id = manager.start_session().await.unwrap();
    manager
        .complete_session(&first_id, ScanStatus::Completed, 0, 1)
        .await
        .unwrap();

    let second_id = manager.start_session().await.unwrap();
    manager
        .complete_session(&second_id, ScanStatus::Completed, 0, 1)
        .await
        .unwrap();

    let (session, _) = manager.get_latest_scan().await.unwrap().unwrap();
    assert_eq!(session.session_id, second_id);
}

#[tokio::test]
async fn unchecked_checks_survive_store_and_restore() {
    let (manager, _dir) = create_test_manager().await;
    let session_id = manager.start_session().await.unwrap();
    let result = ScanResult {
        scan_plugin_id: PluginId::new("pam-hardening"),
        scan_success: true,
        scan_findings: vec![],
        scan_unchecked: vec![UncheckedCheck {
            unchecked_check_id: "pam-minlen".to_string(),
            unchecked_title: "PAM setting: minlen".to_string(),
            unchecked_category: FindingCategory::Authentication,
            unchecked_reason: "reading /etc/security/pwquality.conf requires root".to_string(),
            unchecked_blocker: hardener_types::UncheckedBlocker::Environment,
            unchecked_compliance: vec![],
        }],
        scan_duration_us: 1,
        scan_error: None,
    };
    manager.store_results(&session_id, &[result]).await.unwrap();
    let restored = manager.get_session_results(&session_id).await.unwrap();
    assert_eq!(restored[0].scan_unchecked.len(), 1);
    assert_eq!(
        restored[0].scan_unchecked[0].unchecked_check_id,
        "pam-minlen"
    );
}

/// The key an operator writes an exception under is the one thing a stored
/// finding could not carry: the rebuild hardcoded it as `None` regardless of
/// what the plugin found.
#[tokio::test]
async fn exception_key_survives_store_and_reload() {
    let (manager, _dir) = create_test_manager().await;
    let session_id = manager.start_session().await.unwrap();

    let mut results = sample_results();
    results[0].scan_findings[0].finding_exception_key = Some("net.ipv4.ip_forward".to_string());

    manager.store_results(&session_id, &results).await.unwrap();
    manager
        .complete_session(&session_id, ScanStatus::Completed, 1, 1)
        .await
        .unwrap();

    let (_, restored) = manager.get_latest_scan().await.unwrap().unwrap();
    assert_eq!(
        restored[0].scan_findings[0]
            .finding_exception_key
            .as_deref(),
        Some("net.ipv4.ip_forward"),
        "a dotted key is not a bare TOML key and must survive verbatim"
    );
}

/// A finding an exception could not be about stores no key, and must read back
/// as no key rather than as an empty one, which would advertise a setting an
/// operator could write and that would change nothing.
#[tokio::test]
async fn a_finding_without_an_exception_key_reloads_without_one() {
    let (manager, _dir) = create_test_manager().await;
    let session_id = manager.start_session().await.unwrap();

    let mut results = sample_results();
    results[0].scan_findings[0].finding_exception_key = None;

    manager.store_results(&session_id, &results).await.unwrap();
    manager
        .complete_session(&session_id, ScanStatus::Completed, 1, 1)
        .await
        .unwrap();

    let (_, restored) = manager.get_latest_scan().await.unwrap().unwrap();
    assert_eq!(
        restored[0].scan_findings[0].finding_exception_key, None,
        "no key must read back as None, never as Some(\"\")"
    );
}

/// Every field of a `Finding` must survive the database, not only the fields
/// somebody wrote an assertion for.
///
/// `finding_exception_key` shipped as a hardcoded `None` in the rebuild and no
/// test noticed, because a per-field assertion only ever reaches the fields it
/// was written for. Comparing the whole struct needs no per-field assertion:
/// serde enumerates the fields, so a fourteenth one added and left unpersisted
/// fails here with nobody having written a case for it.
///
/// Every value carries a distinct marker. A field rebuilt as `String::new()`
/// against a fixture that also held `""` would pass while dropping the value.
#[tokio::test]
async fn every_finding_field_survives_the_scan_history() {
    let (manager, _dir) = create_test_manager().await;
    let session_id = manager.start_session().await.unwrap();

    let original = Finding {
        finding_id: "marker-id".to_string(),
        finding_category: FindingCategory::MandatoryAccessControl,
        finding_severity: Severity::Critical,
        finding_title: "marker-title".to_string(),
        finding_description: "marker-description".to_string(),
        finding_explanation: "marker-explanation".to_string(),
        finding_impact: "marker-impact".to_string(),
        finding_current_value: "marker-current".to_string(),
        finding_recommended_value: "marker-recommended".to_string(),
        finding_remediation_steps: vec![
            "marker-step-one".to_string(),
            "marker-step-two".to_string(),
        ],
        finding_compliance: vec![ComplianceMapping {
            compliance_framework: ComplianceFramework::CIS,
            compliance_control_id: "marker-control-id".to_string(),
            compliance_control_title: "marker-control-title".to_string(),
            compliance_section: Some("marker-section".to_string()),
        }],
        finding_exception: ExceptionOutcome::Applied(FindingPolicyException {
            exception_allowed_value: "marker-allowed".to_string(),
            exception_reason: "marker-reason".to_string(),
            exception_approved_by: Some("marker-approver".to_string()),
            exception_approved_date: Some("2026-08-06".to_string()),
            exception_ticket: Some("marker-ticket".to_string()),
            exception_expires: Some("2027-08-06".to_string()),
            exception_is_expired: true,
        }),
        finding_exception_key: Some("marker-exception-key".to_string()),
    };

    let mut results = sample_results();
    results[0].scan_findings = vec![original.clone()];

    manager.store_results(&session_id, &results).await.unwrap();
    manager
        .complete_session(&session_id, ScanStatus::Completed, 1, 1)
        .await
        .unwrap();

    let (_, restored) = manager.get_latest_scan().await.unwrap().unwrap();
    let reloaded = &restored[0].scan_findings[0];

    assert_eq!(
        serde_json::to_value(&original).unwrap(),
        serde_json::to_value(reloaded).unwrap(),
        "a finding must come back exactly as it went in: a field missing from \
         the INSERT, hardcoded in the rebuild, or lost by a str conversion \
         shows up here as a difference"
    );
}

/// A declined exception is a live violation carrying the reason it did not
/// apply, and must survive the round trip rather than being folded into
/// `NotConfigured` for lack of a column to hold it.
#[tokio::test]
async fn a_declined_exception_round_trips() {
    let (manager, _dir) = create_test_manager().await;
    let session_id = manager.start_session().await.unwrap();

    let mut results = sample_results();
    results[0].scan_findings[0].finding_exception =
        ExceptionOutcome::Declined(FindingExceptionDeclined {
            exception_declined_reason: DeclineReason::Expired {
                expired_on: "2026-01-01".to_string(),
            },
            exception_reason: "temporary waiver".to_string(),
        });

    manager.store_results(&session_id, &results).await.unwrap();
    manager
        .complete_session(&session_id, ScanStatus::Completed, 1, 1)
        .await
        .unwrap();

    let (_, restored) = manager.get_latest_scan().await.unwrap().unwrap();
    let stored = &restored[0].scan_findings[0];

    match &stored.finding_exception {
        ExceptionOutcome::Declined(declined) => match &declined.exception_declined_reason {
            DeclineReason::Expired { expired_on } => {
                assert_eq!(
                    expired_on, "2026-01-01",
                    "the expiry survives the round trip"
                );
            }
            other => panic!("the arm changed on the way through: {other:?}"),
        },
        other => panic!("expected Declined, got {other:?}"),
    }

    let ExceptionOutcome::Declined(declined) = &stored.finding_exception else {
        panic!("already matched above, so this cannot differ");
    };
    assert_eq!(
        declined.exception_reason, "temporary waiver",
        "the operator's own reason survives the round trip too"
    );
}
