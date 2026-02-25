use hardener_state::{ScanHistoryManager, ScanStatus, init_db};
use hardener_types::{Finding, FindingCategory, PluginId, ScanResult, Severity};
use tempfile::tempdir;

async fn create_test_manager() -> (ScanHistoryManager, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let pool = init_db(Some(&db_path)).await.unwrap();
    (ScanHistoryManager::new(pool), dir)
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
    let results = vec![ScanResult {
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
            finding_policy_exception: None,
        }],
        scan_duration_us: 1000,
        scan_error: None,
    }];

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
