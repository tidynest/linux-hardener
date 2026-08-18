use hardener_state::audit::QueryFilter;
use hardener_state::{ActionResult, ActionType, AuditLogger};
use std::collections::HashMap;
use tempfile::NamedTempFile;

#[tokio::test]
async fn test_audit_logger_basic() {
    let temp_file = NamedTempFile::new().unwrap();
    let log_path = temp_file.path().to_str().unwrap();

    let logger = AuditLogger::new(log_path).await.unwrap();

    // Log a successful action
    logger
        .log_action(
            ActionType::Scan,
            "testuser".to_string(),
            "/etc/ssh/sshd_config".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    // Verify integrity
    let is_valid = AuditLogger::verify_integrity(log_path).await.unwrap();
    assert!(is_valid);
}

#[tokio::test]
async fn test_multiple_entries_appending() {
    let temp_file = NamedTempFile::new().unwrap();
    let log_path = temp_file.path().to_str().unwrap();

    let logger = AuditLogger::new(log_path).await.unwrap();

    // Log multiple different actions
    logger
        .log_action(
            ActionType::Scan,
            "alice".to_string(),
            "/etc/ssh/sshd_config".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    logger
        .log_action(
            ActionType::Apply,
            "bob".to_string(),
            "kernel_hardening".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    logger
        .log_failure(
            ActionType::Rollback,
            "alice".to_string(),
            "checkpoint_123".to_string(),
            "Checkpoint not found".to_string(),
        )
        .await
        .unwrap();

    // Query all entries
    let all_entries = AuditLogger::query(log_path, QueryFilter::new())
        .await
        .unwrap();

    // Should have exactly 3 entries
    assert_eq!(all_entries.len(), 3);

    // Verify the entries are in order
    assert_eq!(all_entries[0].entry_action_type, ActionType::Scan);
    assert_eq!(all_entries[0].entry_user, "alice");
    assert_eq!(all_entries[0].entry_result, ActionResult::Success);

    assert_eq!(all_entries[1].entry_action_type, ActionType::Apply);
    assert_eq!(all_entries[1].entry_user, "bob");

    assert_eq!(all_entries[2].entry_action_type, ActionType::Rollback);
    assert_eq!(all_entries[2].entry_result, ActionResult::Failure);
    assert_eq!(
        all_entries[2].entry_details.get("error").unwrap(),
        "Checkpoint not found"
    );

    // Verify integrity is still valid
    let is_valid = AuditLogger::verify_integrity(log_path).await.unwrap();
    assert!(is_valid);
}

#[tokio::test]
async fn test_query_filter_by_action_type() {
    let temp_file = NamedTempFile::new().unwrap();
    let log_path = temp_file.path().to_str().unwrap();

    let logger = AuditLogger::new(log_path).await.unwrap();

    // Log various action types
    logger
        .log_action(
            ActionType::Scan,
            "user1".to_string(),
            "target1".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    logger
        .log_action(
            ActionType::Apply,
            "user2".to_string(),
            "target2".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    logger
        .log_action(
            ActionType::Scan,
            "user3".to_string(),
            "target3".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    logger
        .log_action(
            ActionType::CheckpointCreate,
            "user1".to_string(),
            "cp_001".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    // Query only Scan actions
    let scan_filter = QueryFilter::new().with_action_type(ActionType::Scan);
    let scan_entries = AuditLogger::query(log_path, scan_filter).await.unwrap();

    // Should have exactly 2 Scan entries
    assert_eq!(scan_entries.len(), 2);
    assert!(
        scan_entries
            .iter()
            .all(|e| e.entry_action_type == ActionType::Scan)
    );

    // Query only Apply actions
    let apply_filter = QueryFilter::new().with_action_type(ActionType::Apply);
    let apply_entries = AuditLogger::query(log_path, apply_filter).await.unwrap();

    // Should have exactly 1 Apply entry
    assert_eq!(apply_entries.len(), 1);
    assert_eq!(apply_entries[0].entry_action_type, ActionType::Apply);
    assert_eq!(apply_entries[0].entry_user, "user2");
}

#[tokio::test]
async fn test_query_filter_by_user() {
    let temp_file = NamedTempFile::new().unwrap();
    let log_path = temp_file.path().to_str().unwrap();

    let logger = AuditLogger::new(log_path).await.unwrap();

    // Log actions by different users
    logger
        .log_action(
            ActionType::Scan,
            "alice".to_string(),
            "target1".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    logger
        .log_action(
            ActionType::Apply,
            "bob".to_string(),
            "target2".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    logger
        .log_action(
            ActionType::Rollback,
            "alice".to_string(),
            "target3".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    logger
        .log_action(
            ActionType::CheckpointCreate,
            "charlie".to_string(),
            "cp_001".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    // Query actions by alice
    let alice_filter = QueryFilter::new().with_user("alice".to_string());
    let alice_entries = AuditLogger::query(log_path, alice_filter).await.unwrap();

    // Should have exactly 2 entries for alice
    assert_eq!(alice_entries.len(), 2);
    assert!(alice_entries.iter().all(|e| e.entry_user == "alice"));

    // Query actions by bob
    let bob_filter = QueryFilter::new().with_user("bob".to_string());
    let bob_entries = AuditLogger::query(log_path, bob_filter).await.unwrap();

    // Should have exactly 1 entry for bob
    assert_eq!(bob_entries.len(), 1);
    assert_eq!(bob_entries[0].entry_user, "bob");
    assert_eq!(bob_entries[0].entry_action_type, ActionType::Apply);
}

#[tokio::test]
async fn test_query_filter_by_result() {
    let temp_file = NamedTempFile::new().unwrap();
    let log_path = temp_file.path().to_str().unwrap();

    let logger = AuditLogger::new(log_path).await.unwrap();

    // Log mix of successful and failed actions
    logger
        .log_action(
            ActionType::Scan,
            "user1".to_string(),
            "target1".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    logger
        .log_failure(
            ActionType::Apply,
            "user2".to_string(),
            "target2".to_string(),
            "Permission denied".to_string(),
        )
        .await
        .unwrap();

    logger
        .log_action(
            ActionType::Rollback,
            "user3".to_string(),
            "target3".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    logger
        .log_failure(
            ActionType::CheckpointCreate,
            "user4".to_string(),
            "cp_001".to_string(),
            "Disk full".to_string(),
        )
        .await
        .unwrap();

    // Query only successful actions
    let success_filter = QueryFilter::new().with_result(ActionResult::Success);
    let success_entries = AuditLogger::query(log_path, success_filter).await.unwrap();

    // Should have exactly 2 successful entries
    assert_eq!(success_entries.len(), 2);
    assert!(
        success_entries
            .iter()
            .all(|e| e.entry_result == ActionResult::Success)
    );

    // Query only failed actions
    let failure_filter = QueryFilter::new().with_result(ActionResult::Failure);
    let failure_entries = AuditLogger::query(log_path, failure_filter).await.unwrap();

    // Should have exactly 2 failed entries
    assert_eq!(failure_entries.len(), 2);
    assert!(
        failure_entries
            .iter()
            .all(|e| e.entry_result == ActionResult::Failure)
    );

    // Verify error messages are present in failures
    assert!(failure_entries[0].entry_details.contains_key("error"));
    assert!(failure_entries[1].entry_details.contains_key("error"));
}

#[tokio::test]
async fn test_query_combined_filters() {
    let temp_file = NamedTempFile::new().unwrap();
    let log_path = temp_file.path().to_str().unwrap();

    let logger = AuditLogger::new(log_path).await.unwrap();

    // Log various combinations
    logger
        .log_action(
            ActionType::Scan,
            "alice".to_string(),
            "target1".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    logger
        .log_failure(
            ActionType::Scan,
            "alice".to_string(),
            "target2".to_string(),
            "Error occurred".to_string(),
        )
        .await
        .unwrap();

    logger
        .log_action(
            ActionType::Scan,
            "bob".to_string(),
            "target3".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    logger
        .log_action(
            ActionType::Apply,
            "alice".to_string(),
            "target4".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    // Query: Scan actions by alice that were successful
    let combined_filter = QueryFilter::new()
        .with_action_type(ActionType::Scan)
        .with_user("alice".to_string())
        .with_result(ActionResult::Success);

    let entries = AuditLogger::query(log_path, combined_filter).await.unwrap();

    // Should have exactly 1 entry matching all criteria
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].entry_action_type, ActionType::Scan);
    assert_eq!(entries[0].entry_user, "alice");
    assert_eq!(entries[0].entry_result, ActionResult::Success);
    assert_eq!(entries[0].entry_target, "target1");
}

#[tokio::test]
async fn test_tamper_detection() {
    let temp_file = NamedTempFile::new().unwrap();
    let log_path = temp_file.path().to_str().unwrap();

    let logger = AuditLogger::new(log_path).await.unwrap();

    // Log some entries
    logger
        .log_action(
            ActionType::Scan,
            "alice".to_string(),
            "target1".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    logger
        .log_action(
            ActionType::Apply,
            "bob".to_string(),
            "target2".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    // Verify integrity before tampering
    let is_valid = AuditLogger::verify_integrity(log_path).await.unwrap();
    assert!(is_valid);

    // Now tamper with the log file by modifying an entry
    let content = tokio::fs::read_to_string(log_path).await.unwrap();
    let lines: Vec<&str> = content.lines().collect();

    // Modify the first entry (change user from "alice" to "eve")
    let mut first_entry: hardener_state::AuditEntry = serde_json::from_str(lines[0]).unwrap();
    first_entry.entry_user = "eve".to_string();

    // Write the tampered entry back
    let tampered_line = serde_json::to_string(&first_entry).unwrap();
    let mut new_content = String::new();
    new_content.push_str(&tampered_line);
    new_content.push('\n');
    new_content.push_str(lines[1]);
    new_content.push('\n');

    tokio::fs::write(log_path, new_content).await.unwrap();

    // Verify integrity after tampering - should detect tampering
    let is_valid = AuditLogger::verify_integrity(log_path).await.unwrap();
    assert!(!is_valid, "Tampering should have been detected!");
}

#[tokio::test]
async fn test_query_filter_by_time_range() {
    let temp_file = NamedTempFile::new().unwrap();
    let log_path = temp_file.path().to_str().unwrap();

    let logger = AuditLogger::new(log_path).await.unwrap();

    // Log first entry
    logger
        .log_action(
            ActionType::Scan,
            "user1".to_string(),
            "target1".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    // Wait a bit to create time separation
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let middle_time = chrono::Utc::now();
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Log second entry (after middle_time)
    logger
        .log_action(
            ActionType::Apply,
            "user2".to_string(),
            "target2".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Log third entry (even later)
    logger
        .log_action(
            ActionType::Rollback,
            "user3".to_string(),
            "target3".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    // Query entries after middle_time
    let filter = QueryFilter::new().with_start_time(middle_time);
    let entries = AuditLogger::query(log_path, filter).await.unwrap();

    // Should have 2 entries (the last two)
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].entry_action_type, ActionType::Apply);
    assert_eq!(entries[1].entry_action_type, ActionType::Rollback);

    // Query entries before middle_time
    let filter = QueryFilter::new().with_end_time(middle_time);
    let entries = AuditLogger::query(log_path, filter).await.unwrap();

    // Should have 1 entry (the first one)
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].entry_action_type, ActionType::Scan);
}

#[tokio::test]
async fn test_query_empty_filter_returns_all() {
    let temp_file = NamedTempFile::new().unwrap();
    let log_path = temp_file.path().to_str().unwrap();

    let logger = AuditLogger::new(log_path).await.unwrap();

    // Log 5 different entries
    logger
        .log_action(
            ActionType::Scan,
            "user1".to_string(),
            "target1".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    logger
        .log_failure(
            ActionType::Apply,
            "user2".to_string(),
            "target2".to_string(),
            "Error".to_string(),
        )
        .await
        .unwrap();

    logger
        .log_action(
            ActionType::Rollback,
            "user3".to_string(),
            "target3".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    logger
        .log_action(
            ActionType::CheckpointCreate,
            "user4".to_string(),
            "cp_001".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    logger
        .log_action(
            ActionType::ConfigChange,
            "user5".to_string(),
            "config.toml".to_string(),
            ActionResult::Success,
        )
        .await
        .unwrap();

    // Query with empty filter (should return all)
    let all_entries = AuditLogger::query(log_path, QueryFilter::new())
        .await
        .unwrap();

    // Should have all 5 entries
    assert_eq!(all_entries.len(), 5);
}

fn details() -> HashMap<String, String> {
    let mut d = HashMap::new();
    d.insert("operation".to_string(), "exclude".to_string());
    d.insert("reason".to_string(), "No physical premises".to_string());
    d.insert("review_by".to_string(), "2027-08-18".to_string());
    d
}

#[tokio::test]
async fn a_details_bearing_entry_round_trips_and_verifies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.log");
    let path_str = path.to_str().expect("utf-8 path");

    let logger = AuditLogger::new(path_str).await.expect("logger");
    logger
        .log_action_with_details(
            ActionType::ScopeExclusion,
            "eric".to_string(),
            "iso27001:A.7.1".to_string(),
            ActionResult::Success,
            details(),
        )
        .await
        .expect("logged");

    let entries = AuditLogger::query(path_str, QueryFilter::new())
        .await
        .expect("query");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].entry_action_type, ActionType::ScopeExclusion);
    assert_eq!(entries[0].entry_target, "iso27001:A.7.1");
    assert_eq!(
        entries[0].entry_details.get("reason").map(String::as_str),
        Some("No physical premises")
    );

    assert!(
        AuditLogger::verify_integrity(path_str)
            .await
            .expect("verify"),
        "a details-bearing success entry must still verify"
    );
}

/// The regression this task exists for. Details are inside the hash, so
/// rewriting a reason after the fact must break verification.
#[tokio::test]
async fn tampering_with_details_is_detected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.log");
    let path_str = path.to_str().expect("utf-8 path");

    let logger = AuditLogger::new(path_str).await.expect("logger");
    logger
        .log_action_with_details(
            ActionType::ScopeExclusion,
            "eric".to_string(),
            "iso27001:A.7.1".to_string(),
            ActionResult::Success,
            details(),
        )
        .await
        .expect("logged");
    drop(logger);

    let original = std::fs::read_to_string(&path).expect("read");
    let tampered = original.replace("No physical premises", "Approved by management");
    assert_ne!(original, tampered, "the replacement actually fired");
    std::fs::write(&path, tampered).expect("write");

    assert!(
        !AuditLogger::verify_integrity(path_str)
            .await
            .expect("verify"),
        "an altered reason must fail verification"
    );
}

/// Backwards compatibility. An entry written before details existed carries an
/// empty map and was hashed as a five-tuple; it must still verify.
#[tokio::test]
async fn a_detail_free_success_entry_still_verifies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.log");
    let path_str = path.to_str().expect("utf-8 path");

    let logger = AuditLogger::new(path_str).await.expect("logger");
    logger
        .log_action(
            ActionType::Scan,
            "eric".to_string(),
            "localhost".to_string(),
            ActionResult::Success,
        )
        .await
        .expect("logged");

    assert!(
        AuditLogger::verify_integrity(path_str)
            .await
            .expect("verify"),
        "the pre-existing five-tuple hash must not be invalidated"
    );
}

/// A `Failure` through the details-bearing writer is refused, because the
/// failure branch of `verify_integrity` hashes the legacy six-tuple ending in
/// the `error` string and never reaches `hashable`. No details map makes the
/// two agree, and the log is append-only, so one such entry would fail
/// verification for the whole file permanently.
#[tokio::test]
async fn a_failure_result_is_refused_by_the_details_writer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.log");
    let path_str = path.to_str().expect("utf-8 path");

    let logger = AuditLogger::new(path_str).await.expect("logger");
    let refused = logger
        .log_action_with_details(
            ActionType::ScopeExclusion,
            "eric".to_string(),
            "iso27001:A.7.1".to_string(),
            ActionResult::Failure,
            details(),
        )
        .await;

    let error = refused.expect_err("a Failure must be rejected, not written");
    assert!(
        error.to_string().contains("log_failure"),
        "the refusal must name the correct method, got: {error}"
    );

    // Nothing was written, so the chain is untouched and still verifies.
    assert_eq!(
        std::fs::read_to_string(&path).expect("read"),
        "",
        "a refused call must not append an entry"
    );
    assert!(
        AuditLogger::verify_integrity(path_str)
            .await
            .expect("verify")
    );
}

/// A success entry written by the v1.5.1 code, captured verbatim from a
/// throwaway run at commit 9725dcb5 (the parent of the details work) and
/// hard-coded here including its `entry_hash` bytes.
///
/// Reconstructing this line with the current code would prove nothing: writer
/// and verifier would agree by construction whatever `hashable` emits. Only a
/// fixture the pre-change binary produced can catch a change to the five-tuple
/// success hash, which every released `audit.log` depends on.
const V1_5_1_SUCCESS_ENTRY: &str = r#"{"entry_timestamp":"2026-08-18T18:20:01.601580572Z","entry_action_type":"Scan","entry_user":"eric","entry_target":"localhost","entry_result":"Success","entry_details":{},"entry_hash":[87,228,192,248,62,138,232,146,196,188,119,150,140,158,47,228,6,70,37,108,204,213,34,104,178,52,179,251,164,139,96,182]}"#;

/// Backwards compatibility against an already-released binary, which the
/// write-then-verify test above cannot check. Removing the `details.is_empty()`
/// guard in `hashable` leaves that one green and turns this one red.
#[tokio::test]
async fn a_v1_5_1_entry_still_verifies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.log");
    let path_str = path.to_str().expect("utf-8 path");

    std::fs::write(&path, format!("{V1_5_1_SUCCESS_ENTRY}\n")).expect("write fixture");

    assert!(
        AuditLogger::verify_integrity(path_str)
            .await
            .expect("verify"),
        "a log written by v1.5.1 must still verify: the five-tuple success hash \
         is a released format, not an internal detail"
    );
}

/// Both shapes in one chain, since a real log will interleave them.
#[tokio::test]
async fn a_mixed_chain_verifies_end_to_end() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.log");
    let path_str = path.to_str().expect("utf-8 path");

    let logger = AuditLogger::new(path_str).await.expect("logger");
    logger
        .log_action(
            ActionType::Scan,
            "eric".into(),
            "localhost".into(),
            ActionResult::Success,
        )
        .await
        .expect("logged");
    logger
        .log_action_with_details(
            ActionType::ScopeExclusion,
            "eric".into(),
            "iso27001:A.7.1".into(),
            ActionResult::Success,
            details(),
        )
        .await
        .expect("logged");
    logger
        .log_failure(
            ActionType::Apply,
            "eric".into(),
            "sshd".into(),
            "denied".into(),
        )
        .await
        .expect("logged");

    assert!(
        AuditLogger::verify_integrity(path_str)
            .await
            .expect("verify")
    );
}
