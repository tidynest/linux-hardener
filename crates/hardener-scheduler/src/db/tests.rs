#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`db`](super).
//!
//! Split out of `db.rs`. This file sits in the `db/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::db` and every import carried
//! across unchanged, private items included.
//!
//! 289 test lines over the host-aware scan history, the database batch and scheduled scans write.

use super::*;
use tempfile::tempdir;

#[tokio::test]
async fn create_and_retrieve_session() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let manager = ScanHistoryManager::new(&db_path).await.unwrap();

    let id = manager
        .create_session("daemon", "localhost", &["kernel".into(), "ssh".into()])
        .await
        .unwrap();

    let session = manager.get_session(&id).await.unwrap().unwrap();
    assert_eq!(session.status, "running");
    assert_eq!(session.host_identifier, "localhost");
    assert_eq!(session.plugins().unwrap(), vec!["kernel", "ssh"]);
}

#[tokio::test]
async fn complete_session_with_findings() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let manager = ScanHistoryManager::new(&db_path).await.unwrap();

    let id = manager
        .create_session("systemd", "server1", &[])
        .await
        .unwrap();

    let findings = vec![
        ScanFinding {
            plugin_id: "kernel".into(),
            finding_id: "K001".into(),
            severity: "high".into(),
            title: "Test finding".into(),
            description: None,
            current_value: None,
            recommended_value: None,
            category: None,
            compliance_mappings: None,
        },
        ScanFinding {
            plugin_id: "ssh".into(),
            finding_id: "S001".into(),
            severity: "critical".into(),
            title: "SSH issue".into(),
            description: Some("Details".into()),
            current_value: None,
            recommended_value: None,
            category: None,
            compliance_mappings: Some(vec!["CIS-1.1".into()]),
        },
    ];

    manager
        .complete_session(&id, &findings, Some("/tmp/scan.json"), None)
        .await
        .unwrap();

    let session = manager.get_session(&id).await.unwrap().unwrap();
    assert_eq!(session.status, "completed");
    assert_eq!(session.total_findings, 2);
    assert_eq!(session.critical_count, 1);
    assert_eq!(session.high_count, 1);

    let stored_findings = manager.get_findings(&id).await.unwrap();
    assert_eq!(stored_findings.len(), 2);
}

#[tokio::test]
async fn fail_session_records_error() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let manager = ScanHistoryManager::new(&db_path).await.unwrap();

    let id = manager
        .create_session("daemon", "localhost", &[])
        .await
        .unwrap();

    manager
        .fail_session(&id, "Connection refused")
        .await
        .unwrap();

    let session = manager.get_session(&id).await.unwrap().unwrap();
    assert_eq!(session.status, "failed");
    assert_eq!(session.error_message, Some("Connection refused".into()));
}

#[tokio::test]
async fn list_sessions_with_filter() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let manager = ScanHistoryManager::new(&db_path).await.unwrap();

    manager
        .create_session("daemon", "host1", &[])
        .await
        .unwrap();
    manager
        .create_session("daemon", "host2", &[])
        .await
        .unwrap();
    manager
        .create_session("systemd", "host1", &[])
        .await
        .unwrap();

    let filter = SessionFilter {
        host: Some("host1".into()),
        ..Default::default()
    };

    let sessions = manager.list_sessions(&filter).await.unwrap();
    assert_eq!(sessions.len(), 2);
}

#[tokio::test]
async fn notification_logging() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let manager = ScanHistoryManager::new(&db_path).await.unwrap();

    let id = manager
        .create_session("daemon", "localhost", &[])
        .await
        .unwrap();

    manager
        .log_notification(&id, "email", "sent", None)
        .await
        .unwrap();
    manager
        .log_notification(&id, "webhook:slack", "failed", Some("Timeout"))
        .await
        .unwrap();
    // Notifications are logged - no assertion needed, just verify no error
}

#[test]
fn above_floor_zeroes_sub_floor_levels() {
    let t = (1, 2, 3, 4, 5); // critical, high, medium, low, info
    assert_eq!(above_floor(t, Severity::Critical), (1, 0, 0, 0, 0));
    assert_eq!(above_floor(t, Severity::High), (1, 2, 0, 0, 0));
    assert_eq!(above_floor(t, Severity::Medium), (1, 2, 3, 0, 0));
    assert_eq!(above_floor(t, Severity::Low), (1, 2, 3, 4, 0));
    assert_eq!(above_floor(t, Severity::Info), (1, 2, 3, 4, 5));
}

#[test]
fn trend_direction_uses_severity_priority() {
    // Fewer criticals is better, even when lower severities rise.
    assert_eq!(trend_direction((1, 0, 0, 0, 0), (0, 5, 5, 5, 5)), "better");
    // A single new critical is worse, even when everything else drops.
    assert_eq!(trend_direction((0, 9, 9, 9, 9), (1, 0, 0, 0, 0)), "worse");
    assert_eq!(trend_direction((2, 1, 0, 0, 0), (2, 1, 0, 0, 0)), "same");
}

#[test]
fn is_worse_follows_severity_priority() {
    assert!(is_worse((0, 0, 0, 0, 0), (1, 0, 0, 0, 0))); // a new critical
    assert!(!is_worse((1, 0, 0, 0, 0), (0, 9, 9, 9, 9))); // fewer criticals is not worse
    assert!(!is_worse((2, 1, 0, 0, 0), (2, 1, 0, 0, 0))); // unchanged
}

fn session_covering(plugins_scanned: &str) -> ScanSession {
    ScanSession {
        id: "x".into(),
        started_at: 0,
        completed_at: None,
        status: "completed".into(),
        trigger_type: "daemon".into(),
        host_identifier: "h".into(),
        plugins_scanned: plugins_scanned.into(),
        total_findings: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        error_message: None,
        json_file_path: None,
        hash: None,
    }
}

/// A damaged record used to read as a scan that covered no plugins, which
/// is a claim about the host rather than about the row.
#[test]
fn a_damaged_plugin_record_is_an_error_not_an_empty_scan() {
    let damaged = session_covering("{not json");
    assert!(
        damaged.plugins().is_err(),
        "a record that will not parse must not read as an empty scan: {:?}",
        damaged.plugins()
    );
}

/// The counterpart, and the reason this cannot simply treat "fewer plugins
/// than the registry has" as damage: the runner writes the config-filtered
/// set, so a one-plugin or empty session is a real thing to record.
#[test]
fn a_short_or_empty_plugin_record_is_read_as_written() {
    assert_eq!(
        session_covering(r#"["kernel"]"#).plugins().unwrap(),
        vec!["kernel".to_string()]
    );
    assert!(session_covering("[]").plugins().unwrap().is_empty());
}

#[test]
fn severity_tuple_reads_session_counts() {
    let mut s = ScanSession {
        id: "x".into(),
        started_at: 0,
        completed_at: None,
        status: "completed".into(),
        trigger_type: "batch".into(),
        host_identifier: "h".into(),
        plugins_scanned: String::new(),
        total_findings: 0,
        critical_count: 1,
        high_count: 2,
        medium_count: 3,
        low_count: 4,
        info_count: 5,
        error_message: None,
        json_file_path: None,
        hash: None,
    };
    assert_eq!(s.severity_tuple(), (1, 2, 3, 4, 5));
    s.critical_count = 0;
    assert_eq!(s.severity_tuple(), (0, 2, 3, 4, 5));
}

#[tokio::test]
async fn pool_uses_wal_journal_mode() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("wal.db");
    let manager = ScanHistoryManager::new(&db_path).await.unwrap();
    let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&manager.pool)
        .await
        .unwrap();
    assert_eq!(mode.to_lowercase(), "wal", "history pool must use WAL");
}

#[tokio::test]
async fn previous_completed_session_returns_prior() {
    let dir = tempdir().unwrap();
    let manager = ScanHistoryManager::new(&dir.path().join("t.db"))
        .await
        .unwrap();

    // Single completed session: nothing precedes it.
    let first = manager.create_session("schedule", "h", &[]).await.unwrap();
    manager
        .complete_session(&first, &[], None, None)
        .await
        .unwrap();
    assert!(
        manager
            .previous_completed_session("h", &first)
            .await
            .unwrap()
            .is_none()
    );

    // A second session: excluding it returns the other one (the prior scan).
    // With exactly two sessions this is deterministic regardless of any
    // started_at tie: there is only one candidate left after the exclusion.
    let second = manager.create_session("schedule", "h", &[]).await.unwrap();
    manager
        .complete_session(&second, &[], None, None)
        .await
        .unwrap();
    let prev = manager
        .previous_completed_session("h", &second)
        .await
        .unwrap()
        .expect("has a previous");
    assert_eq!(prev.id, first);
}

/// A caller that persists after its scan can record when the scan began.
///
/// Both CLI paths reach persistence only once every plugin has run, so
/// stamping `Utc::now()` inside the insert put the completion time in
/// `started_at` and made `completed_at - started_at` measure the finding
/// inserts. Measured on the machine that found this: zero seconds for 83 of
/// 106 batch rows and 238 of 245 cli rows, with the non-zero ones all carrying
/// large finding counts. The scheduler's runner was never affected, because it
/// opens the session before scanning (#168).
#[tokio::test]
async fn a_session_can_record_a_start_that_precedes_its_insert() {
    let dir = tempdir().unwrap();
    let manager = ScanHistoryManager::new(&dir.path().join("test.db"))
        .await
        .unwrap();

    // Well before the insert, and far enough back that no clock skew or slow
    // test host could account for it.
    let began = chrono::Utc::now().timestamp() - 600;

    let id = manager
        .create_session_started_at("batch", "web-01", &["kernel".into()], began)
        .await
        .unwrap();

    let session = manager.get_session(&id).await.unwrap().unwrap();
    assert_eq!(
        session.started_at, began,
        "the caller's instant must be stored, not the moment of the insert"
    );

    manager
        .complete_session(&id, &[], None, None)
        .await
        .unwrap();
    let completed = manager.get_session(&id).await.unwrap().unwrap();
    let duration = completed.completed_at.expect("a completed session") - completed.started_at;
    assert!(
        duration >= 600,
        "the recorded duration must span the scan, not just the write: {duration}s"
    );
}

/// The convenience wrapper still stamps now, which is correct for a caller
/// that opens its session before scanning, as the scheduler's runner does.
///
/// Without this, `create_session` could be left delegating with any value at
/// all and the test above would still pass.
#[tokio::test]
async fn create_session_without_an_instant_stamps_the_present() {
    let dir = tempdir().unwrap();
    let manager = ScanHistoryManager::new(&dir.path().join("test.db"))
        .await
        .unwrap();

    let before = chrono::Utc::now().timestamp();
    let id = manager
        .create_session("daemon", "localhost", &[])
        .await
        .unwrap();
    let after = chrono::Utc::now().timestamp();

    let session = manager.get_session(&id).await.unwrap().unwrap();
    assert!(
        session.started_at >= before && session.started_at <= after,
        "expected an instant inside [{before}, {after}], got {}",
        session.started_at
    );
}
