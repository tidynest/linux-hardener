#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Tests for `fail_session_on_err` in [`commands`](super).
//!
//! Split out of `commands.rs`, which carried three test modules under three
//! different names. Each keeps its own name in its own file, following
//! `acl_tests.rs`, which has sat beside `main.rs` since 2026-07-18 and is
//! this repository's precedent for a split-out unit test module. `super`
//! still resolves to `crate::commands`.

use super::*;

async fn test_history_manager() -> (ScanHistoryManager, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_db(Some(&dir.path().join("test.db"))).await.unwrap();
    (ScanHistoryManager::new(pool), dir)
}

#[tokio::test]
async fn marks_the_session_failed_and_preserves_the_original_error_on_abort() {
    let (history_manager, _dir) = test_history_manager().await;
    let session_id = history_manager.start_session().await.unwrap();

    let outcome: Result<(), String> = fail_session_on_err(&history_manager, &session_id, async {
        Err("cancelled authentication".to_string())
    })
    .await;

    assert_eq!(outcome, Err("cancelled authentication".to_string()));

    let sessions = history_manager.list_sessions(10).await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_status, ScanStatus::Failed);
}

#[tokio::test]
async fn leaves_the_session_untouched_on_success() {
    let (history_manager, _dir) = test_history_manager().await;
    let session_id = history_manager.start_session().await.unwrap();

    let outcome: Result<i32, String> =
        fail_session_on_err(&history_manager, &session_id, async { Ok(7) }).await;

    assert_eq!(outcome, Ok(7));

    // The success path completes the session itself elsewhere
    // (persist_scan_results); the helper must not touch it.
    let sessions = history_manager.list_sessions(10).await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_status, ScanStatus::Running);
}
