#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`dispatcher`](super).
//!
//! Split out of `notification/dispatcher.rs`. This file sits in the `dispatcher/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::notification::dispatcher` and every import carried
//! across unchanged, private items included.

use super::*;
use crate::config::{NotificationConfig, NotifyMode};
use crate::db::ScanHistoryManager;
use crate::notification::Notifier;
use crate::runner::ScanSummary;
use std::sync::Arc;
use tempfile::tempdir;

struct MockNotifier;
#[async_trait::async_trait]
impl Notifier for MockNotifier {
    async fn send(&self, _summary: &ScanSummary) -> NotificationResult {
        NotificationResult::ok("mock")
    }
    fn channel(&self) -> &str {
        "mock"
    }
}

fn summary(critical: usize) -> ScanSummary {
    ScanSummary {
        session_id: "s".into(),
        host: "h".into(),
        plugins_scanned: vec![],
        total_findings: critical,
        critical_count: critical,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        json_path: None,
        json_hash: None,
        had_errors: false,
        regression: None,
    }
}

async fn dispatcher_with(mode: NotifyMode) -> NotificationDispatcher {
    let dir = tempdir().unwrap();
    let db = Arc::new(
        ScanHistoryManager::new(&dir.path().join("t.db"))
            .await
            .unwrap(),
    );
    let config = NotificationConfig {
        notify_min_severity: "critical".into(),
        notify_mode: mode,
        ..Default::default()
    };
    let mut d = NotificationDispatcher::new(&config, db);
    d.notifiers.push(Box::new(MockNotifier));
    d
}

#[tokio::test]
async fn regression_mode_silent_without_previous() {
    let d = dispatcher_with(NotifyMode::Regression).await;
    // First scan (no previous): even with criticals, regression mode is quiet.
    let results = d.dispatch(&summary(3), None).await;
    assert!(results.is_empty());
}

#[tokio::test]
async fn findings_mode_sends_on_threshold() {
    let d = dispatcher_with(NotifyMode::Findings).await;
    let results = d.dispatch(&summary(1), None).await;
    assert_eq!(results.len(), 1);
}

#[tokio::test]
async fn send_test_bypasses_decision_gate() {
    let d = dispatcher_with(NotifyMode::Regression).await;
    // dispatch would suppress (regression mode, no previous), but send_test must send.
    assert!(d.dispatch(&summary(3), None).await.is_empty());
    assert_eq!(d.send_test(&summary(3)).await.len(), 1);
}
