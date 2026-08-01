#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`daemon`](super).
//!
//! Split out of `daemon.rs`. This file sits in the `daemon/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::daemon` and every import carried
//! across unchanged, private items included.

use super::*;
use tempfile::tempdir;

/// Helper to create test infrastructure.
async fn setup_test_daemon() -> (Daemon, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let db = Arc::new(
        ScanHistoryManager::new(&dir.path().join("test.db"))
            .await
            .unwrap(),
    );
    let json_store = Arc::new(JsonStore::new(dir.path()).await.unwrap());
    let config = SchedulerConfig::default();

    (Daemon::new(config, db, json_store), dir)
}

#[tokio::test]
async fn new_creates_daemon_with_defaults() {
    let (daemon, _dir) = setup_test_daemon().await;

    assert!(!daemon.daemon_config.enabled);
    assert!(daemon.daemon_scheduler.is_none());
    assert!(daemon.daemon_shutdown_tx.is_none());
    assert!(!daemon.daemon_scan_in_progress.load(Ordering::SeqCst));
}

#[tokio::test]
async fn start_fails_when_disabled() {
    let (mut daemon, _dir) = setup_test_daemon().await;

    let registry = hardener_core::PluginRegistry::new();
    let pm = Arc::new(PluginManager::new(registry));
    let ctx = Arc::new(Context::new());

    let result = daemon.start(pm, ctx).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("disabled"));
}

#[tokio::test]
async fn run_once_rejects_concurrent_scans() {
    let (daemon, _dir) = setup_test_daemon().await;

    // Simulate a scan in progress
    daemon.daemon_scan_in_progress.store(true, Ordering::SeqCst);

    let registry = hardener_core::PluginRegistry::new();
    let pm = PluginManager::new(registry);
    let ctx = Context::new();

    let result = daemon.run_once(&pm, &ctx, TriggerType::Manual).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("already in progress"));
}

#[test]
fn scan_in_progress_flag_is_atomic() {
    let flag = Arc::new(AtomicBool::new(false));
    let flag_clone = flag.clone();

    // First swap should succeed (false -> true, returns false)
    assert!(!flag.swap(true, Ordering::SeqCst));

    // Second swap should indicate already set (true -> true, returns true)
    assert!(flag_clone.swap(true, Ordering::SeqCst));

    // Reset
    flag.store(false, Ordering::SeqCst);
    assert!(!flag.load(Ordering::SeqCst));
}
