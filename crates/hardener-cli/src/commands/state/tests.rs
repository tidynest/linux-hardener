#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`state`](super).
//!
//! Split out of `commands/state.rs`. This file sits in the `state/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::commands::state` and every import carried
//! across unchanged, private items included.

use super::*;

/// Every failure used to fold to `None`, so a privileged run simply had
/// no audit trail and said nothing. The failure must survive as an error
/// carrying the path, which is what lets the caller report it.
#[tokio::test]
async fn an_unusable_audit_directory_produces_an_error_not_silence() {
    let dir = tempfile::tempdir().unwrap();
    // A regular file where a directory belongs: create_dir_all below it
    // fails with ENOTDIR.
    let not_a_dir = dir.path().join("not-a-dir");
    fs::write(&not_a_dir, "regular file").unwrap();

    // AuditLogger has no Debug, so unwrap the Result by hand.
    let message = match audit_logger_in(&not_a_dir.join("logs"), None).await {
        Ok(_) => panic!("an uncreatable audit directory must not fold to success"),
        Err(e) => format!("{e:#}"),
    };
    assert!(
        message.contains("audit log directory"),
        "the error must say what it was doing: {message}"
    );
    assert!(
        message.contains("not-a-dir"),
        "the error must name the path: {message}"
    );
}

/// The ordinary case still works, so the guard above is not just
/// rejecting everything.
#[tokio::test]
async fn a_usable_directory_opens_the_audit_log() {
    let dir = tempfile::tempdir().unwrap();
    let logger_dir = dir.path().join("audit");

    audit_logger_in(&logger_dir, Some(0o700))
        .await
        .expect("a writable directory must yield a logger");

    assert!(logger_dir.join("audit.log").exists());
}
