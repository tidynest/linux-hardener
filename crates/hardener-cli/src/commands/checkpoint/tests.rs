#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`checkpoint`](super).
//!
//! Split out of `commands/checkpoint.rs`. This file sits in the `checkpoint/`
//! directory beside it, which the 2018 path rules allow with no `mod.rs` and
//! no `#[path]`, so `super` still resolves to `crate::commands::checkpoint`
//! and every import carried across unchanged, private items included.

use super::*;
use hardener_types::ReloadResult;

#[test]
fn a_rollback_whose_reload_failed_does_not_report_success() {
    let result = RollbackResult {
        rollback_checkpoint_id: "cp_1".to_string(),
        rollback_checkpoint_name: "before-upgrade".to_string(),
        rollback_success: true,
        rollback_files: Vec::new(),
        rollback_reloads: vec![ReloadResult {
            reload_plugin_id: "ssh-hardening".to_string(),
            reload_action: "reload failed".to_string(),
            reload_success: false,
            reload_error: Some("sshd -t refused the restored config".to_string()),
        }],
    };
    assert_eq!(
        rollback_failure_reason(&result),
        Some(FailureReason::Reload)
    );
}

#[test]
fn a_rollback_whose_files_failed_says_so_rather_than_blaming_the_reload() {
    let result = RollbackResult {
        rollback_checkpoint_id: "cp_1".to_string(),
        rollback_checkpoint_name: "before-upgrade".to_string(),
        rollback_success: false,
        rollback_files: Vec::new(),
        rollback_reloads: Vec::new(),
    };
    assert_eq!(rollback_failure_reason(&result), Some(FailureReason::Files));
}

#[test]
fn a_clean_rollback_has_no_failure_reason() {
    let result = RollbackResult {
        rollback_checkpoint_id: "cp_1".to_string(),
        rollback_checkpoint_name: "before-upgrade".to_string(),
        rollback_success: true,
        rollback_files: Vec::new(),
        rollback_reloads: Vec::new(),
    };
    assert_eq!(rollback_failure_reason(&result), None);
}
