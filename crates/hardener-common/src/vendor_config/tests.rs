#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`vendor_config`](super).
//!
//! Split out of `vendor_config.rs`. This file sits in the `vendor_config/`
//! directory beside it, which the 2018 path rules allow with no `mod.rs` and
//! no `#[path]`, so `super` still resolves to `crate::vendor_config` and
//! every import carried across unchanged, private items included.

use super::*;
use crate::executor::MockExecutor;

#[tokio::test]
async fn the_admin_layer_wins_when_both_exist() {
    let executor = MockExecutor::new()
        .with_file("/etc/login.defs", "PASS_MAX_DAYS 90\n")
        .with_file("/usr/etc/login.defs", "PASS_MAX_DAYS 99999\n");
    match read_layered(&executor, "/etc/login.defs").await {
        LayeredRead::Found {
            path,
            layer,
            content,
        } => {
            assert_eq!(path, "/etc/login.defs");
            assert!(matches!(layer, ConfigLayer::Admin));
            assert!(content.contains("90"), "got the vendor content: {content}");
        }
        other => panic!("expected the admin file, got {other:?}"),
    }
}

#[tokio::test]
async fn the_vendor_layer_answers_when_the_admin_file_is_absent() {
    let executor = MockExecutor::new().with_file("/usr/etc/login.defs", "UMASK 022\n");
    match read_layered(&executor, "/etc/login.defs").await {
        LayeredRead::Found {
            path,
            layer,
            content,
        } => {
            assert_eq!(path, "/usr/etc/login.defs");
            assert!(matches!(layer, ConfigLayer::Vendor));
            assert!(content.contains("UMASK"), "got: {content}");
        }
        other => panic!("expected the vendor file, got {other:?}"),
    }
}

#[tokio::test]
async fn absent_at_both_layers_is_absent() {
    let executor = MockExecutor::new();
    assert!(matches!(
        read_layered(&executor, "/etc/login.defs").await,
        LayeredRead::Absent
    ));
}

#[tokio::test]
async fn an_unreadable_admin_file_never_falls_through_to_the_vendor_copy() {
    // The sharpest test in this module. The admin file exists and is in
    // force; reporting the vendor file's values because ours could not be
    // read is a false pass of exactly the shape this workstream removes.
    let executor = MockExecutor::new()
        .with_file("/etc/login.defs", "PASS_MAX_DAYS 90\n")
        .with_read_permission_denied("/etc/login.defs")
        .with_file("/usr/etc/login.defs", "PASS_MAX_DAYS 99999\n");
    match read_layered(&executor, "/etc/login.defs").await {
        LayeredRead::Unreadable {
            path,
            permission_denied,
            ..
        } => {
            assert_eq!(path, "/etc/login.defs");
            assert!(permission_denied, "a denied read must be reported as such");
        }
        other => panic!("an unreadable admin file must not fall through, got {other:?}"),
    }
}

#[tokio::test]
async fn an_indeterminate_admin_probe_is_unreadable_not_absent() {
    // path_exists erroring is not evidence of absence, so the vendor layer
    // must not be consulted on it.
    let executor = MockExecutor::new()
        .with_path_exists_error("/etc/login.defs")
        .with_file("/usr/etc/login.defs", "PASS_MAX_DAYS 99999\n");
    assert!(
        matches!(
            read_layered(&executor, "/etc/login.defs").await,
            LayeredRead::Unreadable { .. }
        ),
        "an unverifiable admin path must fail closed"
    );
}

#[tokio::test]
async fn a_path_outside_etc_has_no_vendor_layer() {
    assert_eq!(
        vendor_path_for("/etc/ssh/sshd_config").as_deref(),
        Some("/usr/etc/ssh/sshd_config")
    );
    assert_eq!(vendor_path_for("/var/lib/thing.conf"), None);
    assert_eq!(vendor_path_for("/etc/"), None);
}
