#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`login_defs`].
//!
//! Split out of `login_defs.rs`. This file sits in the `login_defs/` directory
//! beside it, so `super` still resolves to `crate::login_defs` and every
//! import carried across unchanged, private items included.

use super::*;
use hardener_common::executor::{FileMetadata, MockExecutor};
use std::sync::Arc;

#[tokio::test]
async fn the_copy_takes_the_vendor_file_s_permission_bits() {
    let executor = MockExecutor::new().with_file_metadata(
        "/usr/etc/login.defs",
        "UMASK 022\n",
        FileMetadata {
            exists: true,
            is_file: true,
            is_dir: false,
            // As a metadata probe reports it: regular file plus 0644.
            mode: 0o100_644,
            size: 10,
            uid: 0,
            gid: 0,
        },
    );
    let ctx = Context::with_executor(Arc::new(executor));
    assert_eq!(mode_for_copy_of(&ctx, "/usr/etc/login.defs").await, 0o644);
}

#[tokio::test]
async fn an_unreadable_vendor_mode_never_yields_the_temporary_file_s_0600() {
    let executor = MockExecutor::new().with_metadata_error("/usr/etc/login.defs");
    let ctx = Context::with_executor(Arc::new(executor));
    // Asserted as a literal, not against the constant: comparing the
    // fallback to itself is true whatever the fallback is, so such a test
    // passes just as happily against the 0600 that is the defect.
    assert_eq!(
        mode_for_copy_of(&ctx, "/usr/etc/login.defs").await,
        0o644,
        "a mode that could not be read must not leave the file unreadable to \
         the tools that need it"
    );
}
