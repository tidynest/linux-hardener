#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`binary_utils`](super).
//!
//! Split out of `binary_utils.rs`. This file sits in the `binary_utils/`
//! directory beside it, which the 2018 path rules allow with no `mod.rs` and
//! no `#[path]`, so `super` still resolves to `crate::binary_utils` and every
//! import carried across unchanged, private items included.

use super::*;

#[test]
fn absolute_path_returned_unchanged() {
    assert_eq!(resolve_binary("/usr/bin/ls"), "/usr/bin/ls");
}

#[test]
fn resolves_common_binary() {
    let resolved = resolve_binary("ls");
    assert!(
        resolved.starts_with('/'),
        "Expected absolute path, got: {resolved}"
    );
}

#[test]
fn nonexistent_binary_returns_original() {
    assert_eq!(
        resolve_binary("__nonexistent_binary__"),
        "__nonexistent_binary__"
    );
}
