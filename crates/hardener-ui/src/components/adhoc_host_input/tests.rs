#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`adhoc_host_input`](super).
//!
//! Split out of `components/adhoc_host_input.rs`. This file sits in the
//! `components/adhoc_host_input/` directory beside it, which the 2018 path
//! rules allow with no `mod.rs` and no `#[path]`, so `super` still resolves
//! to `crate::components::adhoc_host_input` and every import carried across
//! unchanged, private items included.

use super::*;

#[test]
fn target_error_mirrors_backend_guard() {
    assert!(target_error("", &[]).is_some(), "empty rejected");
    assert!(
        target_error("-oProxyCommand=x", &[]).is_some(),
        "leading dash rejected"
    );
    assert!(
        target_error("admin@", &[]).is_some(),
        "empty hostname rejected"
    );
    assert!(
        target_error("admin@web-01:2222", &[]).is_none(),
        "valid target accepted"
    );
    assert!(
        target_error("root@10.242.117.2", &[]).is_none(),
        "bare IP target accepted"
    );
    assert!(
        target_error("root@10.242.117.2, scan:22", &[]).is_some(),
        "comma/space in hostname rejected (the live typo)"
    );
    assert!(
        target_error("web", &["web".to_string()]).is_some(),
        "duplicate rejected"
    );
}
