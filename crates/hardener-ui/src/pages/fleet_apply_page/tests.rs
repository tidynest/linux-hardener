#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`fleet_apply_page`](super).
//!
//! Split out of `pages/fleet_apply_page.rs`. This file sits in the
//! `pages/fleet_apply_page/` directory beside it, which the 2018 path rules
//! allow with no `mod.rs` and no `#[path]`, so `super` still resolves to
//! `crate::pages::fleet_apply_page` and every import carried across
//! unchanged, private items included.

use super::*;

#[test]
fn selection_key_is_order_independent_and_mode_sensitive() {
    let h1: HashSet<String> = ["a".into(), "b".into()].into_iter().collect();
    let h2: HashSet<String> = ["b".into(), "a".into()].into_iter().collect();
    let p: HashSet<String> = ["ssh".into()].into_iter().collect();
    assert_eq!(
        selection_key("apply", &h1, &[], &p),
        selection_key("apply", &h2, &[], &p)
    );
    assert_ne!(
        selection_key("apply", &h1, &[], &p),
        selection_key("rollback", &h1, &[], &p)
    );
}

#[test]
fn selection_key_includes_adhoc_targets() {
    let h: HashSet<String> = ["a".into()].into_iter().collect();
    let p = HashSet::new();
    assert_ne!(
        selection_key("apply", &h, &[], &p),
        selection_key("apply", &h, &["root@10.0.0.5".into()], &p),
        "adding an ad-hoc target must invalidate a previous dry-run"
    );
    assert_eq!(
        selection_key("apply", &h, &["x@1".into(), "y@2".into()], &p),
        selection_key("apply", &h, &["y@2".into(), "x@1".into()], &p),
        "ad-hoc order must not matter"
    );
}
