#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`theme`](super).
//!
//! Split out of `utils/theme.rs`. This file sits in the `utils/theme/`
//! directory beside it, which the 2018 path rules allow with no `mod.rs` and
//! no `#[path]`, so `super` still resolves to `crate::utils::theme` and every
//! import carried across unchanged, private items included.

use super::THEMES;

#[test]
fn theme_ids_are_unique() {
    let mut ids: Vec<&str> = THEMES.iter().map(|(id, _)| *id).collect();
    ids.sort_unstable();
    let count = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), count, "theme ids must be unique");
}

#[test]
fn every_theme_has_a_name() {
    for (id, name) in THEMES {
        assert!(!name.is_empty(), "theme {id} has an empty display name");
    }
}

#[test]
fn default_theme_is_present() {
    assert!(
        THEMES.iter().any(|(id, _)| *id == "default"),
        "the default theme must be listed"
    );
}
