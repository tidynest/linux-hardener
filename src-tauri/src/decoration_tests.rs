#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Window decoration tests for the desktop binary.
//!
//! Split out of `main.rs`, which is the crate root, so this file sits beside
//! it in `src/` exactly as `acl_tests.rs` does. `super` is the crate root
//! either way, so the imports carried across unchanged.

use super::desktop_is_tiling;

#[test]
fn recognises_tiling_compositors() {
    assert!(desktop_is_tiling("Hyprland"));
    assert!(desktop_is_tiling("sway"));
    assert!(desktop_is_tiling("wlroots:river"));
}

#[test]
fn rejects_floating_desktops() {
    assert!(!desktop_is_tiling("GNOME"));
    assert!(!desktop_is_tiling("KDE"));
    assert!(!desktop_is_tiling(""));
}
