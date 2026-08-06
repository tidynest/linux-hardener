#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`dropin`].
//!
//! Split out of `dropin.rs`. This file sits in the `dropin/` directory
//! beside it, so `super` still resolves to `crate::dropin` and every
//! import carried across unchanged, private items included.

use super::*;

fn directive(keyword: &'static str, value: &str) -> Directive {
    Directive {
        keyword,
        value: value.to_string(),
        note: "",
    }
}

#[test]
fn directives_are_rendered_in_a_stable_order() {
    let one = render(&[
        directive("X11Forwarding", "no"),
        directive("PermitRootLogin", "no"),
    ]);
    let other = render(&[
        directive("PermitRootLogin", "no"),
        directive("X11Forwarding", "no"),
    ]);
    assert_eq!(one, other, "order in must not change the file on disk");
    let body: Vec<&str> = one.lines().filter(|l| !l.starts_with('#')).collect();
    assert_eq!(body, vec!["PermitRootLogin no", "X11Forwarding no"]);
}

#[test]
fn the_fragment_says_who_owns_it() {
    let rendered = render(&[directive("X11Forwarding", "no")]);
    assert!(
        rendered.starts_with('#'),
        "a managed file must say so before its first directive: {rendered}"
    );
    assert!(rendered.contains("linux-hardener"));
}
