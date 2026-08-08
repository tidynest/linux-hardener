#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`shell_config`].
//!
//! Split out of `shell_config.rs`. This file sits in the `shell_config/`
//! directory beside it, so `super` still resolves to `crate::shell_config`
//! and every import carried across unchanged, private items included.

use super::*;

/// Shell semantics: the last assignment is the one in force, a commented
/// line is not an assignment, and quotes are not part of the value.
#[test]
fn a_shell_value_is_the_last_uncommented_assignment() {
    // Three assignments of the same name: one commented out, which is not
    // an assignment at all, then two live ones, so "the last wins" is
    // pinned rather than being satisfied by there only being one.
    let content = "#IPT_SYSCTL=/etc/ufw/off.conf\nIPV6=yes\n\
                   IPT_SYSCTL=/etc/ufw/superseded.conf\n\
                   IPT_SYSCTL=\"/etc/ufw/sysctl.conf\"\nexport ENABLED=yes\n";
    assert_eq!(
        shell_value(content, "IPT_SYSCTL").as_deref(),
        Some("/etc/ufw/sysctl.conf")
    );
    assert_eq!(shell_value(content, "ENABLED").as_deref(), Some("yes"));
    assert_eq!(shell_value(content, "MISSING"), None);
}
