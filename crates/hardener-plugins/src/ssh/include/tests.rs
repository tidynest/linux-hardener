#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`include`].
//!
//! Split out of `include.rs`. This file sits in the `include/` directory
//! beside it, so `super` still resolves to `crate::include` and every
//! import carried across unchanged, private items included.

use super::*;

#[test]
fn a_live_include_yields_its_patterns() {
    assert_eq!(
        include_patterns("Include /etc/ssh/sshd_config.d/*.conf"),
        Some(vec!["/etc/ssh/sshd_config.d/*.conf".to_string()])
    );
}

#[test]
fn include_is_matched_case_insensitively_and_may_carry_several_patterns() {
    assert_eq!(
        include_patterns("  include  a.conf   b.conf "),
        Some(vec!["a.conf".to_string(), "b.conf".to_string()])
    );
}

#[test]
fn a_commented_include_includes_nothing() {
    assert_eq!(
        include_patterns("# Include /etc/ssh/sshd_config.d/*.conf"),
        None
    );
    assert_eq!(include_patterns("#Include foo.conf"), None);
}

#[test]
fn other_directives_are_not_includes() {
    assert_eq!(include_patterns("PermitRootLogin no"), None);
    assert_eq!(include_patterns(""), None);
    // A bare keyword names no file.
    assert_eq!(include_patterns("Include"), None);
}

#[test]
fn glob_star_matches_the_conf_suffix() {
    assert!(glob_matches("*.conf", "99-archlinux.conf"));
    assert!(glob_matches("*.conf", ".conf"));
    assert!(!glob_matches("*.conf", "readme.txt"));
    assert!(!glob_matches("*.conf", "conf"));
}

#[test]
fn glob_question_mark_matches_exactly_one_character() {
    assert!(glob_matches("0?-base.conf", "01-base.conf"));
    assert!(!glob_matches("0?-base.conf", "0-base.conf"));
    assert!(!glob_matches("0?-base.conf", "012-base.conf"));
}

#[test]
fn glob_handles_a_star_that_must_backtrack() {
    // The naive matcher fails this: the first `*` must give back the `a`
    // it consumed so the literal `ab` can match at the end.
    assert!(glob_matches("*ab", "aab"));
    assert!(glob_matches("*a*b", "xaybzb"));
    assert!(!glob_matches("*ab", "aba"));
}

#[test]
fn a_pattern_with_a_character_class_is_refused_not_guessed() {
    // Treating it as "matches nothing" would hide a drop-in, which is the
    // false pass this module exists to remove.
    assert!(!pattern_is_supported("[0-9]*.conf"));
    assert!(pattern_is_supported("*.conf"));
}

#[test]
fn a_relative_include_resolves_under_etc_ssh() {
    assert_eq!(
        absolute_pattern("sshd_config.d/*.conf", "/etc/ssh/sshd_config"),
        Some(PathBuf::from("/etc/ssh/sshd_config.d/*.conf"))
    );
    assert_eq!(
        absolute_pattern("/somewhere/else.conf", "/etc/ssh/sshd_config"),
        Some(PathBuf::from("/somewhere/else.conf"))
    );
}

#[test]
fn a_relative_include_from_the_vendor_layer_is_refused_rather_than_guessed() {
    // sshd resolves a relative include against its compiled sysconfdir,
    // which this tool cannot read. Guessing /etc/ssh for a file under
    // /usr/etc would silently mis-locate the fragment and report a value
    // that is not in force.
    assert_eq!(
        absolute_pattern("sshd_config.d/*.conf", "/usr/etc/ssh/sshd_config"),
        None
    );
    // An absolute pattern needs no base, so it still resolves.
    assert_eq!(
        absolute_pattern(
            "/usr/etc/ssh/sshd_config.d/40-suse.conf",
            "/usr/etc/ssh/sshd_config"
        ),
        Some(PathBuf::from("/usr/etc/ssh/sshd_config.d/40-suse.conf"))
    );
}
