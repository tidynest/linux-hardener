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

/// A resolved configuration from `(path, content)` pairs in sshd's reading
/// order, with no executor behind it.
fn resolved(segments: &[(&str, &str)]) -> ResolvedConfig {
    ResolvedConfig {
        segments: segments
            .iter()
            .map(|(path, content)| (path.to_string(), content.to_string()))
            .collect(),
    }
}

#[test]
fn a_legacy_spelling_answers_for_the_current_keyword() {
    // Rocky 10's 50-redhat.conf, which ships the old name and no other.
    let config = resolved(&[(
        "/etc/ssh/sshd_config.d/50-redhat.conf",
        "ChallengeResponseAuthentication no\n",
    )]);
    let effective = config
        .effective("KbdInteractiveAuthentication")
        .expect("the old name sets the same option");
    assert_eq!(effective.value, "no");
    assert_eq!(effective.keyword, "ChallengeResponseAuthentication");
}

#[test]
fn the_first_line_wins_whichever_spelling_it_uses() {
    // Both orders checked with `sshd -G` on OpenSSH 10.6p1: The earlier line
    // is the one in force, and its name makes no difference.
    for (content, expected) in [
        (
            "ChallengeResponseAuthentication no\nKbdInteractiveAuthentication yes\n",
            "no",
        ),
        (
            "KbdInteractiveAuthentication yes\nSkeyAuthentication no\n",
            "yes",
        ),
    ] {
        let config = resolved(&[("/etc/ssh/sshd_config", content)]);
        assert_eq!(
            config
                .effective("KbdInteractiveAuthentication")
                .map(|effective| effective.value)
                .as_deref(),
            Some(expected),
            "{content}"
        );
    }
}

#[test]
fn a_keyword_is_not_answered_by_a_different_option() {
    let config = resolved(&[("/etc/ssh/sshd_config", "KbdInteractiveAuthentication no\n")]);
    assert_eq!(config.effective("PasswordAuthentication"), None);
}

/// The resolver used to read each file through `parse_config_value`. These
/// are the guarantees that reader gave, held here now that the lines are
/// walked directly: A comment sets nothing, neither does a keyword with no
/// value, and `Key=value`, indentation and case are all accepted.
#[test]
fn a_comment_or_a_bare_keyword_sets_nothing() {
    let config = resolved(&[(
        "/etc/ssh/sshd_config",
        "#PermitRootLogin yes\nPermitRootLogin\n  permitrootlogin=no\n",
    )]);
    assert_eq!(
        config
            .effective("PermitRootLogin")
            .map(|effective| effective.value)
            .as_deref(),
        Some("no")
    );
}

#[test]
fn a_list_valued_directive_yields_every_argument() {
    // sshd accepts the quotes and the trailing comment, and `sshd -G` prints
    // the two lists bare.
    let config = resolved(&[(
        "/etc/ssh/sshd_config",
        "AuthenticationMethods \"publickey,keyboard-interactive\" publickey # either\n",
    )]);
    assert_eq!(
        config.effective_arguments("AuthenticationMethods"),
        Some(vec!["publickey,keyboard-interactive", "publickey"])
    );
}
