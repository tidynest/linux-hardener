#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`persistence`].
//!
//! Split out of `persistence.rs`. This file sits in the `persistence/` directory
//! beside it, so `super` still resolves to `crate::persistence` and every
//! import carried across unchanged, private items included.

use super::*;

/// The two spellings `sysctl` accepts, reduced to one. Without this the
/// tool's dotted table and ufw's procfs paths never meet, and a comparison
/// that matches nothing reports nothing, which is the pass condition.
#[test]
fn both_separators_reduce_to_the_procfs_spelling() {
    assert_eq!(
        procfs_key("net.ipv4.conf.all.log_martians"),
        "net/ipv4/conf/all/log_martians"
    );
    assert_eq!(
        procfs_key("net/ipv4/conf/all/log_martians"),
        "net/ipv4/conf/all/log_martians"
    );
    assert_eq!(
        procfs_key("kernel.randomize_va_space"),
        "kernel/randomize_va_space"
    );
}

/// An interface name may itself contain a dot, which is the whole reason
/// the rule is "the first separator decides" rather than "replace dots".
#[test]
fn the_first_separator_decides_how_the_rest_is_read() {
    // First separator a slash: dots later in the name are part of it.
    assert_eq!(
        procfs_key("net/ipv4/conf/enp3s0.200/forwarding"),
        "net/ipv4/conf/enp3s0.200/forwarding"
    );
    // First separator a dot: the two are interchanged, so the embedded
    // slash becomes the dot in the interface name.
    assert_eq!(
        procfs_key("net.ipv4.conf.enp3s0/200.forwarding"),
        "net/ipv4/conf/enp3s0.200/forwarding"
    );
}

#[test]
fn a_sysctl_file_is_read_in_either_spelling_and_comments_are_not_settings() {
    let parsed = parse_sysctl(
        "# a comment\n; another\n\nnet/ipv4/conf/all/log_martians=0\n\
         net.ipv4.conf.default.rp_filter = 2\n-fs.suid_dumpable = 1\n",
    );
    assert_eq!(
        parsed.values.get("net/ipv4/conf/all/log_martians"),
        Some(&"0".to_string())
    );
    assert_eq!(
        parsed.values.get("net/ipv4/conf/default/rp_filter"),
        Some(&"2".to_string())
    );
    // A leading `-` only makes the assignment failure-tolerant.
    assert_eq!(
        parsed.values.get("fs/suid_dumpable"),
        Some(&"1".to_string())
    );
    assert!(
        parsed.glob_patterns.is_empty(),
        "no pattern appears in this file"
    );
}

/// The last assignment wins, which is what `sysctl` does with the file.
#[test]
fn a_later_line_wins_over_an_earlier_one() {
    let parsed = parse_sysctl("net.ipv4.conf.all.rp_filter = 0\nnet.ipv4.conf.all.rp_filter = 1\n");
    assert_eq!(
        parsed.values.get("net/ipv4/conf/all/rp_filter"),
        Some(&"1".to_string())
    );
}

/// A pattern is recorded as unresolved rather than skipped in silence.
#[test]
fn a_glob_pattern_is_not_quietly_dropped() {
    let parsed = parse_sysctl("net.ipv4.conf.*.rp_filter = 2\n-net.ipv4.conf.all.rp_filter\n");
    assert_eq!(
        parsed.glob_patterns,
        vec!["net/ipv4/conf/*/rp_filter".to_string()],
        "the pattern must be recorded, keyed the way procfs_key spells a key"
    );
    assert!(
        parsed.values.is_empty(),
        "an exclusion line assigns nothing and a pattern is not resolved here"
    );
}

// `glob_could_match` tests. Both arguments are already spelled by
// `procfs_key`, as every caller in `divergence.rs` spells them.

#[test]
fn a_star_matches_any_run_of_characters_including_none() {
    assert!(glob_could_match(
        "net/ipv4/conf/*/rp_filter",
        "net/ipv4/conf/all/rp_filter"
    ));
    assert!(glob_could_match(
        "net/ipv4/conf/*/rp_filter",
        "net/ipv4/conf//rp_filter"
    ));
    assert!(glob_could_match("net/*", "net/ipv4/conf/all/rp_filter"));
}

#[test]
fn a_star_cannot_name_an_unrelated_key() {
    assert!(!glob_could_match(
        "net/ipv4/conf/*/rp_filter",
        "kernel/kptr_restrict"
    ));
    assert!(!glob_could_match(
        "net/ipv4/conf/*/rp_filter",
        "net/ipv4/conf/all/accept_source_route"
    ));
}

#[test]
fn a_question_mark_matches_exactly_one_character() {
    assert!(glob_could_match(
        "kernel/kptr_restric?",
        "kernel/kptr_restrict"
    ));
    assert!(!glob_could_match(
        "kernel/kptr_restric?",
        "kernel/kptr_restrict_extra"
    ));
    assert!(!glob_could_match(
        "kernel/kptr_restric?",
        "kernel/kptr_restri"
    ));
}

#[test]
fn a_character_class_matches_one_character_without_checking_which() {
    // The class's actual membership is never evaluated: over-matching here is
    // the deliberately safe direction (blocks a key that never had a real
    // exclusion match against it), never the unsafe one.
    assert!(glob_could_match(
        "net/ipv4/conf/[ad]ll/rp_filter",
        "net/ipv4/conf/all/rp_filter"
    ));
    assert!(glob_could_match(
        "net/ipv4/conf/[xyz]ll/rp_filter",
        "net/ipv4/conf/all/rp_filter"
    ));
    assert!(!glob_could_match(
        "net/ipv4/conf/[ad]ll/rp_filter",
        "net/ipv4/conf/ball/rp_filter"
    ));
}

#[test]
fn no_wildcard_at_all_requires_an_exact_match() {
    assert!(glob_could_match(
        "net/ipv4/conf/all/rp_filter",
        "net/ipv4/conf/all/rp_filter"
    ));
    assert!(!glob_could_match(
        "net/ipv4/conf/all/rp_filter",
        "net/ipv4/conf/default/rp_filter"
    ));
}

#[test]
fn an_unterminated_bracket_is_treated_as_a_literal() {
    assert!(glob_could_match(
        "kernel/kptr[restrict",
        "kernel/kptr[restrict"
    ));
    assert!(!glob_could_match(
        "kernel/kptr[restrict",
        "kernel/kptrxrestrict"
    ));
}
