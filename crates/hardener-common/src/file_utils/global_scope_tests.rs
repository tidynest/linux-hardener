#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Global-scope rewriting tests for [`file_utils`](super).
//!
//! Split out of `file_utils.rs`, where it was the second of two top-level
//! test modules. It keeps its own name rather than merging into `tests`,
//! because the question it asks is narrower: that a directive written at
//! global scope is not confused with the same directive inside a `Match`
//! block. `super` still resolves to `crate::file_utils`.

use super::*;

const MATCH_ONLY: &str = "\
PasswordAuthentication no
Match Address 10.0.0.0/8
    PermitRootLogin no
";

#[test]
fn a_directive_only_inside_a_match_block_is_not_a_global_value() {
    // The whole-file read returns "no" and the caller concludes root login
    // is closed, when the block scopes that to one subnet and the global
    // setting is still sshd's compiled default.
    assert_eq!(
        parse_config_value(
            MATCH_ONLY,
            "PermitRootLogin",
            ConfigFormat::SpaceSeparated,
            false
        )
        .as_deref(),
        Some("no"),
        "whole-file read is the behaviour global_scope exists to correct"
    );
    assert_eq!(
        parse_config_value(
            global_scope(MATCH_ONLY),
            "PermitRootLogin",
            ConfigFormat::SpaceSeparated,
            false
        ),
        None,
        "a Match-scoped directive must not be read as the global value"
    );
}

#[test]
fn directives_above_the_match_block_are_still_global() {
    assert_eq!(
        parse_config_value(
            global_scope(MATCH_ONLY),
            "PasswordAuthentication",
            ConfigFormat::SpaceSeparated,
            false
        )
        .as_deref(),
        Some("no")
    );
}

#[test]
fn a_commented_match_opens_no_block() {
    let content = "# Match Address 10.0.0.0/8\nPermitRootLogin no\n";
    assert_eq!(
        parse_config_value(
            global_scope(content),
            "PermitRootLogin",
            ConfigFormat::SpaceSeparated,
            false
        )
        .as_deref(),
        Some("no"),
        "a commented Match must not truncate the global scope"
    );
}

#[test]
fn a_file_with_no_match_block_is_entirely_global() {
    let content = "PermitRootLogin no\nMaxAuthTries 3\n";
    assert_eq!(global_scope(content), content);
}

#[test]
fn the_match_keyword_is_matched_case_insensitively() {
    // sshd accepts any case for keywords, so a lowercase `match` opens a
    // block just as a capitalised one does.
    let content = "match Address 10.0.0.0/8\n    PermitRootLogin no\n";
    assert_eq!(global_scope(content), "");
}
