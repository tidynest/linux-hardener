#![cfg(test)]
//
// Gated here as well as at the declaration, for the reason given at the top
// of `ssh/tests.rs`: The validators decide test context from the file itself.

//! Unit tests for [`auth_methods`].

use super::*;

const KBD: &str = "keyboard-interactive";

/// Every row was checked against `sshd -t` and `sshd -G` on OpenSSH 10.6p1,
/// 2026-11-10, for what sshd accepts and how it prints the lists.
#[test]
fn a_password_method_finishes_alone_only_where_a_list_holds_nothing_else() {
    let cases: &[(Option<&[&str]>, bool, &str)] = &[
        (None, true, "unset means any single method"),
        (Some(&["any"]), true, "any, spelled out"),
        (Some(&[]), true, "an empty value is not evidence of safety"),
        (
            Some(&["keyboard-interactive"]),
            true,
            "the only method asked for",
        ),
        (
            Some(&["password,keyboard-interactive"]),
            true,
            "two password prompts are still passwords alone",
        ),
        (
            Some(&["publickey", "keyboard-interactive"]),
            true,
            "either list will do, and the second needs no key",
        ),
        (
            Some(&["publickey,keyboard-interactive"]),
            false,
            "a second factor behind a key",
        ),
        (
            Some(&["publickey,keyboard-interactive:pam"]),
            false,
            "a submethod names the same method",
        ),
        (
            Some(&["publickey,keyboard-interactive", "publickey,password"]),
            false,
            "every list that names it also asks for a key",
        ),
        (Some(&["publickey"]), false, "no list names it at all"),
    ];
    for (lists, expected, why) in cases {
        assert_eq!(finishes_alone(*lists, KBD), *expected, "{why}: {lists:?}");
    }
}

/// The question is asked per method. A list of `password` alone lets a
/// password finish, but not through keyboard-interactive, and that finding
/// belongs to `PasswordAuthentication`.
#[test]
fn a_list_is_judged_for_the_method_asked_about() {
    assert!(!finishes_alone(Some(&["password"]), KBD));
    assert!(finishes_alone(Some(&["password"]), "password"));
}
