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

/// The opted-in policy holds where every list asks for the key first and the
/// account password after it, and only there (#185).
#[test]
fn a_key_then_the_password_is_required_only_where_every_list_asks_for_both() {
    let cases: &[(Option<&[&str]>, bool, &str)] = &[
        (None, false, "unset lets any single method in"),
        (Some(&["any"]), false, "any, spelled out"),
        (Some(&[]), false, "an empty value is not a policy"),
        (
            Some(&["publickey,keyboard-interactive"]),
            true,
            "the policy",
        ),
        (
            Some(&["publickey,keyboard-interactive:pam"]),
            true,
            "a submethod names the same method",
        ),
        (
            Some(&["publickey,publickey,keyboard-interactive"]),
            true,
            "two keys and a password is stricter, and is kept",
        ),
        (
            Some(&["keyboard-interactive,publickey"]),
            false,
            "a password before the key lets anyone without the key guess at it",
        ),
        (
            Some(&["publickey,keyboard-interactive", "publickey"]),
            false,
            "the second list lets the key in alone",
        ),
        (Some(&["publickey"]), false, "the key alone"),
        (
            Some(&["publickey,password"]),
            false,
            "the password method is switched off by the baseline",
        ),
        (
            Some(&["publickey,keyboard-interactive,password"]),
            false,
            "a list naming a disabled method is skipped by sshd",
        ),
    ];
    for (lists, expected, why) in cases {
        assert_eq!(
            requires_key_then_password(*lists),
            *expected,
            "{why}: {lists:?}"
        );
    }
}

/// What this tool's own remote mode needs: one key, no prompt.
#[test]
fn a_key_alone_suffices_only_through_a_list_of_one_key() {
    assert!(key_alone_suffices(&["any"]));
    assert!(key_alone_suffices(&["publickey"]));
    assert!(key_alone_suffices(&[
        "publickey,keyboard-interactive",
        "publickey"
    ]));
    assert!(!key_alone_suffices(&["publickey,keyboard-interactive"]));
    assert!(!key_alone_suffices(&["publickey,publickey"]));
    assert!(!key_alone_suffices(&["keyboard-interactive"]));
    assert!(!key_alone_suffices(&[]));
}
