//! Fuzzes the directive parsers `apply` writes through: `global_scope`,
//! `set_config_directive` and `parse_config_value`.
//!
//! These functions consume files that arrive from remote hosts over the SSH
//! executor as well as local ones, which makes them parsers of input the
//! operator does not control - the exact case fuzzing exists for. The corpus
//! is seeded from that thought: sshd_config and PAM-shaped text, not just
//! arbitrary bytes.
//!
//! Beyond not panicking, three documented invariants are asserted, because a
//! fuzzer that only survives says less than one that checks:
//!
//! - `set_config_directive` always newline-terminates its result, because
//!   something appends to the file afterwards.
//! - `global_scope` returns a prefix of its input, ending on a line
//!   boundary: everything above the first live `Match` line.
//! - A set-then-parse round trip returns the value that was set, for
//!   directive names and values simple enough that setting them is
//!   unambiguous (no whitespace, newline or `=` in either).

#![no_main]

use hardener_common::file_utils::{
    ConfigFormat, Duplicates, global_scope, parse_config_value, set_config_directive,
};
use libfuzzer_sys::fuzz_target;

/// Split the fuzz input in two at the first newline: the head seeds file
/// content, the tail drives flags and the round-trip key/value.
fn split(data: &[u8]) -> (&[u8], &[u8]) {
    match data.iter().position(|&b| b == b'\n') {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[]),
    }
}

fn simple(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fuzz_target!(|data: &[u8]| {
    let (head, tail) = split(data);
    let content = String::from_utf8_lossy(head).into_owned();
    let tail = String::from_utf8_lossy(tail).into_owned();

    let format = match tail.as_bytes().first() {
        Some(b'k') => ConfigFormat::KeyValue,
        Some(b'a') => ConfigFormat::Auto,
        _ => ConfigFormat::SpaceSeparated,
    };
    let case_sensitive = !tail.as_bytes().get(1).is_some_and(|b| *b == b'i');
    let duplicates = if tail.as_bytes().get(2).is_some_and(|b| *b == b'r') {
        Duplicates::Remove
    } else {
        Duplicates::Keep
    };

    // Invariant: the global scope is a prefix of the content on a line
    // boundary (or the whole content when no live Match line exists).
    let scope = global_scope(&content);
    assert!(content.starts_with(scope));
    assert!(scope.is_empty() || scope.len() == content.len() || scope.ends_with('\n'));

    // Reading arbitrary content for arbitrary directive names must not
    // panic whatever the flags. `get` rather than slicing: three flag bytes
    // may be absent, and byte three need not fall on a char boundary.
    let mut words = tail.get(3..).unwrap_or("").split_whitespace();
    if let (Some(name), Some(value)) = (words.next(), words.next()) {
        let _ = parse_config_value(&content, name, format, case_sensitive);

        if simple(name) && simple(value) {
            let written =
                set_config_directive(&content, name, value, format, case_sensitive, duplicates);
            // Invariant: the result is always newline-terminated.
            assert!(written.ends_with('\n'));
            // Invariant: what was set can be read back, in the written
            // content and in the global scope of it.
            assert_eq!(
                parse_config_value(&written, name, format, case_sensitive),
                Some(value.to_string())
            );
            assert_eq!(
                parse_config_value(global_scope(&written), name, format, case_sensitive),
                Some(value.to_string())
            );
        }
    }
});
