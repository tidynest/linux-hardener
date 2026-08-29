//! Fuzzes the sshd_config `Include` resolution core: `include_patterns`,
//! `glob_matches`, `pattern_is_supported`, `absolute_pattern`, and the
//! first-wins order `ResolvedConfig::effective` answers from.
//!
//! All of it consumes sshd_config content that arrives from remote hosts
//! over the SSH executor, which is input the operator does not control. The
//! order model is the load-bearing half: sshd takes the first value it
//! obtains, so a resolution that answered from any other segment would
//! report compliance a host does not have, which is the false pass the
//! module exists to remove.
//!
//! Invariants asserted, beyond not panicking:
//!
//! - `include_patterns` yields nothing exactly for commented lines,
//!   non-`Include` first words, and `Include` with no patterns, and its
//!   patterns are the non-empty whitespace-split remainder in order.
//! - `glob_matches`, a hand-written backtracking matcher, agrees with the
//!   structural facts of glob(7): a pattern with no metacharacters matches
//!   only the identical name, and a pattern without `*` matches only a name
//!   of the same length, because `?` consumes exactly one character.
//! - `absolute_pattern` passes absolute patterns through and resolves
//!   relative ones against `/etc/ssh` exactly when the including file is
//!   under `/etc`, per sshd_config(5).
//! - `effective` and `effective_without` return the FIRST segment's value
//!   in order. The segments are built from values simple enough that
//!   parsing them is unambiguous, so the expectation is derived from
//!   construction rather than from a second parser.

#![no_main]

use hardener_plugins::fuzz_seams::ssh_include::{
    ResolvedConfig, absolute_pattern, glob_matches, include_patterns, pattern_is_supported,
};
use libfuzzer_sys::fuzz_target;
use std::path::{Path, PathBuf};

fn simple(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fuzz_target!(|data: &[u8]| {
    let (head, rest) = match data.iter().position(|&b| b == b'\n') {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[][..]),
    };
    let text = String::from_utf8_lossy(head).into_owned();
    let (pattern, rest) = match rest.iter().position(|&b| b == b'\n') {
        Some(i) => (
            String::from_utf8_lossy(&rest[..i]).into_owned(),
            &rest[i + 1..],
        ),
        None => (String::from_utf8_lossy(rest).into_owned(), &[][..]),
    };
    let (name, rest) = match rest.iter().position(|&b| b == b'\n') {
        Some(i) => (
            String::from_utf8_lossy(&rest[..i]).into_owned(),
            &rest[i + 1..],
        ),
        None => (String::from_utf8_lossy(rest).into_owned(), &[][..]),
    };

    // include_patterns: the None cases are exactly the three documented ones,
    // and the Some cases carry the remainder tokens, in order, non-empty.
    for line in text.lines() {
        let trimmed = line.trim();
        let first_is_include = trimmed
            .split_whitespace()
            .next()
            .is_some_and(|word| word.eq_ignore_ascii_case("include"));
        let has_patterns = trimmed.split_whitespace().count() > 1;
        match include_patterns(line) {
            Some(patterns) => {
                assert!(
                    !trimmed.starts_with('#'),
                    "a commented line includes nothing"
                );
                assert!(first_is_include, "Some implies the first word is Include");
                assert!(!patterns.is_empty(), "Some implies at least one pattern");
                let remainder: Vec<&str> = trimmed.split_whitespace().skip(1).collect();
                assert_eq!(patterns, remainder, "patterns are the remainder, in order");
            }
            None => {
                assert!(
                    trimmed.starts_with('#') || !first_is_include || !has_patterns,
                    "None only for comments, other keywords, and bare Include"
                );
            }
        }
    }

    // The glob matcher against glob(7)'s structural facts.
    assert_eq!(
        pattern_is_supported(&pattern),
        !pattern.contains('[') && !pattern.contains(']'),
        "support is refused exactly for character classes"
    );
    let has_star = pattern.contains('*');
    let has_question = pattern.contains('?');
    let matched = glob_matches(&pattern, &name);
    if !has_star && !has_question {
        assert_eq!(
            matched,
            pattern == name,
            "a literal pattern matches only the identical name"
        );
    }
    if !has_star {
        assert!(
            !matched || name.chars().count() == pattern.chars().count(),
            "without `*` every pattern character consumes exactly one name character"
        );
    }

    // Relative resolution, per sshd_config(5): absolute passes through,
    // relative resolves against /etc/ssh for an /etc including file and is
    // refused otherwise.
    if pattern.starts_with('/') {
        assert_eq!(
            absolute_pattern(&pattern, "/etc/ssh/sshd_config"),
            Some(PathBuf::from(&pattern))
        );
    } else {
        assert_eq!(
            absolute_pattern(&pattern, "/etc/ssh/sshd_config"),
            Some(Path::new("/etc/ssh").join(&pattern))
        );
        assert_eq!(
            absolute_pattern(&pattern, "/usr/etc/ssh/sshd_config"),
            None,
            "a vendor-layer file gives no base to resolve against"
        );
    }

    // First-wins over constructed segments. Each value that is simple enough
    // to parse unambiguously sets the directive from its segment; anything
    // else leaves a segment that does not set it. The expectation is then
    // the first setting segment in order, by construction.
    let material = String::from_utf8_lossy(rest).into_owned();
    let chunks: Vec<&str> = material.split('|').filter(|chunk| simple(chunk)).collect();
    let paths = ["/a", "/b", "/c"];
    let segments: Vec<(String, String)> = paths
        .iter()
        .enumerate()
        .map(|(i, path)| {
            let content = chunks.get(i).map_or_else(
                || "# nothing here".to_string(),
                |v| format!("PermitRootLogin {v}"),
            );
            (path.to_string(), content)
        })
        .collect();
    let resolved = ResolvedConfig::from_segments(segments.clone());
    let expected_first = segments
        .iter()
        .find(|(_, content)| content != "# nothing here")
        .cloned();
    assert_eq!(
        resolved
            .effective("PermitRootLogin")
            .map(|e| (e.value.clone(), e.source.clone())),
        expected_first.map(|(source, content)| {
            let value = content
                .strip_prefix("PermitRootLogin ")
                .expect("constructed");
            (value.to_string(), source)
        }),
        "effective answers from the first segment that sets the directive"
    );

    let expected_without_b = segments
        .iter()
        .find(|(path, content)| path != "/b" && content != "# nothing here")
        .cloned();
    assert_eq!(
        resolved
            .effective_without("PermitRootLogin", "/b")
            .map(|e| (e.value.clone(), e.source.clone())),
        expected_without_b.map(|(source, content)| {
            let value = content
                .strip_prefix("PermitRootLogin ")
                .expect("constructed");
            (value.to_string(), source)
        }),
        "effective_without answers from the first segment that is not ignored"
    );
});
