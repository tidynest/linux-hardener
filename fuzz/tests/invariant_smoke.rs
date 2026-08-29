//! Runs the fuzz targets' asserted invariants on fixed inputs, without
//! libfuzzer.
//!
//! CI bursts every target for 60 seconds a push, which finds inputs but
//! says nothing deterministic; and this laptop cannot run cargo-fuzz at
//! all (wrapper, rustup and argv[0] interplay). Each case here walks the
//! same invariants over a hand-checked input, so a wrong expectation is
//! caught by `RUSTFLAGS="--cfg fuzzing" cargo test` in this directory
//! rather than read as a parser bug. The flag is required because the
//! seams it reaches compile only under it.

use hardener_common::file_utils::{ConfigFormat, parse_config_value};
use hardener_core::ChangeType;
use hardener_plugins::fuzz_seams::nftables_include::with_include_line;
use hardener_plugins::fuzz_seams::pam_parsing::{
    apply_exact_directive, inline_arg_in_content, stack_loads_module,
};
use hardener_plugins::fuzz_seams::ssh_include::{
    ResolvedConfig, absolute_pattern, glob_matches, include_patterns, pattern_is_supported,
};
use std::path::{Path, PathBuf};

const INCLUDE: &str = "include \"/etc/linux-hardener/nftables/50-linux-hardener.nft\"";

#[test]
fn include_patterns_classifies_the_documented_cases() {
    // The cases the fuzz target asserts yield None:
    for line in ["# Include /x", "include", "PasswordAuthentication no", ""] {
        let trimmed = line.trim();
        let first_is_include = trimmed
            .split_whitespace()
            .next()
            .is_some_and(|w| w.eq_ignore_ascii_case("include"));
        let has_patterns = trimmed.split_whitespace().count() > 1;
        if include_patterns(line).is_none() {
            assert!(trimmed.starts_with('#') || !first_is_include || !has_patterns);
        }
    }
    // A live Include yields its patterns in order.
    let got = include_patterns("include /a.conf /b.conf").expect("live include");
    assert_eq!(got, vec!["/a.conf", "/b.conf"]);
    assert!(
        include_patterns("include").is_none(),
        "bare Include has no patterns"
    );
}

#[test]
fn glob_matches_holds_the_structural_facts() {
    assert!(glob_matches("50-*.conf", "50-hardener.conf"));
    assert!(glob_matches("*.conf", "a.conf"));
    assert!(!glob_matches("*.conf", "a.cfg"));
    assert!(glob_matches("a?c", "abc"));
    assert!(!glob_matches("a?c", "ac"));
    assert_eq!(glob_matches("abc", "abc"), true);
    assert_eq!(glob_matches("abc", "abd"), false);
    assert_eq!(pattern_is_supported("[ab].conf"), false);
    assert_eq!(pattern_is_supported("*.conf"), true);
}

#[test]
fn absolute_pattern_resolves_relative_includes_per_the_manual() {
    assert_eq!(
        absolute_pattern("/abs/x.conf", "/etc/ssh/sshd_config"),
        Some(PathBuf::from("/abs/x.conf"))
    );
    assert_eq!(
        absolute_pattern("x.conf", "/etc/ssh/sshd_config"),
        Some(Path::new("/etc/ssh").join("x.conf"))
    );
    assert_eq!(absolute_pattern("x.conf", "/usr/etc/ssh/sshd_config"), None);
}

#[test]
fn effective_answers_from_the_first_segment_that_sets_the_directive() {
    let segments = vec![
        ("/a".to_string(), "# nothing here".to_string()),
        ("/b".to_string(), "PermitRootLogin no".to_string()),
        ("/c".to_string(), "PermitRootLogin yes".to_string()),
    ];
    let resolved = ResolvedConfig::from_segments(segments);
    let got = resolved
        .effective("PermitRootLogin")
        .expect("a segment sets it");
    assert_eq!((got.value.as_str(), got.source.as_str()), ("no", "/b"));

    let without_b = resolved
        .effective_without("PermitRootLogin", "/b")
        .expect("another segment sets it");
    assert_eq!(
        (without_b.value.as_str(), without_b.source.as_str()),
        ("yes", "/c")
    );
}

const MODULE: &str = "pam_pwquality.so";

#[test]
fn stack_lines_load_and_carry_inline_args_only_when_live() {
    let content = format!("# auth required {MODULE} deny=decoy\nauth required {MODULE} deny=3\n");
    assert!(stack_loads_module(&content, MODULE));
    assert_eq!(
        inline_arg_in_content(&content, MODULE, "deny"),
        Some("3"),
        "the commented decoy must not win"
    );
    assert_eq!(
        inline_arg_in_content(&content, MODULE, "even_deny_root"),
        None,
        "only a whole-token arg= prefix matches"
    );
    let commented = format!("# auth required {MODULE}\n");
    assert!(!stack_loads_module(&commented, MODULE));
}

#[test]
fn apply_exact_directive_converges() {
    for format in [
        ConfigFormat::KeyValue,
        ConfigFormat::SpaceSeparated,
        ConfigFormat::Auto,
    ] {
        let mut file = "minlen = 4\n".to_string();
        let mut changed = false;
        let mut changes = Vec::new();
        apply_exact_directive(
            &mut file,
            &mut changed,
            &mut changes,
            "minlen",
            "9",
            format,
            "t",
        );
        assert_eq!(
            parse_config_value(&file, "minlen", format, true).as_deref(),
            Some("9"),
            "round trip in the written syntax ({format:?})"
        );
        let settled = file.clone();
        let changed_before = changed;
        apply_exact_directive(
            &mut file,
            &mut changed,
            &mut changes,
            "minlen",
            "9",
            format,
            "t",
        );
        assert_eq!(
            file, settled,
            "second application is byte-identical ({format:?})"
        );
        assert_eq!(changed, changed_before);
        assert_eq!(
            changes.last().map(|c| c.change_type),
            Some(ChangeType::Skipped)
        );
    }
}

#[test]
fn the_include_append_is_idempotent_and_loses_nothing() {
    let existing = "flush ruleset\n";
    let once = with_include_line(existing, INCLUDE);
    let twice = with_include_line(&once, INCLUDE);
    assert_eq!(once, twice);
    assert!(once.starts_with(existing));
    // Terminated content needs no separator: the include line starts a line
    // of its own already.
    assert_eq!(&once[existing.len()..], format!("{INCLUDE}\n"));

    // Unterminated content gets exactly one separator newline.
    let unterminated = "flush ruleset";
    let once = with_include_line(unterminated, INCLUDE);
    assert_eq!(&once[unterminated.len()..], format!("\n{INCLUDE}\n"));

    let already = format!("flush ruleset\n{INCLUDE}\n");
    assert_eq!(with_include_line(&already, INCLUDE), already);
    let indented = format!("flush ruleset\n  {INCLUDE}  \n");
    assert_eq!(
        with_include_line(&indented, INCLUDE),
        indented,
        "trim matches"
    );
    assert_eq!(with_include_line("", INCLUDE), format!("{INCLUDE}\n"));
}

/// The two inputs the fuzz-run job's first execution crashed on, held as
/// fixed cases so the regressions stay caught wherever cargo-fuzz cannot
/// run. Both are remote-input shapes: bytes decoded lossily, and line
/// endings a conffile can carry that no fixture hand-written from the same
/// reading as the code would have planted.
#[test]
fn findings_from_the_first_executed_run_stay_fixed() {
    // pam_stack_parsing, `-\r\r\r`: the writer rebuilt content through
    // `str::lines`, which eats a `\r` before a `\n`, so each application
    // after the first reported a change and ate a byte.
    let mut file = "-\r\r\r".to_string();
    let mut changed = false;
    let mut changes = Vec::new();
    for _ in 0..3 {
        apply_exact_directive(
            &mut file,
            &mut changed,
            &mut changes,
            "minlen",
            "-",
            ConfigFormat::SpaceSeparated,
            "fuzz.conf",
        );
    }
    assert_eq!(file, "-\r\r\r\nminlen -\n", "no byte is eaten after the first pass");
    assert_eq!(
        changes.last().map(|c| c.change_type),
        Some(ChangeType::Skipped),
        "an already-correct file records the no-op"
    );

    // config_directives: the case-insensitive prefix matcher sliced at the
    // prefix's byte length before comparing, and a line whose bytes put
    // that index inside a character panicked instead of answering unset.
    assert_eq!(
        parse_config_value("\u{FFFD}\u{FFFD}x\n", "umask", ConfigFormat::Auto, false),
        None,
        "a partial character is not a directive and must not be a panic"
    );
}
