#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`file_utils`](super).
//!
//! Split out of `file_utils.rs`, which carried two top-level test modules.
//! This file holds the first; the second is
//! `file_utils/global_scope_tests.rs`, kept separate because a module that
//! names what it covers says more than a second block inside a generic one.
//! This file sits in the `file_utils/` directory beside its source, which the
//! 2018 path rules allow with no `mod.rs` and no `#[path]`, so `super` still
//! resolves to `crate::file_utils` and every import carried across unchanged,
//! private items included.

use super::*;

/// `update_file_atomically` replaces the inode, so it re-applies the
/// original mode afterwards. A stat failure used to be indistinguishable
/// from "the file did not exist", leaving the rewritten file wearing the
/// temp file's 0600 instead of the original's mode, silently. Refusing is
/// safe here because nothing has been written yet.
#[test]
fn a_stat_failure_refuses_the_write_instead_of_changing_the_mode() {
    let dir = tempfile::tempdir().unwrap();
    // A regular file standing where a directory belongs: stat on a path
    // below it fails with ENOTDIR, which is emphatically not NotFound.
    let not_a_dir = dir.path().join("not-a-dir");
    std::fs::write(&not_a_dir, "regular file").unwrap();
    let target = not_a_dir.join("config");

    let kind = std::fs::metadata(&target).unwrap_err().kind();
    assert_ne!(
        kind,
        std::io::ErrorKind::NotFound,
        "test needs a non-NotFound stat failure, got {kind:?}"
    );

    let err = update_file_atomically(&target, "key = value\n")
        .expect_err("an unreadable mode must not be silently replaced");
    let message = err.to_string();
    assert!(
        message.contains("permissions could not be read"),
        "the refusal must name the cause: {message}"
    );
}

/// The genuinely-absent case still creates the file, since a file that
/// does not exist has no mode to preserve.
#[test]
fn a_missing_file_is_still_created() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("new.conf");

    update_file_atomically(&target, "key = value\n").expect("creating a new file must work");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "key = value\n");
}

/// A created file must not inherit the temporary file's private mode.
///
/// `NamedTempFile` creates 0600 so its contents are never briefly readable,
/// which is right for a temporary file and wrong for the configuration file
/// it becomes. Asserted as the literal 0644 rather than against the
/// constant that holds it, because comparing the value to itself would pass
/// against the 0600 that is the defect.
#[test]
fn a_created_file_is_readable_by_the_tools_that_consume_it() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("created.conf");

    update_file_atomically(&target, "key = value\n").unwrap();

    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o644,
        "a created configuration file at 0600 is unreadable to every \
             ordinary-user tool that reads it, and to a remote write of the same \
             file, which lands 0644"
    );
}

/// The mode of an existing file survives the inode swap.
#[test]
fn an_existing_files_mode_survives_the_rewrite() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("existing.conf");
    std::fs::write(&target, "old\n").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();

    update_file_atomically(&target, "new\n").unwrap();

    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644, "the original mode must be restored");
}

#[test]
fn auto_parses_key_equals_value_with_spaces() {
    assert_eq!(
        parse_config_value("minlen = 14\n", "minlen", ConfigFormat::Auto, true),
        Some("14".to_string())
    );
}

#[test]
fn auto_still_parses_space_separated() {
    assert_eq!(
        parse_config_value(
            "PASS_MAX_DAYS 99999\n",
            "PASS_MAX_DAYS",
            ConfigFormat::Auto,
            true
        ),
        Some("99999".to_string())
    );
}

#[test]
fn auto_parses_key_equals_value_without_spaces() {
    assert_eq!(
        parse_config_value("minlen=14\n", "minlen", ConfigFormat::Auto, true),
        Some("14".to_string())
    );
}

/// `sshd_config(5)` accepts `Key=Value`, and `sshd -t` accepts it too, so
/// reading such a line as "not set" reports a directive the host plainly
/// holds as absent.
#[test]
fn space_separated_reads_an_equals_separated_directive() {
    assert_eq!(
        parse_config_value(
            "PermitRootLogin=no\n",
            "PermitRootLogin",
            ConfigFormat::SpaceSeparated,
            false
        ),
        Some("no".to_string()),
    );
}

/// The value is what a caller compares against its target, so the
/// separator must never be returned in its place.
#[test]
fn space_separated_reads_a_spaced_equals_separator() {
    assert_eq!(
        parse_config_value(
            "PermitRootLogin = no\n",
            "PermitRootLogin",
            ConfigFormat::SpaceSeparated,
            false
        ),
        Some("no".to_string()),
    );
}

/// Ending a key at `=` must not end it anywhere else.
#[test]
fn space_separated_does_not_match_a_longer_key_that_starts_the_same() {
    assert_eq!(
        parse_config_value(
            "ClientAliveInterval=300\n",
            "ClientAlive",
            ConfigFormat::SpaceSeparated,
            false
        ),
        None,
    );
}

#[test]
fn space_separated_ignores_a_key_with_no_value() {
    assert_eq!(
        parse_config_value(
            "PermitRootLogin\n",
            "PermitRootLogin",
            ConfigFormat::SpaceSeparated,
            false
        ),
        None,
    );
}

const REAL_LOGIN_DEFS: &str = "\
#\tPASS_MAX_DAYS\tMaximum number of days a password may be used.
#
PASS_MAX_DAYS\t99999
PASS_MIN_DAYS\t0
";

#[test]
fn key_value_reads_a_whitespace_separated_directive() {
    assert_eq!(
        parse_config_value(
            REAL_LOGIN_DEFS,
            "PASS_MAX_DAYS",
            ConfigFormat::KeyValue,
            true
        ),
        Some("99999".to_string()),
    );
}

#[test]
fn key_value_still_reads_an_equals_separated_directive() {
    assert_eq!(
        parse_config_value("minlen = 14\n", "minlen", ConfigFormat::KeyValue, true),
        Some("14".to_string()),
    );
}

#[test]
fn key_value_does_not_match_a_longer_key_that_starts_the_same() {
    assert_eq!(
        parse_config_value(REAL_LOGIN_DEFS, "PASS_MAX", ConfigFormat::KeyValue, true),
        None,
        "the separator test is what enforces the key boundary",
    );
}

#[test]
fn key_value_ignores_a_key_with_no_value() {
    assert_eq!(
        parse_config_value(
            "PASS_MAX_DAYS\n",
            "PASS_MAX_DAYS",
            ConfigFormat::KeyValue,
            true
        ),
        None,
    );
}

#[test]
fn a_damaged_file_reports_the_live_line_not_the_appended_one() {
    let damaged = format!("{REAL_LOGIN_DEFS}PASS_MAX_DAYS = 90\n");
    assert_eq!(
        parse_config_value(&damaged, "PASS_MAX_DAYS", ConfigFormat::Auto, true),
        Some("99999".to_string()),
        "the live line comes first and is what the system enforces",
    );
}

#[test]
fn the_live_line_is_rewritten_not_the_comment_above_it() {
    let out = set_config_directive(
        REAL_LOGIN_DEFS,
        "PASS_MAX_DAYS",
        "90",
        ConfigFormat::SpaceSeparated,
        true,
        Duplicates::Keep,
    );
    assert!(
        out.contains("#\tPASS_MAX_DAYS\tMaximum number of days"),
        "the explanatory comment must survive:\n{out}",
    );
    assert!(
        out.contains("PASS_MAX_DAYS 90"),
        "the live line must carry the new value:\n{out}",
    );
    assert!(
        !out.contains("99999"),
        "and the old value must be gone:\n{out}",
    );
}

#[test]
fn a_commented_default_with_no_live_line_is_still_replaced() {
    let out = set_config_directive(
        "#PermitRootLogin prohibit-password\n",
        "PermitRootLogin",
        "no",
        ConfigFormat::SpaceSeparated,
        true,
        Duplicates::Keep,
    );
    assert_eq!(out.trim(), "PermitRootLogin no");
}

#[test]
fn remove_drops_a_later_definition_of_the_same_key() {
    // The commented occurrence sits BELOW the live line, in the same
    // stretch the removal loop walks. A comment above it could never be a
    // removal candidate, so it proves nothing about the loop.
    let damaged = format!("{REAL_LOGIN_DEFS}#PASS_MAX_DAYS 12345\nPASS_MAX_DAYS = 90\n");
    let out = set_config_directive(
        &damaged,
        "PASS_MAX_DAYS",
        "90",
        ConfigFormat::SpaceSeparated,
        true,
        Duplicates::Remove,
    );
    assert!(out.contains("PASS_MAX_DAYS 90"), "{out}");
    assert!(
        !out.contains("PASS_MAX_DAYS = 90"),
        "the appended line must go:\n{out}"
    );
    assert!(
        out.contains("#\tPASS_MAX_DAYS\tMaximum number of days"),
        "a comment is documentation and is never removed:\n{out}",
    );
    assert!(
        out.contains("#PASS_MAX_DAYS 12345"),
        "a comment below the live line is not a duplicate either:\n{out}",
    );
}

#[test]
fn keep_leaves_a_match_block_directive_alone() {
    let sshd = "\
PermitRootLogin yes
Match Address 10.0.0.0/8
    PermitRootLogin yes
";
    let out = set_config_directive(
        sshd,
        "PermitRootLogin",
        "no",
        ConfigFormat::SpaceSeparated,
        true,
        Duplicates::Keep,
    );
    assert!(out.contains("PermitRootLogin no"), "{out}");
    assert!(
        out.contains("    PermitRootLogin yes"),
        "a Match scoped directive is not a duplicate and must survive:\n{out}",
    );
}

/// The only live occurrence of a directive can sit inside a `Match` block
/// while the global setting exists only as a commented default. Rewriting
/// the block line would leave the global at sshd's compiled default and
/// narrow the new value to the block's scope, so the commented global is
/// the only correct target.
#[test]
fn a_global_directive_is_never_written_inside_a_match_block() {
    let sshd = "\
#PermitRootLogin prohibit-password
Match Address 10.0.0.0/8
    PermitRootLogin yes
";
    let out = set_config_directive(
        sshd,
        "PermitRootLogin",
        "no",
        ConfigFormat::SpaceSeparated,
        true,
        Duplicates::Keep,
    );

    assert_eq!(
        out.lines().next(),
        Some("PermitRootLogin no"),
        "the commented global default is the line to rewrite:\n{out}",
    );
    assert!(
        out.contains("Match Address 10.0.0.0/8\n    PermitRootLogin yes"),
        "the block must survive byte for byte, indentation included:\n{out}",
    );
    assert_eq!(
        out.lines().count(),
        3,
        "no line may be added inside the block:\n{out}",
    );
    assert_eq!(
        out.lines()
            .filter(|l| l.trim() == "PermitRootLogin no")
            .count(),
        1,
        "the new value belongs to the global scope only:\n{out}",
    );
}

/// Appending a brand new directive at the end of the file would land it
/// inside a trailing block, scoping a global setting to whatever that
/// block matches.
#[test]
fn a_new_directive_is_inserted_above_a_trailing_match_block() {
    let sshd = "\
Port 22
Match User deploy
    PasswordAuthentication yes
";
    let out = set_config_directive(
        sshd,
        "PermitRootLogin",
        "no",
        ConfigFormat::SpaceSeparated,
        true,
        Duplicates::Keep,
    );
    assert_eq!(
        out,
        "Port 22\nPermitRootLogin no\nMatch User deploy\n    PasswordAuthentication yes\n",
    );
}

/// A commented `Match` opens no block, so it must not shorten the region
/// the writer may consider.
#[test]
fn a_commented_match_does_not_end_the_global_region() {
    let sshd = "\
#Match Address 10.0.0.0/8
PermitRootLogin yes
";
    let out = set_config_directive(
        sshd,
        "PermitRootLogin",
        "no",
        ConfigFormat::SpaceSeparated,
        true,
        Duplicates::Keep,
    );
    assert_eq!(out, "#Match Address 10.0.0.0/8\nPermitRootLogin no\n");
}

/// `faillock.conf` and its siblings ship their defaults commented out, and
/// an operator writes `deny=10` as readily as `deny = 10`. A key that ends
/// at the `=` rather than at whitespace is still the live definition, so it
/// is the line to rewrite: activating the comment above it would leave the
/// operator's own setting standing below the tool's.
#[test]
fn a_live_key_equals_value_line_beats_the_comment_above_it() {
    let faillock = "\
# deny = 3
deny=10
";
    let out = set_config_directive(
        faillock,
        "deny",
        "5",
        ConfigFormat::KeyValue,
        true,
        Duplicates::Remove,
    );
    assert_eq!(out, "# deny = 3\ndeny = 5\n");
}

/// A file the writer cannot see through is rewritten on every run and never
/// converges: the tool reports the value it wrote while its own reader
/// still returns the one it left in place.
#[test]
fn rewriting_a_key_equals_value_line_converges_in_one_pass() {
    let out = set_config_directive(
        "minlen=8\n",
        "minlen",
        "14",
        ConfigFormat::KeyValue,
        true,
        Duplicates::Remove,
    );
    assert_eq!(out, "minlen = 14\n");
    assert_eq!(
        parse_config_value(&out, "minlen", ConfigFormat::Auto, true),
        Some("14".to_string()),
        "the reader must agree with what the writer just wrote:\n{out}",
    );
}

/// Ending the key at `=` must not end it anywhere else: `PASS_MAX` is not
/// a definition of `PASS_MAX_DAYS`, so the writer appends its own line
/// rather than rewriting the longer key's.
#[test]
fn the_writer_does_not_match_a_longer_key_that_starts_the_same() {
    let out = set_config_directive(
        REAL_LOGIN_DEFS,
        "PASS_MAX",
        "1",
        ConfigFormat::SpaceSeparated,
        true,
        Duplicates::Keep,
    );
    assert!(
        out.contains("PASS_MAX_DAYS\t99999"),
        "the longer key is a different directive and must be untouched:\n{out}",
    );
    assert!(
        out.ends_with("PASS_MAX 1\n"),
        "the new directive is appended as its own line, terminated:\n{out}",
    );
}

/// sshd reads `match` as readily as `Match`, so the boundary is ASCII
/// case insensitive.
#[test]
fn a_lowercase_match_ends_the_global_region_too() {
    let sshd = "\
#PermitRootLogin prohibit-password
match address 10.0.0.0/8
    PermitRootLogin yes
";
    let out = set_config_directive(
        sshd,
        "PermitRootLogin",
        "no",
        ConfigFormat::SpaceSeparated,
        true,
        Duplicates::Keep,
    );
    assert_eq!(
        out.lines().next(),
        Some("PermitRootLogin no"),
        "the commented global default is the line to rewrite:\n{out}",
    );
    assert!(
        out.contains("    PermitRootLogin yes"),
        "the block line must survive:\n{out}",
    );
}

/// The writer's output is a file, and a file ends with a newline.
///
/// It did not. `content.lines()` discards the terminator and `join("\n")` does
/// not put one back, so every rewrite came back one byte short and the next
/// thing appended to that file landed on the last directive. The symptom that
/// found it was sshd refusing `Bad SSH2 mac spec '...umac-128-etm@openssh.comMaxAuthTries'`.
#[test]
fn the_written_content_is_newline_terminated() {
    let out = set_config_directive(
        "Port 22\n",
        "PermitRootLogin",
        "no",
        ConfigFormat::SpaceSeparated,
        true,
        Duplicates::Keep,
    );
    assert!(
        out.ends_with('\n'),
        "an appended directive left the file unterminated:\n{out:?}",
    );

    // The loss was never conditional on appending. A directive rewritten where
    // it already stands took the terminator with it too, which is why a host
    // needed no new directive to end up with a truncated file.
    let rewritten = set_config_directive(
        "PermitRootLogin yes\n",
        "PermitRootLogin",
        "no",
        ConfigFormat::SpaceSeparated,
        true,
        Duplicates::Keep,
    );
    assert_eq!(rewritten, "PermitRootLogin no\n");
}

/// Terminating the output must not accumulate blank lines, or a compliant file
/// grows by one every run and each run reports a change it did not need to
/// make. This is the positive control on the fix: it fails just as loudly for a
/// writer that appends a newline unconditionally as the test above fails for
/// one that appends none.
#[test]
fn an_existing_trailing_blank_line_is_neither_lost_nor_multiplied() {
    let with_blank = "Port 22\n\n";
    let once = set_config_directive(
        with_blank,
        "PermitRootLogin",
        "no",
        ConfigFormat::SpaceSeparated,
        true,
        Duplicates::Keep,
    );
    assert_eq!(
        once, "Port 22\n\nPermitRootLogin no\n",
        "the blank line the file already had must survive unchanged",
    );

    // And the second pass, which is what an operator running apply twice sees.
    let twice = set_config_directive(
        &once,
        "PermitRootLogin",
        "no",
        ConfigFormat::SpaceSeparated,
        true,
        Duplicates::Keep,
    );
    assert_eq!(
        twice, once,
        "a second pass over its own output must be a no-op"
    );
}

// ---------------------------------------------------------------------------
// The file_utils survivors of the 2026-08-11 mutation pass.
//
// Fourteen mutants lived here, on functions that reach disk, which the Phase 4
// triage rule calls bugs rather than notes. `parse_config_value` was already
// exercised thirteen times and two of its mutants still survived, which is the
// reminder that a function having tests is not the same as its behaviour being
// pinned. The other five functions had nothing at all.
// ---------------------------------------------------------------------------

/// `read_config_file` survived returning `Ok(String::new())` and
/// `Ok("xyzzy".into())`: nothing asserted that what comes back is what is on
/// disk. Every plugin's view of a configuration file arrives through here, so
/// a constant would make each of them agree with a file that does not exist.
#[test]
fn reading_a_config_file_returns_what_the_file_holds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sshd_config");
    let contents = "PermitRootLogin no\nPort 22\n";
    std::fs::write(&path, contents).expect("write the file");

    assert_eq!(
        read_config_file(&path).expect("a readable file is read"),
        contents,
        "the reader must return the file's bytes, not a value of its own"
    );
}

/// The optional reader survived `Ok(None)`, `Ok(Some(String::new()))` and
/// `Ok(Some("xyzzy".into()))`. Present-and-readable is the case all three
/// constants get wrong.
#[test]
fn the_optional_reader_returns_the_contents_of_a_file_that_is_there() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("faillock.conf");
    let contents = "deny = 5\n";
    std::fs::write(&path, contents).expect("write the file");

    assert_eq!(
        read_config_file_optional(&path).expect("a readable file is read"),
        Some(contents.to_string()),
        "a file that is present must come back with its contents"
    );
}

/// Absent is the one error this reader is allowed to swallow, and the mutants
/// that forced the `NotFound` guard to `false` or flipped its `==` turned that
/// into a hard failure. A plugin asking after an optional file it does not
/// have would then fail its whole scan.
#[test]
fn the_optional_reader_reports_a_missing_file_as_absent_rather_than_failing() {
    let dir = tempfile::tempdir().expect("tempdir");

    assert_eq!(
        read_config_file_optional(&dir.path().join("not-here.conf"))
            .expect("an absent optional file is not an error"),
        None,
        "a file that is not there must read as absent"
    );
}

/// The other side of the same guard, and the case that kills forcing it to
/// `true`. A directory is present and unreadable as text: `read_to_string`
/// fails with `EISDIR`, which is emphatically not `NotFound`, and swallowing
/// it would report a path that exists and cannot be read as one that is simply
/// absent. That conflation is the shape this project has already paid for
/// once, in the pam plugin.
#[test]
fn the_optional_reader_refuses_an_error_that_is_not_absence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("a-directory");
    std::fs::create_dir(&path).expect("create the directory");

    assert!(
        read_config_file_optional(&path).is_err(),
        "a path that exists and cannot be read as text must fail, not read as absent"
    );
}

/// `parse_config_value` survived `==` becoming `!=` in its case-sensitive key
/// comparison, which inverts the match: every directive except the one asked
/// for would answer. Two directives are needed to see it, because with one the
/// inverted comparison has nothing to return.
#[test]
fn a_case_sensitive_lookup_answers_with_the_directive_that_was_asked_for() {
    let content = "Alpha 1\nBeta 2\n";

    assert_eq!(
        parse_config_value(content, "Beta", ConfigFormat::SpaceSeparated, true),
        Some("2".to_string()),
        "the value must come from the directive whose key matches, not from the \
         first key that does not"
    );
    assert_eq!(
        parse_config_value(content, "beta", ConfigFormat::SpaceSeparated, true),
        None,
        "a case-sensitive lookup must not match a differently-cased key"
    );
}

/// `strip_prefix_with_case` survived `>=` becoming `<` on its length check.
/// The case-insensitive arm is the whole of what that guard protects, so an
/// ordinary case-insensitive hit is what dies.
#[test]
fn a_case_insensitive_prefix_matches_regardless_of_case() {
    assert_eq!(
        strip_prefix_with_case("PermitRootLogin=no", "permitrootlogin", false),
        Some("=no"),
        "the case-insensitive arm must match and return the text after the prefix"
    );
}

/// The same guard survived `&&` becoming `||`, which is the dangerous
/// direction: the length check alone would then pass, the content comparison
/// would never run, and any line at least as long as the directive name would
/// match it. A key of the same length as the one asked for is what shows it.
#[test]
fn a_prefix_of_the_right_length_but_the_wrong_text_does_not_match() {
    assert_eq!(
        strip_prefix_with_case("Bar=1", "Foo", false),
        None,
        "matching on length alone would make every directive of the right width \
         answer for every other"
    );
}

/// `create_timestamped_backup` survived returning `Ok(Default::default())`,
/// which writes no backup and hands back an empty path while reporting
/// success. Every plugin's rollback contract rests on the copy this makes, and
/// a backup that silently is not written is invisible until the rollback that
/// needs it.
#[test]
fn a_timestamped_backup_is_actually_written_and_carries_the_original_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("hardening.rules");
    let contents = "-w /etc/passwd -p wa -k identity\n";
    std::fs::write(&path, contents).expect("write the file");

    let backup = create_timestamped_backup(&path).expect("the backup is taken");

    assert!(
        backup.exists(),
        "the returned path must name a file that exists: {}",
        backup.display()
    );
    assert_eq!(
        std::fs::read_to_string(&backup).expect("read the backup"),
        contents,
        "the backup must hold the bytes of the file it was taken from"
    );
    assert_ne!(
        backup, path,
        "the backup must be a second file, not the original"
    );
}

/// `safe_copy_to_new` survived `||` becoming `&&` in its destination guard,
/// and a dangling symlink is exactly the input that separates the two: it is
/// a symlink that does not exist, so the real guard refuses on the second
/// test while the mutant's conjunction lets it through. The guard is there to
/// stop a symlink race on a predictable backup path, so the distinction is a
/// security one rather than a tidiness one.
///
/// The mutant still fails, because `O_EXCL` refuses too, but it fails with a
/// different message from a later stage. Asserting on which error comes back
/// is what separates them; asserting merely that one did would pass on both.
#[test]
fn copying_refuses_a_destination_that_is_a_dangling_symlink() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("sshd_config");
    std::fs::write(&source, "Port 22\n").expect("write the source");

    let destination = dir.path().join("sshd_config.backup.1");
    std::os::unix::fs::symlink(dir.path().join("no-such-target"), &destination)
        .expect("plant a dangling symlink at the backup path");

    let error = safe_copy_to_new(&source, &destination)
        .expect_err("a symlink standing at the destination must be refused");

    assert!(
        error.to_string().contains("already exists"),
        "the destination guard must refuse a symlink before opening anything: got {error}"
    );
}
