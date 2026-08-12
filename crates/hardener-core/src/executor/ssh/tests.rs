#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`ssh`](super).
//!
//! Split out of `executor/ssh.rs`. This file sits in the `executor/ssh/`
//! directory beside it, which the 2018 path rules allow with no `mod.rs` and
//! no `#[path]`, so `super` still resolves to `crate::executor::ssh` and
//! every import carried across unchanged, private items included.

use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn connect_error_carries_reason_and_no_hint_on_network_failure() {
    // openssh's `{e:#}` for a closed port; the reason must reach the user
    // and a genuine network fault must never get the auth hint.
    let detail = "failed to connect to the remote host: connect to host 10.0.0.5 port 22: Connection refused";
    let msg = connect_error_message("10.0.0.5", detail);
    assert!(msg.starts_with("Failed to connect to 10.0.0.5: "));
    assert!(msg.contains("Connection refused"), "reason surfaced: {msg}");
    assert!(
        !msg.contains("ssh-add"),
        "network failure must not get the auth hint: {msg}"
    );
}

#[test]
fn connect_error_appends_hint_on_auth_failure() {
    let detail =
        "failed to connect to the remote host: root@10.0.0.5: Permission denied (publickey).";
    let msg = connect_error_message("10.0.0.5", detail);
    assert!(
        msg.contains("Permission denied (publickey)"),
        "reason surfaced: {msg}"
    );
    assert!(
        msg.contains("ssh-add"),
        "auth failure gets the ssh-agent/key hint: {msg}"
    );
}

#[test]
fn tee_command_round_trips_newline_terminated_content() {
    // A remote apply→rollback cycle must not grow files: content that
    // already ends in a newline gets no separator before the delimiter.
    let content = "Hello!\n";
    let delim = unique_delimiter(content);
    let cmd = tee_command(Path::new("/tmp/t"), content);
    assert!(
        cmd.ends_with(&format!("<< '{delim}'\n{content}{delim}")),
        "newline-terminated content must not be doubled: {cmd}"
    );
}

#[test]
fn tee_command_terminates_bare_content_with_single_newline() {
    let content = "Hello!";
    let delim = unique_delimiter(content);
    let cmd = tee_command(Path::new("/tmp/t"), content);
    assert!(
        cmd.ends_with(&format!("<< '{delim}'\n{content}\n{delim}")),
        "bare content gains exactly one heredoc newline: {cmd}"
    );
}

#[test]
fn tee_command_writes_empty_content_as_empty_body() {
    let delim = unique_delimiter("");
    let cmd = tee_command(Path::new("/tmp/t"), "");
    assert!(
        cmd.ends_with(&format!("<< '{delim}'\n{delim}")),
        "empty content must produce an empty heredoc body: {cmd}"
    );
}

#[test]
fn parse_stat_zero_perm_file_is_not_confused_with_missing() {
    // A remote 0000-perm regular file (e.g. Arch's /etc/shadow): rollback reads
    // mode 0 as "did not exist" and deletes it, so an existing file must never
    // parse to mode 0. Parity with local.rs::metadata_of_zero_perm_file_*.
    let meta = parse_metadata_probe("E\nregular empty file 0 0 0 0").expect("parse");
    assert!(meta.exists && meta.is_file);
    assert_ne!(
        meta.mode, 0,
        "existing 0000-perm remote file must not report mode 0"
    );
    assert_eq!(
        meta.mode & 0o777,
        0,
        "permission bits must still read as 0000"
    );
}

#[test]
fn parse_stat_directory_preserves_perms_and_type() {
    let meta = parse_metadata_probe("E\ndirectory 755 4096 0 0").expect("parse");
    assert!(meta.is_dir);
    assert_eq!(meta.mode & 0o777, 0o755);
    assert_ne!(meta.mode & 0o170000, 0, "type bit present for existing dir");
}

#[test]
fn parse_stat_regular_file_parses_all_fields() {
    // rsplitn from the right: gid=42, uid=0, size=1234, mode=640, type="regular file".
    let meta = parse_metadata_probe("E\nregular file 640 1234 0 42").expect("parse");
    assert_eq!(meta.mode & 0o777, 0o640);
    assert_eq!(meta.size, 1234);
    assert_eq!(meta.uid, 0);
    assert_eq!(meta.gid, 42);
}

#[test]
fn probe_marks_existing_but_unreadable_path_as_unverifiable() {
    // The whole point of the change: `stat` failed on a path that is there.
    // Reporting this as absent is what let rollback delete /etc/passwd.
    let err = parse_metadata_probe("E\n").expect_err("must not report absence");
    let message = format!("{err:#}");
    assert!(
        message.contains("could not be read"),
        "error must say the metadata was unreadable, got: {message}"
    );
}

#[test]
fn probe_reports_confirmed_absence_as_ok() {
    // `test -e` said no and `stat` printed nothing: absence is confirmed, and
    // this must stay a non-error so hosts lacking an optional path still work.
    let meta = parse_metadata_probe("N\n").expect("confirmed absence is not an error");
    assert!(!meta.exists);
    assert_eq!(
        meta.mode, 0,
        "absent path keeps the mode-0 'did not exist' sentinel"
    );
}

#[test]
fn probe_trusts_a_parsed_stat_line_over_a_losing_marker() {
    // `test -e` can lose a race with a path being created between the two
    // probes. A parsed stat line is the stronger evidence.
    let meta = parse_metadata_probe("N\nregular file 640 1234 0 42")
        .expect("a stat line wins over the marker");
    assert!(meta.exists);
    assert_eq!(meta.mode & 0o777, 0o640);
}

#[test]
fn probe_rejects_an_unrecognised_marker() {
    // A shell that emitted something else entirely must not be read as absence.
    parse_metadata_probe("something unexpected\n")
        .expect_err("an unrecognised marker must not report absence");
}

#[test]
fn probe_rejects_empty_or_whitespace_only_output() {
    // The original bug's second, unreported arm: completely empty command
    // output (a dropped connection, a shell that printed nothing at all)
    // read as confirmed absence too, not just the `NOTFOUND` sentinel.
    // Only a bare `N` marker may ever confirm absence.
    for stdout in ["", "\n", "   \n", "\n\n   \n"] {
        let err = parse_metadata_probe(stdout)
            .expect_err("empty or whitespace-only output must not confirm absence");
        let message = format!("{err:#}");
        assert!(
            message.contains("unrecognised metadata probe output"),
            "error must name what was actually received, got: {message}"
        );
    }
}

#[test]
fn path_exists_probe_confirms_presence() {
    let exists = parse_path_exists_probe("yes\n").expect("a bare yes must parse");
    assert!(exists, "yes must report presence");
}

#[test]
fn path_exists_probe_confirms_absence() {
    let exists = parse_path_exists_probe("no\n").expect("a bare no must parse");
    assert!(!exists, "no must report absence");
}

#[test]
fn path_exists_probe_rejects_unexpected_output() {
    // A remote shell that emits a banner, a sudo prompt, or any other
    // noise ahead of the marker must not be read as "no" - that is the
    // bug this branch exists to fix, one function over from where it was
    // first found.
    let err = parse_path_exists_probe("Last login: Tue Jan  1 00:00:00 2026\nyes")
        .expect_err("noise ahead of the marker must not resolve to a boolean");
    let message = format!("{err:#}");
    assert!(
        message.contains("unrecognised path_exists probe output"),
        "error must name what was actually received, got: {message}"
    );
}

#[test]
fn metadata_probe_confirms_existence_and_reads_stat_in_one_round_trip() {
    let cmd = metadata_probe_command(Path::new("/etc/shadow"));
    assert!(
        cmd.contains("test -e"),
        "absence must be positively confirmed, not inferred from stat failing"
    );
    assert!(cmd.contains("stat -c '%F %a %s %u %g'"));
    assert!(cmd.contains("echo E") && cmd.contains("echo N"));
    assert!(
        cmd.contains("LC_ALL=C stat -c"),
        "the locale pin must sit on `stat` itself, since %F is translated and \
         the parser matches English only (#155): {cmd}"
    );
    assert!(
        !cmd.contains("NOTFOUND"),
        "the sentinel that conflated absent with unreadable must be gone"
    );
}

#[test]
fn metadata_probe_escapes_a_path_with_spaces() {
    // Both occurrences of the path must be escaped, or a crafted path could
    // break out of one of them.
    let cmd = metadata_probe_command(Path::new("/etc/my dir/file"));
    assert!(
        !cmd.contains("/etc/my dir/file "),
        "unescaped path leaked into the command: {cmd}"
    );
}

// The two tests above assert on substrings of the command text. A command
// with `&&`/`||` swapped, or a `stat` gated on the wrong branch, still
// contains every one of those substrings and would still pass them - that
// textual match is exactly how the original `|| echo 'NOTFOUND'` survived
// review. The tests below run the real command through a real shell
// instead, so they exercise the actual branch behaviour.

/// Scratch directory unique to one test run, so parallel test binaries and
/// repeated runs never collide. Removed on drop, including on panic, so a
/// failing assertion never leaks a directory under the system temp dir.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(label: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "hardener-ssh-metadata-probe-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs `metadata_probe_command(path)` through a real `/bin/sh -c`,
/// optionally shadowing PATH lookups with `fake_bin_dir` prepended ahead
/// of the real PATH (used to make `stat` resolve to a binary that always
/// fails), and returns raw stdout for `parse_metadata_probe` to classify.
/// The shell itself is located by absolute path so overriding PATH for
/// `stat` resolution never breaks finding `sh`.
fn run_probe(path: &Path, fake_bin_dir: Option<&Path>) -> String {
    let mut command = std::process::Command::new("/bin/sh");
    command.arg("-c").arg(metadata_probe_command(path));
    if let Some(dir) = fake_bin_dir {
        let real_path = std::env::var("PATH").unwrap_or_default();
        command.env("PATH", format!("{}:{real_path}", dir.display()));
    }
    let output = command
        .output()
        .expect("run the metadata probe under a real shell");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn metadata_probe_execution_confirms_an_existing_readable_path() {
    let dir = ScratchDir::new("exists");
    let file = dir.path().join("target");
    std::fs::write(&file, b"content").expect("write fixture file");

    let stdout = run_probe(&file, None);
    assert!(
        stdout.starts_with("E\n"),
        "an existing path must be positively confirmed, got: {stdout:?}"
    );
    let meta = parse_metadata_probe(&stdout).expect("existing readable path must parse");
    assert!(meta.exists, "readable existing path must report exists");
}

#[test]
fn metadata_probe_execution_confirms_an_absent_path() {
    let dir = ScratchDir::new("absent");
    let missing = dir.path().join("does-not-exist");

    let stdout = run_probe(&missing, None);
    assert_eq!(
        stdout.trim(),
        "N",
        "an absent path must yield a bare N marker, got: {stdout:?}"
    );
    let meta = parse_metadata_probe(&stdout).expect("confirmed absence must not be an error");
    assert!(!meta.exists, "absent path must report exists = false");
}

#[test]
fn metadata_probe_execution_flags_an_existing_unreadable_path_as_unverifiable() {
    let dir = ScratchDir::new("stat-fails");
    let file = dir.path().join("target");
    std::fs::write(&file, b"content").expect("write fixture file");

    // Shadow `stat` on PATH with a binary that always fails, so the path
    // genuinely exists while the stat probe genuinely produces nothing -
    // the same shape an incompatible `stat` or a permission error
    // produces on a real host. `test` and `echo` are shell builtins, so
    // they still resolve correctly under this restricted PATH.
    let fake_bin = dir.path().join("fakebin");
    std::fs::create_dir_all(&fake_bin).expect("create fake bin dir");
    let fake_stat = fake_bin.join("stat");
    std::fs::write(&fake_stat, b"#!/bin/sh\nexit 1\n").expect("write fake stat binary");
    let mut perms = std::fs::metadata(&fake_stat)
        .expect("stat the fake stat binary")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&fake_stat, perms).expect("make fake stat executable");

    let stdout = run_probe(&file, Some(&fake_bin));
    assert_eq!(
        stdout.trim(),
        "E",
        "existing path with a failing stat must yield a bare E marker, got: {stdout:?}"
    );
    let err = parse_metadata_probe(&stdout)
        .expect_err("a path that exists but cannot be stat'd must never read as absent");
    let message = format!("{err:#}");
    assert!(
        message.contains("could not be read"),
        "error must say the metadata was unreadable, got: {message}"
    );
}

/// An installed locale under which `stat -c '%F'` answers in another language,
/// or `None` when this machine cannot ask the question.
///
/// The search is the guard as much as the setup. A hard-coded locale name that
/// happens not to be generated would leave `stat` falling back to English, and
/// the test below would then pass without asking anything at all: it would
/// prove the pin works against output the pin was never needed for. Requiring
/// the chosen locale to actually change the answer is what makes the pass mean
/// something, and its absence a stated skip rather than a silent one.
fn a_locale_that_translates_stat(probe_file: &Path) -> Option<String> {
    let listed = std::process::Command::new("locale")
        .arg("-a")
        .output()
        .ok()?;
    let names: Vec<String> = String::from_utf8_lossy(&listed.stdout)
        .lines()
        .map(str::to_string)
        .collect();

    names.into_iter().find(|name| {
        std::process::Command::new("stat")
            .args(["-c", "%F"])
            .arg(probe_file)
            .env("LC_ALL", name)
            .output()
            .is_ok_and(|output| !String::from_utf8_lossy(&output.stdout).contains("regular"))
    })
}

/// The probe answers in English however the remote host is configured (#155).
///
/// `%F` is translated and `parse_stat_fields` matches `regular` and `directory`
/// literally, so without the `LC_ALL=C` pin a Swedish host reports `normal fil`
/// for a file and `katalog` for a directory: `is_file` goes false, checkpoint
/// capture in `hardener-state` skips a path it looked at and found, and the
/// wrong type bit lands in `mode`. `LocalExecutor` reads `std::fs::Metadata`
/// and carries no locale, so this is also what keeps the two executors
/// answering alike.
///
/// This runs the real command through a real shell under an inherited hostile
/// locale, rather than asserting that the command text contains the pin. The
/// text assertion above cannot tell a pin on `stat` from one placed where it
/// does nothing.
#[test]
fn the_metadata_probe_answers_in_english_under_a_translated_locale() {
    let dir = ScratchDir::new("locale");
    let file = dir.path().join("target");
    std::fs::write(&file, b"content").expect("write fixture file");

    let Some(locale) = a_locale_that_translates_stat(&file) else {
        eprintln!(
            "unaskable: no locale installed here translates `stat -c '%F'`, so \
             the pin cannot be exercised on this machine"
        );
        return;
    };

    for (path, is_file, is_dir) in [(file.as_path(), true, false), (dir.path(), false, true)] {
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(metadata_probe_command(path))
            .env("LC_ALL", &locale)
            .output()
            .expect("run the metadata probe under a translated locale");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();

        let meta = parse_metadata_probe(&stdout)
            .unwrap_or_else(|e| panic!("probe under {locale} must still parse: {e:#}"));
        assert_eq!(
            meta.is_file,
            is_file,
            "is_file for {} under {locale}, from probe output {stdout:?}",
            path.display()
        );
        assert_eq!(
            meta.is_dir,
            is_dir,
            "is_dir for {} under {locale}, from probe output {stdout:?}",
            path.display()
        );
    }
}

/// The checkpoint host key is derived by a free function rather than only
/// inside `description`, so a fleet run can predict the key a host will file
/// under before it opens a connection. Deriving it twice would let the
/// prediction and the record drift, which is the drift `host_key_for`'s own
/// documentation exists to prevent, so `description` calls this and nothing
/// else formats the string.
#[test]
fn checkpoint_host_key_names_the_account_the_target_gave() {
    assert_eq!(
        checkpoint_host_key(Some("admin"), "web-01", 22),
        "ssh://admin@web-01:22"
    );
    assert_eq!(
        checkpoint_host_key(Some("admin"), "web-01", 2222),
        "ssh://admin@web-01:2222",
        "the port is part of the key, so one machine on two ports is two keys"
    );
}

/// The defect this used to pin is fixed, and what replaces it is deliberately
/// weaker than "the two forms are always two keys".
///
/// A bare target now resolves through the operator's ssh configuration, so on a
/// host whose config really does say `User root` the two forms agree, and they
/// should: they name the same account on the same machine, and the fleet
/// collision refusal is then right to treat a run selecting both as one target
/// twice. What can no longer happen is the two agreeing because the key
/// *invented* an account nobody named. That case is covered by
/// [`a_bare_target_is_filed_under_the_resolved_user`], which is the one that
/// pins the fix; this one pins only the part that does not depend on whose
/// machine the suite runs on.
#[test]
fn checkpoint_host_key_keeps_the_target_it_was_given() {
    assert_eq!(
        checkpoint_host_key(Some("root"), "web-01", 22),
        "ssh://root@web-01:22",
        "an explicit root is still filed under root"
    );
    assert!(
        checkpoint_host_key(None, "web-01", 22).ends_with("@web-01:22"),
        "however the user resolves, the host and port are still the key's tail"
    );
}

/// An explicitly named user is never resolved: the operator said which account.
#[test]
fn an_explicit_user_is_taken_at_its_word() {
    let key = checkpoint_host_key_with(
        |_| panic!("a target that names its user must not consult ssh"),
        Some("admin"),
        "web-01",
        22,
    );
    assert_eq!(key, "ssh://admin@web-01:22");
}

/// A bare target is filed under the account ssh would actually reach, which is
/// the whole defect: the fabricated `root` made it one key with `root@host`.
#[test]
fn a_bare_target_is_filed_under_the_resolved_user() {
    let key = checkpoint_host_key_with(
        |host| {
            assert_eq!(
                host, "web-01",
                "the resolver is asked about the target host"
            );
            Some("deploy".to_string())
        },
        None,
        "web-01",
        22,
    );
    assert_eq!(key, "ssh://deploy@web-01:22");
    assert_ne!(
        key,
        legacy_checkpoint_host_key("web-01", 22),
        "a resolved bare target must not collide with an explicit root@host"
    );
}

/// A resolver that cannot answer leaves the old fabrication rather than
/// inventing a second one, so the worst case is the behaviour that shipped
/// before, which the fleet collision refusal already guards.
#[test]
fn an_unanswerable_resolver_falls_back_to_the_legacy_key() {
    let key = checkpoint_host_key_with(|_| None, None, "web-01", 22);
    assert_eq!(key, legacy_checkpoint_host_key("web-01", 22));
}

/// The `user` line is parsed out of what ssh really prints, and the answer is
/// the one ssh gave rather than merely some answer.
///
/// A parse checked only against a hand-written fixture proves the fixture, not
/// the format. `ssh -G` opens no connection, so this costs nothing and needs no
/// host to exist. It is skipped rather than failed where ssh is absent, since
/// then the resolver is correct to answer `None`.
///
/// This asked only whether *a* non-empty user came back, which a body replaced
/// by any constant satisfies: the checkpoint key a bare target is filed under
/// could have been a fabrication and nothing would have gone red. The
/// comparison is against a second, independent reading of the same `ssh -G`
/// output, because only an independent reference can fail a constant. Its
/// ceiling is that both readings look for the same prefix, so a wrong prefix
/// would agree with itself; what it does pin is that the value is ssh's.
#[test]
fn resolve_ssh_user_parses_what_ssh_actually_prints() {
    const HOST: &str = "a-host-that-need-not-exist";

    let Ok(output) = std::process::Command::new("ssh")
        .args(["-G", "--", HOST])
        .output()
    else {
        eprintln!("skipping: no ssh on this machine");
        return;
    };
    let printed = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            line.strip_prefix("user ")
                .map(|user| user.trim().to_string())
        })
        .expect("ssh -G always reports an effective user, defaulting to the local one");

    assert_eq!(
        resolve_ssh_user(HOST),
        Some(printed),
        "the resolved user must be the one ssh itself would use for this target, \
         since it becomes the checkpoint key a bare target is filed under"
    );
}

/// The heredoc delimiter must be absent from the body it terminates.
///
/// A delimiter the content already contains ends the heredoc early, so the
/// remote write truncates the file at that line: `write_file` would report
/// success having written part of an sshd_config.
#[test]
fn the_heredoc_delimiter_grows_until_the_content_cannot_contain_it() {
    assert_eq!(
        unique_delimiter("PermitRootLogin no\n"),
        "HARDENER_EOF",
        "content that cannot collide keeps the base delimiter"
    );
    assert_eq!(
        unique_delimiter("# a comment saying HARDENER_EOF\n"),
        "HARDENER_EOFX",
        "one collision grows it by exactly one character"
    );

    let adversarial = "HARDENER_EOF and HARDENER_EOFX\n";
    let delimiter = unique_delimiter(adversarial);
    assert_eq!(
        delimiter, "HARDENER_EOFXX",
        "it keeps growing while the grown form still collides"
    );
    assert!(
        !adversarial.contains(&delimiter),
        "and the invariant that matters is the one the loop exists for: the \
         content must not contain what terminates it"
    );
}

/// A stat line short of its five fields parses to nothing, and saying so is the
/// only safe answer.
///
/// `rsplitn(5, ' ')` yields at most five parts, so a length check written the
/// other way round can never fire and the parse indexes past the end of a short
/// line. The complete line beside it is the control: a guard that refused
/// everything would pass the first two assertions on its own.
#[test]
fn a_stat_line_missing_fields_parses_to_nothing() {
    assert!(
        parse_stat_fields("regular file 640").is_none(),
        "three fields cannot fill five, and a partial parse would invent a mode"
    );
    assert!(
        parse_stat_fields("").is_none(),
        "an empty line is the shape a failed `stat` leaves behind"
    );
    assert!(
        parse_stat_fields("regular file 640 1234 0 42").is_some(),
        "the control: a complete line still parses"
    );
}

/// `is_file` must mean over ssh what it means locally.
///
/// `LocalExecutor` answers from `std::fs::Metadata::is_file`, which is false for
/// a device. This reader used to accept any `%F` containing the word `file`,
/// which made `character special file` and `block special file` report as files
/// here and not there, and `hardener-state/src/manager.rs:598` gates checkpoint
/// capture on this field, so the two executors disagreed about the same path.
/// The special-file rows are the ones that were wrong; the rest are the control
/// that stops the fix over-correcting into "nothing is a file".
#[test]
fn only_a_regular_file_reads_as_a_file_over_ssh() {
    for (stat_line, is_file, is_dir) in [
        ("regular file 640 1234 0 42", true, false),
        ("regular empty file 0 0 0 0", true, false),
        ("directory 755 4096 0 0", false, true),
        ("character special file 660 0 0 5", false, false),
        ("block special file 660 0 0 5", false, false),
        ("symbolic link 777 7 0 0", false, false),
    ] {
        let meta = parse_stat_fields(stat_line).expect("every line here is complete");
        assert_eq!(
            meta.is_file, is_file,
            "is_file for `{stat_line}` must match what LocalExecutor reports \
             for the same path, since checkpoint capture gates on it"
        );
        assert_eq!(meta.is_dir, is_dir, "is_dir for `{stat_line}`");
        assert_ne!(
            meta.mode, 0,
            "and every existing path keeps a non-zero mode, or rollback reads \
             `{stat_line}` as never having existed and removes it"
        );
    }
}

/// The file-type bit survives a mode field that already carries it.
///
/// `mode` is built as `type_bit | permission_bits`, and the OR is load
/// bearing rather than cosmetic: checkpoint rollback reads `mode == 0` as
/// "did not exist at capture" and removes the path, so any existing file must
/// come back with a non-zero mode.
///
/// Normally the two operands are disjoint, `%a` reaching `0o7777` and the type
/// bit sitting at `0o100000`, which is why an XOR here looks harmless and
/// survived a mutation pass. They stop being disjoint the moment the mode
/// field parses to something overlapping the type bits, and this parser reads
/// text from the remote host rather than a trusted structure. Under XOR the
/// bits cancel, `mode` becomes 0, and a rollback deletes a file that exists.
///
/// `0o100000` is not what `stat -c %a` emits. That is the point: the contract
/// is "an existing path never reports mode 0", and it has to hold for whatever
/// arrives, not only for well-formed output.
#[test]
fn the_type_bit_is_never_cancelled_by_the_permission_field() {
    let meta = parse_stat_fields("regular file 100000 1234 0 42")
        .expect("five fields parse, whatever the mode field holds");

    assert_ne!(
        meta.mode, 0,
        "an existing path reporting mode 0 is read by checkpoint rollback as \
         absent at capture, and the path is then deleted"
    );
    assert_eq!(
        meta.mode & 0o170000,
        0o100000,
        "the regular-file type bit must be set, not cancelled: combining the \
         type bit with the permission field must add bits rather than toggle \
         them"
    );
}
