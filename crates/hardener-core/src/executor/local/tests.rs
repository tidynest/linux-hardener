#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`local`](super).
//!
//! Split out of `executor/local.rs`. This file sits in the `executor/local/`
//! directory beside it, which the 2018 path rules allow with no `mod.rs` and
//! no `#[path]`, so `super` still resolves to `crate::executor::local` and
//! every import carried across unchanged, private items included.

use super::*;

/// A symlink must be reported as one, with its target, and a regular file
/// must be reported as positively not one.
///
/// Both halves matter. Without the first, capture stores the content the
/// link points at and a rollback writes that content back through the link,
/// which is how a checkpoint of `/etc/systemd/system` came to hold the
/// contents of packaged unit files. Without the second, every ordinary file
/// would be treated as a link and never restored at all.
#[tokio::test]
async fn read_link_tells_a_symlink_from_a_regular_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("real.conf");
    let link = dir.path().join("link.conf");
    std::fs::write(&target, "content\n").expect("write");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    let executor = LocalExecutor::new();

    assert_eq!(
        executor
            .read_link(&link)
            .await
            .expect("read_link on a link"),
        Some(target.to_string_lossy().into_owned()),
        "a symlink must report the path it points at"
    );
    assert_eq!(
        executor
            .read_link(&target)
            .await
            .expect("read_link on a file"),
        None,
        "a regular file must be reported as positively not a symlink"
    );
}

#[test]
fn kernel_interface_path_matches_proc_and_sys() {
    assert!(is_kernel_interface_path(Path::new(
        "/proc/sys/net/ipv4/ip_forward"
    )));
    assert!(is_kernel_interface_path(Path::new(
        "/sys/kernel/mm/transparent_hugepage/enabled"
    )));
}

#[test]
fn kernel_interface_path_rejects_ordinary_and_lookalike_paths() {
    assert!(!is_kernel_interface_path(Path::new(
        "/etc/sysctl.d/99-hardening.conf"
    )));
    assert!(!is_kernel_interface_path(Path::new("/etc/procmail.conf")));
    assert!(!is_kernel_interface_path(Path::new("/etc/sysprep.conf")));
    assert!(!is_kernel_interface_path(Path::new(
        "/home/user/proc/notes"
    )));
    assert!(!is_kernel_interface_path(Path::new("relative/proc/path")));
}

#[tokio::test]
async fn write_file_to_ordinary_path_still_round_trips_atomically() {
    // A real /proc write needs root and cannot be exercised here, so
    // this test instead pins down the non-kernel-interface branch:
    // ordinary paths (the vast majority of writes, e.g. /etc/sysctl.d
    // drop-ins) must keep going through update_file_atomically after
    // the dispatch is introduced, preserving existing permissions and
    // surviving a mid-write crash without truncating the target.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("99-hardening.conf");
    std::fs::write(&path, "old\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let exec = LocalExecutor::new();
    exec.write_file(&path, "new\n").await.unwrap();

    assert_eq!(std::fs::read_to_string(&path).unwrap(), "new\n");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644,
        "atomic write must preserve original permissions"
    );
}

#[tokio::test]
async fn local_read_dir_lists_immediate_children_only() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.conf"), "x").unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    std::fs::write(dir.path().join("sub/b.conf"), "y").unwrap();
    let exec = LocalExecutor::new();
    let mut got: Vec<String> = exec
        .read_dir(dir.path())
        .await
        .unwrap()
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    got.sort();
    assert_eq!(got, vec!["a.conf", "sub"]);
}

#[tokio::test]
async fn local_read_dir_missing_path_is_empty_not_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist");
    let got = LocalExecutor::new().read_dir(&missing).await.unwrap();
    assert!(
        got.is_empty(),
        "missing directory must yield an empty vec, not an error"
    );
}

#[tokio::test]
async fn metadata_of_zero_perm_file_is_not_confused_with_missing() {
    // Checkpoint rollback treats a stored `mode` of 0 as the sentinel for
    // "path did not exist at capture" (→ the path is removed on restore). An
    // existing file with permissions 0000 (e.g. Arch's /etc/shadow) must
    // therefore never report mode 0, or a rollback would delete it.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zero.conf");
    std::fs::write(&path, "x").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

    let meta = LocalExecutor::new().file_metadata(&path).await.unwrap();

    assert!(meta.exists);
    assert_ne!(
        meta.mode, 0,
        "existing 0000-perm file must not report mode 0 (collides with the \
             'did not exist' sentinel checkpoint rollback relies on)"
    );
    assert_eq!(
        meta.mode & 0o777,
        0,
        "permission bits must still read as 0000"
    );
}

/// Guards the probe string against a real shell rather than a fake
/// executor. It passes against the shipped `which` probe too, because this
/// host has `which`; what it adds is proof that the replacement asks a
/// real shell the same question and gets the same three answers.
#[tokio::test]
async fn command_exists_answers_against_a_real_shell() {
    let executor = LocalExecutor::new();

    assert!(
        executor.command_exists("sh").await.unwrap(),
        "sh is spawnable here or nothing in this suite could have run"
    );
    assert!(
        !executor
            .command_exists("__no_such_program__")
            .await
            .unwrap(),
        "an absent program is an answer, not an error"
    );
    assert!(
        !executor.command_exists("cd").await.unwrap(),
        "`cd` is a shell builtin with no binary behind it: execute_command \
             could not spawn it, so command_exists must not claim it is there"
    );
}

/// The probe against real coreutils, which is the only witness for the script
/// itself: every assertion in `hardener-common` states what the parser does
/// with an answer, and a fixture cannot say what `readlink` does.
///
/// Every case here is correct when the runner is root, which the cross-distro
/// containers are. A `chmod 000` fixture would express the `EACCES` arm
/// directly and go vacuous under root, so that arm is reached through the
/// parent gate instead: a parent that cannot be resolved is refused whether the
/// reason is absence or permission, and the two arrive identically.
#[tokio::test]
async fn the_writer_privilege_probe_reads_a_real_filesystem() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("real.conf");
    let link = dir.path().join("link.conf");
    let dangling = dir.path().join("dangling.conf");
    let orphan = dir.path().join("gone").join("child.conf");
    std::fs::write(&target, "content\n").expect("write");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    std::os::unix::fs::symlink(dir.path().join("nothing"), &dangling).expect("symlink");

    let executor = LocalExecutor::new();

    assert_eq!(
        executor
            .link_target_as_writer(&target)
            .await
            .expect("a regular file is an answer"),
        None,
        "a regular file whose parent resolves is positively not a symlink"
    );
    assert_eq!(
        executor
            .link_target_as_writer(&link)
            .await
            .expect("a link is an answer"),
        Some(target.canonicalize().expect("canonicalize the target")),
        "a link reports where it finally lands, every component resolved"
    );
    assert!(
        executor.link_target_as_writer(&dangling).await.is_err(),
        "a link pointing at nothing has no destination to judge, so it refuses"
    );
    assert!(
        executor.link_target_as_writer(&orphan).await.is_err(),
        "a path whose parent does not resolve cannot be probed, so it refuses: \
         this is the arm that answers 'not a symlink' before the fix"
    );
}

/// The path shapes that defeated the probe during review, pinned against a real
/// filesystem rather than against a fixture that could only restate the claim.
///
/// Only the trailing-slash assertions below witness the script text itself.
/// Nothing in `hardener-common` runs a real shell, so its fixtures can only
/// state what `test -h` and `readlink -e` are claimed to do against a
/// directory symlink and a file symlink, never prove it against real
/// coreutils; the loop over `dir_link` and the assertion against `file_link`
/// do. `normalise_probe_path` strips the trailing slash in Rust before either
/// spelling in the loop reaches the script, so both spellings there drive the
/// identical script invocation, and what the pair proves is that the
/// stripping changes no answer.
///
/// The dot-segment assertions witness something else entirely.
/// `normalise_probe_path` refuses `dir_link.join(".")` and `dir_link.join("..")`
/// in Rust before any command is built, so no mutation to `LINK_PROBE_SCRIPT`
/// can ever turn them red. What they prove instead is that the refusal reaches
/// a caller through the real `LocalExecutor`, which the pure unit test on
/// `normalise_probe_path` in `hardener-common` cannot show: that test calls
/// the function directly and never touches an executor at all.
///
/// A trailing slash forces the kernel to resolve the terminal component
/// before the `lstat` behind `test -h`, which reads a symlink as `NOTLINK`.
/// That is the **admitting** answer, and a write to such a path lands
/// somewhere the gate never judged.
#[tokio::test]
async fn the_probe_is_not_defeated_by_a_trailing_slash_or_dot_segment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target_dir = dir.path().join("realdir");
    let target_file = target_dir.join("child.conf");
    std::fs::create_dir(&target_dir).expect("create realdir");
    std::fs::write(&target_file, "content\n").expect("write");

    let dir_link = dir.path().join("linkdir");
    let file_link = dir.path().join("filelink");
    std::os::unix::fs::symlink(&target_dir, &dir_link).expect("symlink dir");
    std::os::unix::fs::symlink(&target_file, &file_link).expect("symlink file");

    let executor = LocalExecutor::new();
    let resolved_dir = target_dir.canonicalize().expect("canonicalize realdir");

    for spelling in [dir_link.clone(), dir_link.join("")] {
        assert_eq!(
            executor
                .link_target_as_writer(&spelling)
                .await
                .expect("a link is an answer"),
            Some(resolved_dir.clone()),
            "a trailing slash must not turn a symlink into the admitting \
             'not a symlink' answer: {}",
            spelling.display()
        );
    }

    // A trailing slash on a link to a regular file does not resolve at all, and
    // answered NOTLINK before the normalisation landed.
    assert_eq!(
        executor
            .link_target_as_writer(&file_link.join(""))
            .await
            .expect("a link is an answer"),
        Some(target_file.canonicalize().expect("canonicalize child")),
        "a link to a regular file must answer the same with a trailing slash"
    );

    // A dot segment has no final named component for the gate to be scoped to,
    // so it refuses rather than guessing. Resolving it by name would disagree
    // with the kernel whenever the component before it is a link.
    for shape in [dir_link.join("."), dir_link.join("..")] {
        assert!(
            executor.link_target_as_writer(&shape).await.is_err(),
            "a trailing dot segment must refuse rather than admit: {}",
            shape.display()
        );
    }

    // The control, and it is what stops the two assertions above being
    // satisfied by a probe that refuses everything: an ordinary dotfile is not
    // a dot segment and must still be answered.
    let dotfile = dir.path().join(".hidden.conf");
    std::fs::write(&dotfile, "content\n").expect("write dotfile");
    assert_eq!(
        executor
            .link_target_as_writer(&dotfile)
            .await
            .expect("a dotfile is an answer"),
        None,
        "an ordinary dotfile must be answered, or the refusal above proves nothing"
    );
}

/// The argv claim behind `LINK_PROBE_SCRIPT`'s positional-argument design,
/// proved against a real shell rather than only asserted in that doc comment:
/// a path holding a space and a semicolon is one argv entry, not shell text
/// that could end the intended command and start another.
///
/// The symlink's own name also carries a leading dash, the shape `--` ahead
/// of the path in the script's `readlink` and `test` calls exists to guard
/// against. That guard is not what this assertion exercises: every path
/// reaching the probe here is absolute, built from a tempdir, so the dash
/// sits on the final named component and never on the first character of the
/// `$1` token itself, which is the one character an option parser looks at.
/// What this assertion does prove is that a name shaped like an option is
/// still answered correctly end to end; it is not proof that `--` is
/// load-bearing on this call path.
#[tokio::test]
async fn a_dangerous_name_never_reaches_the_shell_as_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("real.conf");
    std::fs::write(&target, "content\n").expect("write target");

    let plain = dir.path().join("a file; touch pwned.conf");
    std::fs::write(&plain, "content\n").expect("write plain");

    let link = dir.path().join("-dashed name.conf");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    let executor = LocalExecutor::new();

    assert_eq!(
        executor
            .link_target_as_writer(&plain)
            .await
            .expect("a regular file with a dangerous name is still an answer"),
        None,
        "a name holding a space and a semicolon must not stop the probe \
         reporting NOTLINK for an ordinary file"
    );
    assert_eq!(
        executor
            .link_target_as_writer(&link)
            .await
            .expect("a symlink with a leading dash is still an answer"),
        Some(target.canonicalize().expect("canonicalize the target")),
        "a name shaped like an option must still be answered correctly"
    );
    assert!(
        !dir.path().join("pwned.conf").exists(),
        "a pwned.conf file appearing here would mean the semicolon in the \
         file's name reached the shell as text instead of arriving as one \
         opaque argv entry"
    );
    assert!(
        !dir.path().join("pwned").exists(),
        "a pwned file appearing here would mean the semicolon in the file's \
         name reached the shell as text instead of arriving as one opaque \
         argv entry"
    );
}

/// A symlinked directory component is resolved, not flattened by name.
///
/// `<dir>/dlink/../victim` is `<dir>/victim` as a string and
/// `<outside>/victim` on the filesystem, and the difference is the whole
/// reason the probe asks `readlink -e` rather than following one hop.
#[tokio::test]
async fn the_probe_resolves_a_symlinked_directory_component() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside tempdir");
    std::fs::create_dir(outside.path().join("sub")).expect("create sub");
    let victim = outside.path().join("victim");
    std::fs::write(&victim, "not ours\n").expect("write victim");

    let dlink = dir.path().join("dlink");
    std::os::unix::fs::symlink(outside.path().join("sub"), &dlink).expect("symlink dir");
    let followed = dir.path().join("followed.conf");
    std::os::unix::fs::symlink(dir.path().join("dlink/../victim"), &followed).expect("symlink");

    let executor = LocalExecutor::new();

    assert_eq!(
        executor
            .link_target_as_writer(&followed)
            .await
            .expect("the link resolves"),
        Some(victim.canonicalize().expect("canonicalize the victim")),
        "the destination is the one the kernel reaches, not the one string \
         surgery predicts"
    );
}
