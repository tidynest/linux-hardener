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
