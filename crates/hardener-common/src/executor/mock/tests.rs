#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`mock`](super).
//!
//! Split out of `executor/mock.rs`. This file sits in the `executor/mock/`
//! directory beside it, which the 2018 path rules allow with no `mod.rs` and
//! no `#[path]`, so `super` still resolves to `crate::executor::mock` and
//! every import carried across unchanged, private items included.

/// The mock answers `read_link` from its own registry, and an unregistered
/// path is positively not a symlink.
///
/// The second half is what lets every fixture written before symlinks existed
/// go on describing the same host: the inherited body shells out to
/// `readlink`, which no fixture registers, so it would report "could not
/// determine" for paths the mock knows exactly.
#[tokio::test]
async fn read_link_answers_from_the_registry_and_defaults_to_not_a_symlink() {
    let executor = MockExecutor::new()
        .with_file("/etc/plain.conf", "x\n")
        .with_symlink("/etc/link.conf", "/usr/etc/plain.conf");

    assert_eq!(
        executor
            .read_link(Path::new("/etc/link.conf"))
            .await
            .expect("registered link"),
        Some("/usr/etc/plain.conf".to_string())
    );
    assert_eq!(
        executor
            .read_link(Path::new("/etc/plain.conf"))
            .await
            .expect("registered file"),
        None,
        "a path with no registered link must read as not a symlink"
    );
}
use super::*;

#[tokio::test]
async fn mock_read_dir_returns_seeded_children() {
    let exec = MockExecutor::new()
        .with_directory("/etc/d")
        .with_file("/etc/d/a", "1")
        .with_file("/etc/d/b", "2")
        .with_file("/etc/other", "3");
    let mut got: Vec<String> = exec
        .read_dir(std::path::Path::new("/etc/d"))
        .await
        .unwrap()
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    got.sort();
    assert_eq!(got, vec!["/etc/d/a", "/etc/d/b"]);
}

#[tokio::test]
async fn mock_read_dir_missing_path_is_empty() {
    let got = MockExecutor::new()
        .read_dir(std::path::Path::new("/no/such/dir"))
        .await
        .unwrap();
    assert!(got.is_empty());
}

#[tokio::test]
async fn read_permission_denied_surfaces_io_kind() {
    let mock = MockExecutor::new().with_read_permission_denied("/etc/security/pwquality.conf");
    let err = mock
        .read_file(std::path::Path::new("/etc/security/pwquality.conf"))
        .await
        .unwrap_err();
    assert!(crate::error::is_permission_denied(&err));
}

#[tokio::test]
async fn a_read_denied_path_still_reports_as_present() {
    // A root-only file is present and refuses to open. No executor
    // produces "denied, and also absent": LocalExecutor::path_exists
    // confirms absence only on NotFound and returns an error for a denied
    // probe. A mock that reported such a path as absent is gentler than
    // reality, so a caller that consults the probe before falling back
    // takes a branch it could never take on a real host.
    let mock = MockExecutor::new().with_read_permission_denied("/etc/ssh/sshd_config");
    assert!(
        mock.path_exists(std::path::Path::new("/etc/ssh/sshd_config"))
            .await
            .expect("the probe itself succeeds"),
        "a file whose read is denied is still there"
    );
}

#[tokio::test]
async fn a_read_denied_path_keeps_metadata_it_was_already_given() {
    // Denial must not overwrite what a fixture stated deliberately, so
    // ordering in the builder chain cannot change the answer.
    let mock = MockExecutor::new()
        .with_read_permission_denied("/etc/shadow")
        .with_file_metadata(
            "/etc/shadow",
            "root:x:",
            FileMetadata {
                exists: true,
                is_file: true,
                is_dir: false,
                mode: 0o600,
                size: 7,
                uid: 0,
                gid: 42,
            },
        );
    let metadata = mock
        .file_metadata(std::path::Path::new("/etc/shadow"))
        .await
        .expect("metadata reads");
    assert_eq!(metadata.mode, 0o600, "the stated mode must survive");
    assert_eq!(metadata.gid, 42, "the stated ownership must survive");
}

#[tokio::test]
async fn a_read_denied_path_can_still_be_declared_absent_explicitly() {
    // The escape hatch stays open: an explicit path_exists override wins,
    // so a test that genuinely wants the impossible state can say so.
    let mock = MockExecutor::new()
        .with_read_permission_denied("/etc/nope")
        .with_path_exists("/etc/nope", false);
    assert!(
        !mock
            .path_exists(std::path::Path::new("/etc/nope"))
            .await
            .expect("the probe itself succeeds")
    );
}

#[tokio::test]
async fn metadata_error_is_not_reported_as_absence() {
    let mock = MockExecutor::new().with_metadata_error("/etc/shadow");
    mock.file_metadata(std::path::Path::new("/etc/shadow"))
        .await
        .expect_err("an unverifiable path must error, never report exists: false");
}

#[tokio::test]
async fn path_exists_can_disagree_with_metadata() {
    // The real divergence on an incompatible host: the path is there, but
    // its metadata cannot be read. A shared flag cannot express this.
    let mock = MockExecutor::new()
        .with_metadata_error("/etc/shadow")
        .with_path_exists("/etc/shadow", true);
    assert!(
        mock.path_exists(std::path::Path::new("/etc/shadow"))
            .await
            .expect("path_exists does not fail here")
    );
    mock.file_metadata(std::path::Path::new("/etc/shadow"))
        .await
        .expect_err("metadata is still unreadable");
}

#[tokio::test]
async fn path_exists_error_is_not_reported_as_absence() {
    let mock = MockExecutor::new().with_path_exists_error("/etc/passwd");
    mock.path_exists(std::path::Path::new("/etc/passwd"))
        .await
        .expect_err("an unverifiable path must error, never report exists: false");
}

/// The mock owns its filesystem, so it must answer the writer-privilege probe
/// from its registries rather than by running a script it registers no command
/// for. Three outcomes, and a fixture has to be able to state all three.
#[tokio::test]
async fn the_writer_privilege_probe_answers_from_the_registries() {
    let exec = MockExecutor::new()
        .with_symlink("/etc/link.conf", "/usr/etc/plain.conf")
        .with_unprobeable("/root/.ssh/authorized_keys");

    assert_eq!(
        exec.link_target_as_writer(Path::new("/etc/link.conf"))
            .await
            .expect("a registered link is an answer"),
        Some(PathBuf::from("/usr/etc/plain.conf")),
        "a registered link reports its target"
    );
    assert_eq!(
        exec.link_target_as_writer(Path::new("/etc/plain.conf"))
            .await
            .expect("an unregistered path is an answer"),
        None,
        "a path with no registered link is positively not a symlink, which is \
         what keeps every fixture written before symlinks existed meaningful"
    );
    assert!(
        exec.link_target_as_writer(Path::new("/root/.ssh/authorized_keys"))
            .await
            .is_err(),
        "a path a fixture calls unprobeable must fail closed, so the guard's \
         refusing arm is reachable at the caller"
    );
}
