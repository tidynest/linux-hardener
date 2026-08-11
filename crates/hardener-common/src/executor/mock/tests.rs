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

/// Every builder keeps what the builders before it registered.
///
/// Seven of them survived being replaced by `Default::default()`, which
/// discards both the registration being made and everything set up before it.
/// The triage rule calls a mock a note rather than a bug, and that is the wrong
/// reading here: **a fixture decides what the tests above it can detect.** A
/// builder that quietly returns a blank executor leaves every test using it
/// asking its questions of an empty host, and a suite whose fixtures cannot be
/// trusted proves nothing about the code it covers.
///
/// One chain exercises all seven, because the failure is precisely that a later
/// call throws away an earlier one, and a chain is the only shape that can show
/// it.
#[tokio::test]
async fn a_builder_chain_keeps_every_registration_made_before_it() {
    let ok = CommandOutput {
        stdout: "ok".to_string(),
        stderr: String::new(),
        exit_code: 0,
    };

    let executor = MockExecutor::new()
        .with_file("/etc/ssh/sshd_config", "PermitRootLogin no\n")
        .with_file("/etc/removed.conf", "gone\n")
        .without_file("/etc/removed.conf")
        .with_directory("/etc/ssh/sshd_config.d")
        .with_read_dir_permission_denied("/etc/unreadable")
        .with_command("systemctl", &["is-enabled", "sshd"], ok.clone())
        .with_command_program("sshd", ok.clone())
        .with_command_sequence("nft", &["list", "ruleset"], vec![ok.clone()])
        .with_command_exists("nft", true);

    assert_eq!(
        executor
            .read_file(Path::new("/etc/ssh/sshd_config"))
            .await
            .expect("the first registration survives every builder after it")
            .trim(),
        "PermitRootLogin no",
        "a file registered before eight further builder calls is still there"
    );
    assert_eq!(
        executor
            .read_file_optional(Path::new("/etc/removed.conf"))
            .await
            .expect("an absent path is an answer"),
        None,
        "and one explicitly removed is still absent"
    );
    assert!(
        executor
            .path_exists(Path::new("/etc/ssh/sshd_config.d"))
            .await
            .expect("the directory is registered"),
        "the directory registration survives"
    );
    assert!(
        executor
            .read_dir(Path::new("/etc/unreadable"))
            .await
            .is_err(),
        "so does the unlistable directory, which is the only way a caller's \
         permission-denied branch is reachable at all"
    );
    assert!(
        executor
            .execute_command("systemctl", &["is-enabled", "sshd"])
            .await
            .is_ok(),
        "the exact-argument command registration survives"
    );
    assert!(
        executor.execute_command("sshd", &["-t"]).await.is_ok(),
        "and the whole-program one"
    );
    assert!(
        executor
            .execute_command("nft", &["list", "ruleset"])
            .await
            .is_ok(),
        "and the sequenced one"
    );
    assert!(
        executor
            .command_exists("nft")
            .await
            .expect("an explicit registration answers"),
        "and the explicit command-exists registration"
    );
}

/// `command_exists` answers what it was told, in both directions and by both
/// routes.
///
/// It survived being replaced by `true` and by `false`, and its registration
/// lookup survived `==` becoming `!=`. Every plugin gates its probes on this,
/// so a fixture answering `true` for everything hides a missing-tool branch
/// that a real host takes, and one answering `false` for everything makes every
/// plugin skip its work while the suite reports success. **A mock that can
/// return either answer unnoticed cannot fail**, which is the whole reason
/// these are worth killing rather than noting.
#[tokio::test]
async fn command_exists_answers_both_ways_and_by_both_routes() {
    let executor = MockExecutor::new()
        .with_command_exists("nft", true)
        .with_command_exists("iptables", false)
        .with_command(
            "systemctl",
            &["is-enabled", "sshd"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        );

    assert!(
        executor
            .command_exists("nft")
            .await
            .expect("registered true"),
        "an explicit `true` must come back true"
    );
    assert!(
        !executor
            .command_exists("iptables")
            .await
            .expect("registered false"),
        "and an explicit `false` false, which is the half a fixture defaulting \
         to present can never say"
    );
    assert!(
        executor
            .command_exists("systemctl")
            .await
            .expect("inferred from a registered command"),
        "a program with a registered command exists by that route alone"
    );
    // Worth recording rather than fixing here: the inference reads `commands`
    // only, so a program registered through `with_command_program` is *not*
    // inferred to exist. The two registrations answer differently, and a
    // fixture using the whole-program form has to add `with_command_exists`
    // beside it or its subject will skip the work.
    assert!(
        !executor
            .command_exists("firewall-cmd")
            .await
            .expect("nothing registered is an answer, not an error"),
        "and one registered nowhere does not: the `==` matching the program \
         name is what tells these apart"
    );
}

/// The operation log records what happened, and clearing it empties it.
///
/// `log` survived returning a default, `clear_log` survived doing nothing, and
/// `files` survived three constant bodies. Every one of them is an assertion
/// surface: a test that checks "the plugin wrote this file" against a log that
/// is always empty passes only because it was written to expect nothing, and a
/// `clear_log` that does nothing makes a two-phase test read the first phase's
/// writes as the second's.
#[tokio::test]
async fn the_operation_log_records_what_happened_and_clears_on_request() {
    let executor = MockExecutor::new().with_file("/etc/ssh/sshd_config", "PermitRootLogin no\n");

    executor
        .read_file(Path::new("/etc/ssh/sshd_config"))
        .await
        .expect("read the registered file");
    executor
        .write_file(Path::new("/etc/ssh/sshd_config"), "PermitRootLogin yes\n")
        .await
        .expect("write it back");

    let log = executor.log();
    assert_eq!(
        log.files_read,
        vec![PathBuf::from("/etc/ssh/sshd_config")],
        "the read must be recorded, or every assertion made against this log \
         passes by finding nothing"
    );
    assert_eq!(
        log.files_written,
        vec![(
            PathBuf::from("/etc/ssh/sshd_config"),
            "PermitRootLogin yes\n".to_string()
        )],
        "and so must the write, with what was written"
    );

    assert_eq!(
        executor
            .files()
            .get(Path::new("/etc/ssh/sshd_config"))
            .map(String::as_str),
        Some("PermitRootLogin yes\n"),
        "the virtual filesystem must hold what was written, not the content it \
         started with: a `write_file` that did nothing would leave the original"
    );

    executor.clear_log();
    let cleared = executor.log();
    assert!(
        cleared.files_read.is_empty() && cleared.files_written.is_empty(),
        "clearing must actually empty it, or a second phase reads the first \
         phase's operations as its own: {cleared:?}"
    );
}

/// `read_file_optional` tells content from absence.
///
/// It survived `Ok(None)`, `Ok(Some(String::new()))` and `Ok(Some("xyzzy"))`.
/// The distinction it draws is the one this project has already paid for
/// twice: a present file and an absent one restore differently, and a fixture
/// that cannot tell them apart cannot test the code that must.
#[tokio::test]
async fn read_file_optional_tells_content_from_absence() {
    let executor = MockExecutor::new().with_file("/etc/login.defs", "UMASK 077\n");

    assert_eq!(
        executor
            .read_file_optional(Path::new("/etc/login.defs"))
            .await
            .expect("a registered file"),
        Some("UMASK 077\n".to_string()),
        "a registered file comes back with exactly its content"
    );
    assert_eq!(
        executor
            .read_file_optional(Path::new("/etc/nothing-here"))
            .await
            .expect("an unregistered path is an answer, not an error"),
        None,
        "and an unregistered one is a positive absence"
    );
}
