#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`manager`].
//!
//! Split out of `manager.rs`. This file sits in the `manager/` directory
//! beside it, so `super` still resolves to `crate::manager` and every
//! import carried across unchanged, private items included.

use super::*;
use hardener_common::executor::MockExecutor;

#[test]
fn default_prefixes_cover_account_database_paths() {
    // The permissions plugin checkpoints these (CIS 6.1.2-6.1.5). Rollback's
    // Phase-1 allowlist matches via `starts_with`, so an uncovered path is
    // refused and skipped rather than restored, and the rollback reports
    // failure. It no longer abandons the other files, but a declared path
    // silently not coming back is still the wrong outcome.
    for path in ["/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"] {
        assert!(
            DEFAULT_ROLLBACK_PREFIXES
                .iter()
                .any(|p| path.starts_with(p)),
            "{path} not covered by DEFAULT_ROLLBACK_PREFIXES (rollback would abort)"
        );
    }
}

#[test]
fn default_prefixes_cover_the_systemd_paths_the_services_plugin_checkpoints() {
    // The services plugin checkpoints /etc/systemd/system before disabling
    // or masking a unit, so an uncovered path here would be skipped and the
    // unit never restored. Phase 1 used to abandon the entire rollback over
    // one such path; it now skips it and restores the rest, which makes this
    // check about whether the plugin's own writes come back rather than about
    // whether anything comes back at all.
    let path = "/etc/systemd/system/multi-user.target.wants/example.service";
    assert!(
        DEFAULT_ROLLBACK_PREFIXES
            .iter()
            .any(|p| path.starts_with(p)),
        "{path} not covered by DEFAULT_ROLLBACK_PREFIXES (rollback would abort)"
    );
}

#[test]
fn default_prefixes_exclude_package_owned_unit_directories() {
    // Nothing this tool does writes to the packaged unit directory, so
    // restoring into it could only overwrite a distribution's unit files
    // with copies captured before a package update.
    for path in ["/usr/lib/systemd/system/sshd.service", "/usr/bin/systemctl"] {
        assert!(
            !DEFAULT_ROLLBACK_PREFIXES
                .iter()
                .any(|p| path.starts_with(p)),
            "{path} must stay outside the rollback allowlist"
        );
    }
}

#[tokio::test]
async fn rollback_restores_zero_perm_account_file_instead_of_removing_it() {
    use hardener_common::executor::{CommandOutput, FileMetadata};

    // End-to-end guard for the cross-distro regression (permissions
    // apply→rollback exit 1 + silent /etc/shadow deletion on Arch). Drives the
    // public rollback() API and proves BOTH halves of the fix together:
    //   1. /etc/shadow is in the production allowlist → Phase-1 does not abort.
    //   2. A file that existed at capture with perms 0000 is stored with a
    //      non-zero mode (S_IFREG type bit, as the fixed LocalExecutor now
    //      reports it), so restore re-applies permissions rather than reading
    //      mode 0 as "did not exist" and deleting the path.
    let manager = test_manager().await; // production DEFAULT_ROLLBACK_PREFIXES
    let shadow = "/etc/shadow";
    let ok = || CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    let executor = MockExecutor::new()
        .with_file_metadata(
            shadow,
            "",
            FileMetadata {
                exists: true,
                is_file: true,
                is_dir: false,
                mode: 0o100000, // S_IFREG | 0000 perms: what the fixed local executor reports
                size: 0,
                uid: 0,
                gid: 0,
            },
        )
        .with_command("chmod", &["0", shadow], ok())
        .with_command("chown", &["0:0", shadow], ok());

    let cp_id = manager
        .create_checkpoint_metadata_only(&executor, "perm-test", &[Path::new(shadow)])
        .await
        .expect("checkpoint");

    // Returning Ok (not Err) proves the allowlist accepts /etc/shadow.
    let result = manager
        .rollback(&executor, &cp_id)
        .await
        .expect("rollback must not abort on an allow-listed path");

    assert!(
        result.rollback_success,
        "rollback should succeed: {result:?}"
    );
    assert_eq!(result.rollback_files.len(), 1);
    assert_eq!(
        result.rollback_files[0].restore_action,
        FileRestoreAction::PermissionsRestored,
        "an existing 0000-perm file must be permission-restored, never Removed"
    );
    assert!(
        !executor
            .log()
            .commands_executed
            .iter()
            .any(|(program, _)| program == "rm"),
        "rollback must never issue `rm` for a file that existed at capture"
    );
}

#[tokio::test]
async fn rollback_refuses_to_delete_every_undeletable_path_recorded_as_absent() {
    use hardener_common::executor::FileMetadata;

    // A checkpoint written by a version whose stat probe reported an
    // existing file as absent stores it with mode 0, which restore reads
    // as "remove on rollback". Fixing capture cannot disarm rows already
    // on disk, so restore must refuse the deletion outright.
    //
    // Every entry in the list is exercised, not a representative one, so a
    // path added to UNDELETABLE_ROLLBACK_PATHS is covered the moment it is
    // added rather than waiting for someone to remember a new test.
    let manager = test_manager().await;
    let mut exercised = 0usize;

    for path in UNDELETABLE_ROLLBACK_PATHS {
        // No skip for a path that is a symlink on the machine running this.
        // There used to be one, because Phase 1 asked the local filesystem
        // whether these paths were links and could abort the whole rollback
        // over a contributor's own /etc. It asks the executor now, and the
        // executor here is a mock that knows of no symlink at all, so every
        // entry is exercised on every machine. The guard would exempt these
        // rows in any case: a row recorded absent restores by unlinking the
        // path itself, which follows nothing.
        exercised += 1;

        // Capture believes the path is absent: nothing registered on the
        // mock, so file_metadata reports a confirmed absence and the row
        // stores 0.
        let capturing = MockExecutor::new();
        let cp_id = manager
            .create_checkpoint_metadata_only(&capturing, "poisoned", &[Path::new(path)])
            .await
            .unwrap_or_else(|e| panic!("{path}: capture of a confirmed-absent path: {e}"));

        // Rollback then runs against a host that does have the path, which
        // is what an operator upgrading from v1.4.0 actually has.
        let restoring = MockExecutor::new().with_file_metadata(
            path,
            "",
            FileMetadata {
                exists: true,
                is_file: true,
                is_dir: false,
                mode: 0o100644,
                size: 0,
                uid: 0,
                gid: 0,
            },
        );

        let result = manager
            .rollback(&restoring, &cp_id)
            .await
            .unwrap_or_else(|e| panic!("{path}: rollback must run rather than abort: {e}"));

        let restoring_log = restoring.log();
        let deletions: Vec<_> = restoring_log
            .commands_executed
            .iter()
            .filter(|(cmd, args)| cmd == "rm" && args.iter().any(|a| a == path))
            .collect();
        assert!(
            deletions.is_empty(),
            "rollback must never delete {path}, but issued: {deletions:?}"
        );
        assert_eq!(
            result.rollback_files[0].restore_action,
            FileRestoreAction::Skipped,
            "{path}: a refused deletion must be recorded as Skipped"
        );
        assert!(
            !result.rollback_success,
            "{path}: a refused deletion means the checkpoint is untrustworthy and must be reported, not silently swallowed"
        );
    }

    assert!(
        exercised > 0,
        "every UNDELETABLE_ROLLBACK_PATHS entry was a symlink on this machine; the guard was never exercised"
    );
}

/// The capture-then-rollback shape every apply that creates a file produces:
/// the checkpoint records `path` truthfully absent, and by rollback time the
/// host has it. Shared by the paths that exercise it so they cannot drift
/// apart; each caller keeps its own assertions, because what the removal
/// means differs per path even though the mechanism does not.
async fn rollback_over_a_path_the_apply_created(path: &str) -> (RollbackResult, MockExecutor) {
    use hardener_common::executor::FileMetadata;

    let manager = test_manager().await;

    let capturing = MockExecutor::new();
    let cp_id = manager
        .create_checkpoint_metadata_only(&capturing, "pre-apply", &[Path::new(path)])
        .await
        .expect("capture of a confirmed-absent path must succeed");

    let restoring = MockExecutor::new()
        .with_file_metadata(
            path,
            "",
            FileMetadata {
                exists: true,
                is_file: true,
                is_dir: false,
                mode: 0o100644,
                size: 0,
                uid: 0,
                gid: 0,
            },
        )
        .with_command("rm", &["-f", path], ok_output());

    let result = manager
        .rollback(&restoring, &cp_id)
        .await
        .expect("rollback must run rather than abort");

    (result, restoring)
}

#[tokio::test]
async fn rollback_still_deletes_a_path_an_apply_can_create() {
    // The counterpart to the test above: the refusal is keyed on list
    // membership, so a path an apply CAN create must still be removed. The
    // kernel plugin writes its own /etc/sysctl.d drop-in, so a checkpoint
    // taken before that apply records the file as absent truthfully, and
    // deleting it is what the operator asked for. Protecting it instead
    // would leave the hardening in place after a rollback.
    let drop_in = "/etc/sysctl.d/99-hardener.conf";
    assert!(
        !UNDELETABLE_ROLLBACK_PATHS.contains(&drop_in),
        "{drop_in} is created by the kernel plugin's apply, so it must stay deletable"
    );

    let (result, restoring) = rollback_over_a_path_the_apply_created(drop_in).await;

    let restoring_log = restoring.log();
    assert!(
        restoring_log
            .commands_executed
            .iter()
            .any(|(cmd, args)| cmd == "rm" && args.iter().any(|a| a == drop_in)),
        "a file the apply created must still be deleted, but the commands issued were: {:?}",
        restoring_log.commands_executed
    );
    assert_eq!(
        result.rollback_files[0].restore_action,
        FileRestoreAction::Removed,
        "an unprotected path recorded as absent must be Removed"
    );
    assert!(
        result.rollback_success,
        "deleting a path the apply created is an ordinary success: {result:?}"
    );
}

/// The same rule, for the file the firewall plugin's nftables backend renders
/// its whole ruleset into and loads.
///
/// An apply creates `/etc/nftables.conf` on every host that never had one,
/// which is every Fedora and RHEL host (they ship `/etc/sysconfig/nftables.conf`
/// instead) and every host whose firewall was ufw or firewalld. That places it
/// under the membership rule at [`UNDELETABLE_ROLLBACK_PATHS`] rather than
/// under any exemption from it: protecting it would leave the rendered ruleset
/// on disk with `nftables.service` already enabled by the same apply, so the
/// posture the operator rolled back would return at the next boot. An earlier
/// wording added that the plugin's own `reload_after_rollback` would load it
/// straight back in; that route closed when the checkpoint was scoped to the
/// selected backend's own paths, so the next boot is the reason that stands.
///
/// Same precedent as the kernel plugin's sysctl.d drop-in above and the ssh
/// plugin's drop-in, which states the rule in its own checkpoint call.
#[tokio::test]
async fn rollback_deletes_the_nftables_ruleset_an_apply_created() {
    let ruleset = "/etc/nftables.conf";
    assert!(
        !UNDELETABLE_ROLLBACK_PATHS.contains(&ruleset),
        "{ruleset} is created by the firewall plugin's apply, so it must stay deletable"
    );

    let (result, restoring) = rollback_over_a_path_the_apply_created(ruleset).await;

    let restoring_log = restoring.log();
    assert!(
        restoring_log
            .commands_executed
            .iter()
            .any(|(cmd, args)| cmd == "rm" && args.iter().any(|a| a == ruleset)),
        "the rendered ruleset must be deleted, or it returns at the next boot; \
         the commands issued were: {:?}",
        restoring_log.commands_executed
    );
    assert_eq!(
        result.rollback_files[0].restore_action,
        FileRestoreAction::Removed,
        "the ruleset an apply rendered must be Removed, not Skipped"
    );
    assert!(
        result.rollback_success,
        "undoing an nftables apply is an ordinary success, not a refusal: {result:?}"
    );
}

/// A command that ran and refused is not a command that worked.
///
/// `execute_command` returns `Ok` for a process that started and exited
/// non-zero, so a removal blocked by a read-only mount or an unwritable
/// parent directory arrived here as success. Rollback then reported the
/// file removed, `rollback_success` stayed true, and the operator was told
/// the host was back at the checkpoint while the file the apply created was
/// still on disk still doing its job.
#[tokio::test]
async fn a_removal_the_host_refused_is_not_a_successful_rollback() {
    use hardener_common::executor::FileMetadata;

    let manager = test_manager().await;
    let drop_in = "/etc/sysctl.d/99-hardener.conf";

    let capturing = MockExecutor::new();
    let cp_id = manager
        .create_checkpoint_metadata_only(&capturing, "pre-apply", &[Path::new(drop_in)])
        .await
        .expect("capture of a confirmed-absent path must succeed");

    let restoring = MockExecutor::new()
        .with_file_metadata(
            drop_in,
            "",
            FileMetadata {
                exists: true,
                is_file: true,
                is_dir: false,
                mode: 0o100644,
                size: 0,
                uid: 0,
                gid: 0,
            },
        )
        .with_command(
            "rm",
            &["-f", drop_in],
            hardener_common::executor::CommandOutput {
                stdout: String::new(),
                stderr: "rm: cannot remove '/etc/sysctl.d/99-hardener.conf': Read-only \
                         file system"
                    .to_string(),
                exit_code: 1,
            },
        );

    let result = manager
        .rollback(&restoring, &cp_id)
        .await
        .expect("rollback must run rather than abort");

    assert!(
        !result.rollback_success,
        "a file the host refused to remove is still hardening it: {result:?}"
    );
    assert!(
        result.rollback_files[0]
            .restore_error
            .as_deref()
            .is_some_and(|e| e.contains("Read-only file system")),
        "the reason the host gave must reach the operator, got: {:?}",
        result.rollback_files[0].restore_error
    );
}

/// The same conflation on the metadata half of a restore.
///
/// These two are best-effort by design, and the comment above them names
/// the case they are expected to lose: a remote restore by a user who does
/// not own the target. That is precisely a command that runs and is
/// refused, so the one failure the design anticipates was the one it could
/// not see, and a restore that recovered content but no permissions
/// reported itself as complete.
#[tokio::test]
async fn permissions_the_host_refused_to_restore_are_reported() {
    use hardener_common::executor::{CommandOutput, FileMetadata};

    for refused in ["chmod", "chown"] {
        let manager = test_manager().await;
        let path = "/etc/shadow";
        let denied = || CommandOutput {
            stdout: String::new(),
            stderr: "Operation not permitted".to_string(),
            exit_code: 1,
        };

        let executor = MockExecutor::new()
            .with_file_metadata(
                path,
                "",
                FileMetadata {
                    exists: true,
                    is_file: true,
                    is_dir: false,
                    mode: 0o100000,
                    size: 0,
                    uid: 0,
                    gid: 0,
                },
            )
            .with_command(
                "chmod",
                &["0", path],
                if refused == "chmod" {
                    denied()
                } else {
                    ok_output()
                },
            )
            .with_command(
                "chown",
                &["0:0", path],
                if refused == "chown" {
                    denied()
                } else {
                    ok_output()
                },
            );

        let cp_id = manager
            .create_checkpoint_metadata_only(&executor, "perm-test", &[Path::new(path)])
            .await
            .expect("checkpoint");

        let result = manager
            .rollback(&executor, &cp_id)
            .await
            .expect("rollback must not abort on an allow-listed path");

        assert!(
            !result.rollback_success,
            "{refused} was refused, so the mode on {path} is not what the checkpoint \
             recorded: {result:?}"
        );
        assert!(
            result.rollback_files[0]
                .restore_error
                .as_deref()
                .is_some_and(|e| e.contains(refused) && e.contains("Operation not permitted")),
            "the refusal must name the command and the reason, got: {:?}",
            result.rollback_files[0].restore_error
        );
    }
}

#[tokio::test]
async fn rollback_refuses_to_delete_a_critical_path_when_existence_cannot_be_checked() {
    // The existence probe itself can fail, for example an SSH command that
    // dies mid-check. That is neither "confirmed absent" nor "confirmed
    // present": the guard must fail closed rather than guess either way.
    let manager = test_manager().await;
    let passwd = "/etc/passwd";

    let capturing = MockExecutor::new();
    let cp_id = manager
        .create_checkpoint_metadata_only(&capturing, "poisoned", &[Path::new(passwd)])
        .await
        .expect("capture of a confirmed-absent path must succeed");

    let restoring = MockExecutor::new().with_path_exists_error(passwd);

    let result = manager
        .rollback(&restoring, &cp_id)
        .await
        .expect("rollback must run rather than abort");

    let restoring_log = restoring.log();
    let deletions: Vec<_> = restoring_log
        .commands_executed
        .iter()
        .filter(|(cmd, args)| cmd == "rm" && args.iter().any(|a| a == passwd))
        .collect();
    assert!(
        deletions.is_empty(),
        "rollback must never delete {passwd} when its existence cannot be confirmed, but issued: {deletions:?}"
    );
    assert_eq!(
        result.rollback_files[0].restore_action,
        FileRestoreAction::Skipped,
        "an unverifiable path must be recorded as Skipped"
    );
    assert!(
        !result.rollback_success,
        "an unverifiable path means rollback cannot proceed safely and must be reported, not silently swallowed"
    );
}

#[tokio::test]
async fn rollback_succeeds_when_a_protected_path_is_genuinely_absent() {
    // A minimal host with no sudo installed has no /etc/sudoers.d. Capture
    // records that absence correctly, so rollback has nothing to delete and
    // must report an ordinary success. Refusing here would fail every
    // rollback on every host that lacks an optional package.
    let manager = test_manager().await;
    let sudoers_d = "/etc/sudoers.d";

    // Absent at capture and still absent at restore: nothing registered.
    let executor = MockExecutor::new();
    let cp_id = manager
        .create_checkpoint_metadata_only(&executor, "minimal-host", &[Path::new(sudoers_d)])
        .await
        .expect("capture of a confirmed-absent path must succeed");

    let result = manager
        .rollback(&executor, &cp_id)
        .await
        .expect("rollback must run");

    assert!(
        result.rollback_success,
        "a genuinely absent optional path must not fail the rollback: {result:?}"
    );
    assert!(
        result.rollback_files[0].restore_error.is_none(),
        "no error should be recorded for a path that was never there: {:?}",
        result.rollback_files[0].restore_error
    );
}

/// Builds a CheckpointManager over a temporary in-memory SQLite database
/// with a freshly generated signing key: no filesystem privileges needed.
async fn test_manager() -> CheckpointManager {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("mgr_test.db");
    let db_pool = crate::db::init_db(Some(&db_path)).await.expect("init_db");
    let key_path = dir.path().join("test.key");
    let signer = CheckpointSigner::new_with_path(&key_path).expect("signer");
    // Keep `dir` alive for the duration of the test by leaking it into the heap.
    // The OS reclaims the tempdir when the process exits.
    std::mem::forget(dir);
    CheckpointManager::new_with_signer(db_pool, signer).expect("manager")
}

#[tokio::test]
async fn create_checkpoint_captures_via_executor_and_tags_host() {
    let exec = MockExecutor::new()
        .remote()
        .with_description("ssh://root@h")
        .with_file("/etc/sysctl.conf", "kernel.kptr_restrict = 1\n");

    let manager = test_manager().await;
    let id = manager
        .create_checkpoint(&exec, "t", &[std::path::Path::new("/etc/sysctl.conf")])
        .await
        .expect("create_checkpoint");

    let (cp, file_states) = manager.get_checkpoint(&id).await.expect("get_checkpoint");
    assert_eq!(cp.host_key, "ssh://root@h");
    assert_eq!(file_states.len(), 1);
    assert_eq!(
        file_states[0].file_content.as_deref(),
        Some(b"kernel.kptr_restrict = 1\n".as_ref()),
    );
    assert!(
        exec.log()
            .files_read
            .iter()
            .any(|p| p.ends_with("sysctl.conf"))
    );
}

#[tokio::test]
async fn local_executor_tags_host_key_as_local() {
    let exec = MockExecutor::new().with_file("/etc/test.conf", "v=1\n");

    let manager = test_manager().await;
    let id = manager
        .create_checkpoint(
            &exec,
            "local-test",
            &[std::path::Path::new("/etc/test.conf")],
        )
        .await
        .expect("create_checkpoint");

    let (cp, _) = manager.get_checkpoint(&id).await.expect("get_checkpoint");
    assert_eq!(cp.host_key, "local");
}

#[tokio::test]
async fn rollback_restores_directory_permissions_not_skipped() {
    // A directory's captured mode (0o755) carries no S_IFDIR bit; `file_metadata`
    // masks the type bit off. Rollback must still re-apply its permissions rather
    // than skip or remove it. Regression guard for the masked-mode directory bug.
    let ok = hardener_common::executor::CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    let exec = MockExecutor::new()
        .with_directory("/etc/pam.d")
        .with_command("chmod", &["755", "/etc/pam.d"], ok.clone())
        .with_command("chown", &["0:0", "/etc/pam.d"], ok);

    let manager = test_manager().await;
    let id = manager
        .create_checkpoint_metadata_only(&exec, "dir", &[std::path::Path::new("/etc/pam.d")])
        .await
        .expect("create");
    let result = manager.rollback(&exec, &id).await.expect("rollback");

    assert!(result.rollback_success, "directory rollback should succeed");
    let entry = result
        .rollback_files
        .iter()
        .find(|f| f.restore_path.ends_with("pam.d"))
        .expect("directory entry present");
    assert!(
        matches!(entry.restore_action, FileRestoreAction::PermissionsRestored),
        "directory must have permissions restored, not skipped or removed"
    );
    assert!(
        !exec.log().commands_executed.iter().any(|(p, _)| p == "rm"),
        "directory must not be removed on rollback"
    );
}

#[tokio::test]
async fn absent_file_is_captured_as_missing_entry() {
    let exec = MockExecutor::new(); // no files seeded

    let manager = test_manager().await;
    let id = manager
        .create_checkpoint(
            &exec,
            "absent",
            &[std::path::Path::new("/etc/no-such-file")],
        )
        .await
        .expect("create_checkpoint");

    let (_, file_states) = manager.get_checkpoint(&id).await.expect("get_checkpoint");
    assert_eq!(file_states.len(), 1);
    assert!(file_states[0].file_content.is_none());
    assert_eq!(file_states[0].file_permissions, 0);
}

#[tokio::test]
async fn metadata_only_checkpoint_stores_no_content() {
    let exec = MockExecutor::new().with_directory("/etc/pam.d");

    let manager = test_manager().await;
    let id = manager
        .create_checkpoint_metadata_only(&exec, "meta-only", &[std::path::Path::new("/etc/pam.d")])
        .await
        .expect("create_checkpoint_metadata_only");

    let (_, file_states) = manager.get_checkpoint(&id).await.expect("get_checkpoint");
    assert_eq!(file_states.len(), 1);
    assert!(file_states[0].file_content.is_none());
    assert_ne!(file_states[0].file_permissions, 0);
}

#[tokio::test]
async fn capture_refuses_to_record_an_unverifiable_path_as_absent() {
    // The data-loss bug at its source. An unstat-able path recorded as
    // absent (file_permissions: 0) is deleted by a later rollback, so
    // capture must fail rather than record it.
    let manager = test_manager().await;
    let executor = MockExecutor::new()
        .with_metadata_error("/etc/passwd")
        .with_path_exists("/etc/passwd", true);

    manager
        .create_checkpoint_metadata_only(
            &executor,
            "permissions-hardening",
            &[std::path::Path::new("/etc/passwd")],
        )
        .await
        .expect_err("an unverifiable path must abort capture, not be stored as absent");
}

#[tokio::test]
async fn capture_still_records_a_genuinely_absent_path() {
    // The other half: confirmed absence must stay an ordinary outcome, or
    // every host lacking an optional path would fail to apply.
    let manager = test_manager().await;
    let executor = MockExecutor::new();

    manager
        .create_checkpoint_metadata_only(
            &executor,
            "permissions-hardening",
            &[std::path::Path::new("/etc/sudoers.d")],
        )
        .await
        .expect("a confirmed-absent path is not an error");
}

#[tokio::test]
async fn capture_refuses_a_declared_path_whose_content_cannot_be_read() {
    // A checkpoint that silently records no content for a file it was asked
    // to protect is worse than no checkpoint: rollback restores the mode and
    // never the contents, so the file cannot be recovered.
    let manager = test_manager().await;
    let path = "/etc/security/faillock.conf";
    let executor = MockExecutor::new()
        .with_file(path, "deny = 3\n")
        .with_read_permission_denied(path);

    let result = manager
        .create_checkpoint(&executor, "unreadable", &[Path::new(path)])
        .await;

    let error = result
        .expect_err("a declared path whose content could not be read must fail the capture")
        .to_string();
    // Named in the capture's own words, not merely somewhere in the wrapped
    // cause: this mock's read error happens to repeat the path, but a real
    // one need not (a bare "Permission denied (os error 13)" does not), and
    // an operator cannot act on a failure that does not say which file.
    assert!(
        error.contains(&format!("Cannot checkpoint {path}")),
        "the failure must name the path it could not capture, got: {error}"
    );
}

#[tokio::test]
async fn capture_tolerates_an_unreadable_child_of_a_declared_directory() {
    // Guard against over-correction: a plugin declares /etc/pam.d to record
    // it, not to rewrite what is inside. One odd file in there must not stop
    // an apply on a host that works today.
    let manager = test_manager().await;
    let dir = "/etc/pam.d";
    let child = "/etc/pam.d/odd";
    let executor = MockExecutor::new()
        .with_directory(dir)
        .with_file(child, "unreadable\n")
        .with_read_permission_denied(child);

    let result = manager
        .create_checkpoint(&executor, "sweep", &[Path::new(dir)])
        .await;

    let id = result.expect("an unreadable file found by recursion must not fail the capture");
    let (_, file_states) = manager.get_checkpoint(&id).await.expect("get_checkpoint");
    let captured = file_states
        .iter()
        .find(|s| s.file_path == child)
        .expect("the capture must still record a row for the unreadable child");
    assert_eq!(
        captured.file_content, None,
        "the tolerated child must carry no content, since none was read"
    );
}

#[tokio::test]
async fn list_checkpoints_includes_host_key() {
    let exec = MockExecutor::new()
        .remote()
        .with_description("ssh://root@target")
        .with_file("/etc/ssh/sshd_config", "Port 22\n");

    let manager = test_manager().await;
    manager
        .create_checkpoint(
            &exec,
            "listed",
            &[std::path::Path::new("/etc/ssh/sshd_config")],
        )
        .await
        .expect("create_checkpoint");

    let list = manager.list_checkpoints().await.expect("list_checkpoints");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].host_key, "ssh://root@target");
}

fn cp(id: &str, name: &str, ts: i64, host: &str) -> Checkpoint {
    Checkpoint {
        checkpoint_id: CheckpointId::new(id.to_string()),
        checkpoint_name: name.to_string(),
        checkpoint_timestamp: ts,
        checkpoint_username: "u".to_string(),
        checkpoint_signature: vec![],
        host_key: host.to_string(),
    }
}

#[test]
fn select_latest_named_picks_newest_per_name_for_host() {
    let all = vec![
        cp("a", "ssh-hardening-pre-apply", 100, "ssh://root@h"),
        cp("b", "ssh-hardening-pre-apply", 200, "ssh://root@h"),
        cp("c", "kernel-hardening-pre-apply", 150, "ssh://root@h"),
        cp("d", "ssh-hardening-pre-apply", 999, "ssh://root@other"),
    ];
    let names = vec![
        "ssh-hardening-pre-apply".to_string(),
        "kernel-hardening-pre-apply".to_string(),
    ];
    let got = select_latest_named(&all, &["ssh://root@h".to_string()], &names);
    assert_eq!(got.len(), 2, "one checkpoint per matched name");
    assert_eq!(
        got[0].checkpoint_id.as_str(),
        "b",
        "newest ssh checkpoint on this host"
    );
    assert_eq!(got[1].checkpoint_id.as_str(), "c");
}

#[test]
fn select_latest_named_omits_unmatched_names_and_other_hosts() {
    let all = vec![cp("a", "ssh-hardening-pre-apply", 100, "ssh://root@h")];
    let names = vec![
        "audit-hardening-pre-apply".to_string(),
        "ssh-hardening-pre-apply".to_string(),
    ];
    let got = select_latest_named(&all, &["ssh://root@nope".to_string()], &names);
    assert!(got.is_empty(), "no checkpoints for that host");
}

/// A checkpoint filed under a key an earlier release used is still selected.
///
/// This is what stops the host-key fix from making an operator's existing
/// remote rollback points invisible. The legacy key is accepted for lookup and
/// never written, and the newest across both keys wins, because the two name
/// the same machine and the same account.
#[test]
fn select_latest_named_accepts_a_key_an_earlier_release_used() {
    let all = vec![
        cp("old", "ssh-hardening-pre-apply", 100, "ssh://root@h:22"),
        cp("new", "ssh-hardening-pre-apply", 200, "ssh://deploy@h:22"),
        cp("older", "kernel-hardening-pre-apply", 50, "ssh://root@h:22"),
    ];
    let names = vec![
        "ssh-hardening-pre-apply".to_string(),
        "kernel-hardening-pre-apply".to_string(),
    ];
    let keys = [
        "ssh://deploy@h:22".to_string(),
        "ssh://root@h:22".to_string(),
    ];

    let got = select_latest_named(&all, &keys[..], &names);

    assert_eq!(got.len(), 2, "both names resolve across the two keys");
    assert_eq!(
        got[0].checkpoint_id.as_str(),
        "new",
        "newest wins regardless of which key it was filed under"
    );
    assert_eq!(
        got[1].checkpoint_id.as_str(),
        "older",
        "a name only the legacy key holds is still found, which is the point"
    );

    assert!(
        select_latest_named(&all, &keys[..1], &names)
            .iter()
            .all(|c| c.checkpoint_id.as_str() != "older"),
        "and without the legacy key it is not found, so the test is not vacuous"
    );
}

#[tokio::test]
async fn latest_named_for_host_reads_db() {
    let exec = MockExecutor::new()
        .remote()
        .with_description("ssh://root@h")
        .with_file("/etc/ssh/sshd_config", "Port 22\n");
    let manager = test_manager().await;
    manager
        .create_checkpoint(
            &exec,
            "ssh-hardening-pre-apply",
            &[std::path::Path::new("/etc/ssh/sshd_config")],
        )
        .await
        .expect("create");
    let got = manager
        .latest_named_for_host(
            &["ssh://root@h".to_string()],
            &["ssh-hardening-pre-apply".to_string()],
        )
        .await
        .expect("select");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].checkpoint_name, "ssh-hardening-pre-apply");
}

/// Builds a CheckpointManager with a custom allowlist containing `/etc/x`.
async fn test_manager_with_etc_x() -> CheckpointManager {
    test_manager_with_allowlist(vec!["/etc/x".to_string()]).await
}

async fn test_manager_with_allowlist(prefixes: Vec<String>) -> CheckpointManager {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("mgr_test.db");
    let db_pool = crate::db::init_db(Some(&db_path)).await.expect("init_db");
    let key_path = dir.path().join("test.key");
    let signer = CheckpointSigner::new_with_path(&key_path).expect("signer");
    std::mem::forget(dir);
    CheckpointManager::new_with_allowlist(db_pool, signer, prefixes).expect("manager")
}

/// A link to a directory is a link, not a directory to walk into.
///
/// `file_metadata` follows a link, so such a path reports `is_dir` and the
/// recursive capture would descend into the target, storing the target
/// directory's files under child paths that resolve back through the link.
/// Restoring those would write into the target directory, which is the same
/// defect one level down.
///
/// The child registered below is what lets this test fail: without it the
/// recursion would find nothing and a single link entry would be
/// indistinguishable from a walk that happened to come back empty.
#[tokio::test]
async fn a_link_to_a_directory_is_captured_as_a_link_not_walked_into() {
    let exec = MockExecutor::new()
        .with_directory("/etc/x/wants")
        .with_symlink("/etc/x/wants", "/usr/lib/systemd/system")
        .with_file("/etc/x/wants/packaged.service", "[Unit]\n");
    let manager = test_manager_with_etc_x().await;

    let id = manager
        .create_checkpoint(&exec, "dirlink", &[Path::new("/etc/x/wants")])
        .await
        .expect("create_checkpoint");
    let (_, states) = manager.get_checkpoint(&id).await.expect("get_checkpoint");

    assert_eq!(
        states.len(),
        1,
        "a link must be one entry, not a walk of what it points at, got: {:?}",
        states.iter().map(|s| &s.file_path).collect::<Vec<_>>()
    );
    assert_eq!(
        states[0].file_link_target.as_deref(),
        Some("/usr/lib/systemd/system"),
        "the entry must record where the link points"
    );
    assert!(
        states[0].file_content.is_none(),
        "a link has no content of its own to store"
    );
}

/// A symlink must come back as a symlink, not as the content it pointed at.
///
/// `file_metadata` follows a link, so a capture of `/etc/systemd/system`
/// stored the contents of the packaged unit files its enablement links point
/// at. Restoring that meant writing those bytes back through the link into
/// `/usr/lib/systemd/system`, which the allowlist exists to prevent, so
/// `systemctl disable` and `systemctl mask` state has never been recoverable
/// on any distribution: the rollback either refused the path or, before that,
/// abandoned the whole run over it.
///
/// Recreating the link writes only the link, so the target's directory is
/// never touched and the allowlist question is about the link's own path.
/// The assertions below say that in three ways, because "it did not write
/// through the link" is the property, and an `ln` that ran alongside a write
/// would satisfy a weaker one.
#[tokio::test]
async fn a_captured_symlink_is_restored_as_a_link_not_as_content() {
    use hardener_common::executor::CommandOutput;

    let link = "/etc/x/autovt.service";
    let target = "/usr/lib/systemd/system/getty.service";
    let exec = MockExecutor::new()
        // The link's own directory. A host cannot hold a link whose
        // directory is absent, and a restore probes that directory before
        // recreating the link, so a fixture omitting it describes a host
        // that could not exist and sends the restore down the branch that
        // creates the directory instead of the one under test here.
        .with_directory("/etc/x")
        // Content is what the mock returns for a read, exactly as a real
        // read through the link would return the target's bytes.
        .with_file(link, "[Unit]\nDescription=Getty\n")
        .with_symlink(link, target)
        .with_command(
            "ln",
            &["-sfn", target, link],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
    let manager = test_manager_with_etc_x().await;

    let id = manager
        .create_checkpoint(&exec, "svc", &[Path::new(link)])
        .await
        .expect("create_checkpoint");
    let result = manager.rollback(&exec, &id).await.expect("rollback");

    let log = exec.log();
    assert!(
        log.commands_executed
            .iter()
            .any(|(program, args)| program == "ln" && args.iter().any(|a| a == target)),
        "the link must be recreated pointing at its target, got: {:?}",
        log.commands_executed
    );
    assert!(
        !log.files_written.iter().any(|(p, _)| p == Path::new(link)),
        "nothing may be written through the link, got: {:?}",
        log.files_written
    );
    assert!(
        !log.commands_executed
            .iter()
            .any(|(program, args)| (program == "chmod" || program == "chown")
                && args.iter().any(|a| a == link)),
        "chmod and chown follow a link, so neither may be issued for one, got: {:?}",
        log.commands_executed
    );
    assert!(
        result.rollback_success,
        "restoring a link is a success, got: {:?}",
        result.rollback_files
    );
}

/// One file that cannot be restored must not cost the operator every other
/// file in the checkpoint.
///
/// `/etc/systemd/system` is allow-listed and the services plugin declares
/// it, so capture recurses in and collects the stock unit symlinks a
/// distribution ships there. `autovt@.service` points into
/// `/usr/lib/systemd/system`, which is deliberately not allow-listed,
/// because writing a captured copy through that link would overwrite a
/// packaged unit file. The guard is right to refuse it. Phase 1 then turned
/// that one refusal into an abort of the entire rollback, so
/// `hardener rollback` restored nothing at all on four of the five test
/// distributions, measured 2026-07-29.
///
/// Phase 2 already treats the identical condition as a per-file skip, so two
/// copies of one guard disagreed and the fatal copy ran first.
#[tokio::test]
async fn one_unrestorable_path_does_not_abort_the_whole_rollback() {
    use hardener_common::executor::CommandOutput;

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_path_buf();
    let good = root.join("good.conf");
    let outward = root.join("outward.link");

    let manager = test_manager_with_allowlist(vec![root.to_string_lossy().into_owned()]).await;
    // chmod and chown are registered because a restore issues both after the
    // write. Without them the run stops at a failed metadata command and the
    // assertion below would pass or fail for a reason that has nothing to do
    // with Phase 1, which is how a fixture comes to hide the thing under test.
    let ok = || CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    let good_str = good.to_str().expect("utf8");
    let exec = MockExecutor::new()
        .with_file(good_str, "captured\n")
        .with_file(outward.to_str().expect("utf8"), "captured\n")
        .with_command("chmod", &["644", good_str], ok())
        .with_command("chown", &["0:0", good_str], ok());

    let id = manager
        .create_checkpoint(&exec, "mixed", &[good.as_path(), outward.as_path()])
        .await
        .expect("create_checkpoint");

    // Resolves outside the allowlist, exactly as a stock unit symlink does.
    // Registered on the executor and after the capture, so the row is recorded
    // as the regular file it was and the guard meets the link the way a rollback
    // does: by asking the host it is about to write to.
    exec.add_symlink(&outward.to_string_lossy(), "/etc");

    let result = manager
        .rollback(&exec, &id)
        .await
        .expect("one unrestorable path must not abort the rollback");

    let entry = |p: &Path| {
        result
            .rollback_files
            .iter()
            .find(|f| f.restore_path == p.to_string_lossy())
            .unwrap_or_else(|| panic!("{} missing from the result", p.display()))
    };
    assert!(
        entry(&good).restore_success,
        "the in-bounds file must still be restored, got: {:?}",
        entry(&good).restore_error
    );
    let refused = entry(&outward);
    assert!(
        !refused.restore_success,
        "the out-of-bounds symlink must not be written"
    );
    assert!(
        refused
            .restore_error
            .as_deref()
            .unwrap_or_default()
            .contains("resolves outside"),
        "the refusal must say why, got: {:?}",
        refused.restore_error
    );
    assert!(
        !result.rollback_success,
        "a rollback that skipped a file is not a successful one"
    );
}

#[tokio::test]
async fn rollback_refuses_cross_host_checkpoint() {
    let remote = MockExecutor::new()
        .remote()
        .with_description("ssh://a")
        .with_file("/etc/x", "original\n");

    let manager = test_manager_with_etc_x().await;
    let id = manager
        .create_checkpoint(&remote, "t", &[std::path::Path::new("/etc/x")])
        .await
        .expect("create_checkpoint");

    // A local executor targets "local", but the checkpoint was for "ssh://a".
    let local = MockExecutor::new();
    let err = manager
        .rollback(&local, &id)
        .await
        .expect_err("expected cross-host error");
    assert!(
        err.to_string().contains("Refusing to restore"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn rollback_restores_through_executor() {
    use hardener_common::executor::CommandOutput;

    // Seed the executor with the "original" file content and register
    // chmod/chown so best-effort metadata commands succeed.
    let exec = MockExecutor::new()
        .with_file("/etc/x", "original\n")
        .with_command(
            "chmod",
            &["644", "/etc/x"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        )
        .with_command(
            "chown",
            &["0:0", "/etc/x"],
            CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        );

    let manager = test_manager_with_etc_x().await;
    let id = manager
        .create_checkpoint(&exec, "t", &[std::path::Path::new("/etc/x")])
        .await
        .expect("create_checkpoint");

    // Overwrite the file in the mock's in-memory store.
    exec.write_file(std::path::Path::new("/etc/x"), "changed\n")
        .await
        .expect("write_file");

    let result = manager.rollback(&exec, &id).await.expect("rollback");
    assert!(result.rollback_success, "rollback_success should be true");

    // The executor's write_file restores the content into the mock store.
    let restored = exec
        .read_file(std::path::Path::new("/etc/x"))
        .await
        .expect("read_file after rollback");
    assert_eq!(restored, "original\n");
}

/// A helper producing a zero-exit command output for best-effort chmod/chown.
fn ok_output() -> hardener_common::executor::CommandOutput {
    hardener_common::executor::CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    }
}

#[tokio::test]
async fn rollback_snapshots_current_state_before_restoring() {
    // The reversible-rollback guarantee: before overwriting the live files,
    // rollback captures their CURRENT content as a new checkpoint named after
    // the one being restored.
    let exec = MockExecutor::new()
        .with_file("/etc/x", "original\n")
        .with_command("chmod", &["644", "/etc/x"], ok_output())
        .with_command("chown", &["0:0", "/etc/x"], ok_output());
    let manager = test_manager_with_etc_x().await;
    let id = manager
        .create_checkpoint(&exec, "hardening", &[Path::new("/etc/x")])
        .await
        .expect("create_checkpoint");

    // The live state diverges from the checkpoint we will restore.
    exec.write_file(Path::new("/etc/x"), "changed\n")
        .await
        .expect("write_file");

    let before = manager.list_checkpoints().await.expect("list").len();
    manager.rollback(&exec, &id).await.expect("rollback");
    let after = manager.list_checkpoints().await.expect("list");

    assert_eq!(
        after.len(),
        before + 1,
        "rollback must create exactly one pre-rollback checkpoint"
    );
    let pre = after
        .iter()
        .find(|c| c.checkpoint_name == "Before rollback to 'hardening'")
        .expect("a checkpoint named after the restored one must exist");
    let (_, states) = manager
        .get_checkpoint(&pre.checkpoint_id)
        .await
        .expect("get_checkpoint");
    let captured = states
        .iter()
        .find(|s| s.file_path == "/etc/x")
        .expect("the snapshot must include /etc/x");
    assert_eq!(
        captured.file_content.as_deref(),
        Some(b"changed\n".as_ref()),
        "the snapshot must capture the CURRENT content, not the restored checkpoint's"
    );
}

#[tokio::test]
async fn rollback_snapshot_keeps_account_files_metadata_only() {
    // Parity with apply-time capture: account databases are snapshot
    // metadata-only, so no password hashes ever enter the checkpoint DB.
    use hardener_common::executor::FileMetadata;
    let shadow = "/etc/shadow";
    let exec = MockExecutor::new()
        .with_file_metadata(
            shadow,
            "root:$6$secret$hash:19000:0:99999:7:::\n",
            FileMetadata {
                exists: true,
                is_file: true,
                is_dir: false,
                mode: 0o100000,
                size: 0,
                uid: 0,
                gid: 0,
            },
        )
        .with_command("chmod", &["0", shadow], ok_output())
        .with_command("chown", &["0:0", shadow], ok_output());
    let manager = test_manager().await; // production allowlist covers /etc/shadow
    let id = manager
        .create_checkpoint_metadata_only(&exec, "perm", &[Path::new(shadow)])
        .await
        .expect("create_checkpoint_metadata_only");

    manager.rollback(&exec, &id).await.expect("rollback");

    let after = manager.list_checkpoints().await.expect("list");
    let pre = after
        .iter()
        .find(|c| c.checkpoint_name == "Before rollback to 'perm'")
        .expect("pre-rollback checkpoint");
    let (_, states) = manager
        .get_checkpoint(&pre.checkpoint_id)
        .await
        .expect("get_checkpoint");
    let s = states
        .iter()
        .find(|s| s.file_path == shadow)
        .expect("shadow captured");
    assert!(
        s.file_content.is_none(),
        "account files must be snapshot metadata-only: no content may be stored"
    );
}

#[tokio::test]
async fn rollback_is_reversible_via_its_pre_rollback_checkpoint() {
    // End-to-end undo: after rolling back, restoring the pre-rollback
    // checkpoint returns the system to the state it was in before rollback.
    let exec = MockExecutor::new()
        .with_file("/etc/x", "baseline\n")
        .with_command("chmod", &["644", "/etc/x"], ok_output())
        .with_command("chown", &["0:0", "/etc/x"], ok_output());
    let manager = test_manager_with_etc_x().await;
    let baseline = manager
        .create_checkpoint(&exec, "baseline", &[Path::new("/etc/x")])
        .await
        .expect("create_checkpoint");

    // Move the live state forward (as an apply would).
    exec.write_file(Path::new("/etc/x"), "hardened\n")
        .await
        .expect("write_file");

    // Roll back to baseline; this must snapshot the "hardened" state first.
    manager.rollback(&exec, &baseline).await.expect("rollback");
    assert_eq!(
        exec.read_file(Path::new("/etc/x")).await.expect("read"),
        "baseline\n"
    );

    // Undo the rollback by restoring the pre-rollback checkpoint.
    let pre = manager
        .list_checkpoints()
        .await
        .expect("list")
        .into_iter()
        .find(|c| c.checkpoint_name == "Before rollback to 'baseline'")
        .expect("pre-rollback checkpoint");
    manager
        .rollback(&exec, &pre.checkpoint_id)
        .await
        .expect("undo rollback");

    assert_eq!(
        exec.read_file(Path::new("/etc/x")).await.expect("read"),
        "hardened\n",
        "undoing the rollback must restore the pre-rollback state"
    );
}

#[tokio::test]
async fn rollback_fails_closed_when_current_state_cannot_be_captured() {
    // If the current state cannot be snapshot, rollback must refuse and write
    // nothing: a rollback we cannot undo is more dangerous than not running.
    use hardener_common::executor::FileMetadata;
    let setup = MockExecutor::new()
        .with_file("/etc/x", "original\n")
        .with_command("chmod", &["644", "/etc/x"], ok_output())
        .with_command("chown", &["0:0", "/etc/x"], ok_output());
    let manager = test_manager_with_etc_x().await;
    let id = manager
        .create_checkpoint(&setup, "cp", &[Path::new("/etc/x")])
        .await
        .expect("create_checkpoint");

    // Roll back against a host where /etc/x exists but is unreadable.
    let exec = MockExecutor::new()
        .with_file_metadata(
            "/etc/x",
            "unreadable",
            FileMetadata {
                exists: true,
                is_file: true,
                is_dir: false,
                mode: 0o644,
                size: 10,
                uid: 0,
                gid: 0,
            },
        )
        .with_read_permission_denied("/etc/x")
        .with_command("chmod", &["644", "/etc/x"], ok_output())
        .with_command("chown", &["0:0", "/etc/x"], ok_output());

    let before = manager.list_checkpoints().await.expect("list").len();
    let result = manager.rollback(&exec, &id).await;

    assert!(
        result.is_err(),
        "rollback must fail closed when the current state cannot be captured"
    );
    assert!(
        exec.log().files_written.is_empty(),
        "no file may be written when rollback fails closed"
    );
    assert_eq!(
        manager.list_checkpoints().await.expect("list").len(),
        before,
        "no half-committed pre-rollback checkpoint may persist on failure"
    );
}

#[tokio::test]
async fn rollback_leaves_no_snapshot_when_validation_rejects() {
    // The snapshot runs after Phase 1, over the restorable set only, so a
    // checkpoint whose every path is refused must not persist an orphan
    // pre-rollback checkpoint or read a refused path's content. This fixture
    // holds exactly one path and it is out of bounds, which is the
    // nothing-left-to-restore case: an error, not a run whose every file was
    // skipped.
    let exec = MockExecutor::new().with_file("/tmp/evil.conf", "x\n");
    let manager = test_manager_with_etc_x().await; // allowlist is ["/etc/x"] only
    let id = manager
        .create_checkpoint(&exec, "bad", &[Path::new("/tmp/evil.conf")])
        .await
        .expect("create_checkpoint");

    let before = manager.list_checkpoints().await.expect("list").len();
    let result = manager.rollback(&exec, &id).await;

    assert!(
        result.is_err(),
        "rollback must reject a path outside the allowlist"
    );
    assert_eq!(
        manager.list_checkpoints().await.expect("list").len(),
        before,
        "a rollback rejected by validation must not persist a pre-rollback checkpoint"
    );
}

/// Registers the `chmod` and `chown` a metadata restore issues for `path`, so a
/// rollback test is measuring the thing it names rather than an unregistered
/// command. The mode is what `restore_file_state_tracked` formats: the
/// permission bits alone, octal, with no type bits.
fn with_metadata_restore(executor: MockExecutor, path: &str, mode_octal: &str) -> MockExecutor {
    executor
        .with_command("chmod", &[mode_octal, path], ok_output())
        .with_command("chown", &["0:0", path], ok_output())
}

/// Issue #60: a rollback that could not put the bytes back stops calling itself
/// a success.
///
/// A best-effort capture whose read failed produced a row identical to one
/// captured metadata-only on purpose: no content, a real mode, no link target.
/// Restore re-applied permissions to both and reported success, so an operator
/// who asked for a file's contents back was told the rollback worked while the
/// contents were whatever the apply had left there.
///
/// The two fixtures differ only in whether the file can be read at capture.
#[tokio::test]
async fn a_rollback_that_could_not_restore_the_bytes_says_so() {
    use hardener_common::executor::FileMetadata;

    let present = |mode: u32| FileMetadata {
        exists: true,
        is_file: true,
        is_dir: false,
        mode,
        size: 0,
        uid: 0,
        gid: 0,
    };
    let dir = "/etc/sysctl.d";
    let path = "/etc/sysctl.d/99-hardener.conf";

    // A declared FILE is captured under `ContentPolicy::Required`, which refuses
    // outright when the content cannot be read. Only recursion into a declared
    // DIRECTORY uses `BestEffort`, so that is the only way to reach the row this
    // test is about, and the fixture has to be shaped that way to reach it.
    let fixture = |readable: bool| {
        let executor = MockExecutor::new()
            .with_directory(dir)
            .with_file(path, "kernel.kptr_restrict = 2\n")
            .with_file_metadata(path, "kernel.kptr_restrict = 2\n", present(0o100644));
        let executor = match readable {
            true => executor,
            false => executor.with_read_permission_denied(path),
        };
        with_metadata_restore(with_metadata_restore(executor, path, "644"), dir, "755")
    };

    // Readable at capture: the bytes are stored and the rollback restores them.
    let manager = test_manager().await;
    let readable = fixture(true);
    let id = manager
        .create_checkpoint(&readable, "readable", &[Path::new(dir)])
        .await
        .expect("capture");
    let restored = manager.rollback(&readable, &id).await.expect("rollback");
    assert!(
        restored.rollback_success,
        "a checkpoint holding the bytes restores them: {:?}",
        restored.rollback_files
    );

    // Unreadable at capture: the row is what could be salvaged, and the rollback
    // must not claim to have restored what it never held.
    let manager = test_manager().await;
    let unreadable = fixture(false);
    let id = manager
        .create_checkpoint(&unreadable, "unreadable", &[Path::new(dir)])
        .await
        .expect("a best-effort capture salvages what it can rather than refusing");
    let result = manager.rollback(&unreadable, &id).await.expect("rollback");

    assert!(
        !result.rollback_success,
        "a rollback that restored no bytes must not report success: {:?}",
        result.rollback_files
    );
    let reported = result
        .rollback_files
        .iter()
        .find(|f| f.restore_path == path)
        .expect("the file must appear in the per-file results");
    assert!(
        !reported.restore_success,
        "the file itself must be the one reported, not some other row"
    );
    let reason = reported
        .restore_error
        .as_deref()
        .expect("a shortfall must carry its reason");
    assert!(
        reason.contains("content was not") && reason.contains("could not read it"),
        "the reason must say what was and was not restored, got: {reason}"
    );
}

/// The other half of the same distinction: a capture that stored no bytes on
/// purpose has nothing missing, so its rollback is a plain success.
///
/// This is what stops the fix above from being "report every contentless row as
/// a shortfall", which would fail every permissions rollback, since the account
/// databases are captured metadata-only precisely so their contents never enter
/// the checkpoint database.
#[tokio::test]
async fn a_deliberately_metadata_only_rollback_is_still_a_success() {
    use hardener_common::executor::FileMetadata;

    let manager = test_manager().await;
    let path = "/etc/shadow";
    let executor = with_metadata_restore(
        MockExecutor::new().with_file_metadata(
            path,
            "",
            FileMetadata {
                exists: true,
                is_file: true,
                is_dir: false,
                mode: 0o100000,
                size: 0,
                uid: 0,
                gid: 0,
            },
        ),
        path,
        "0",
    );

    let id = manager
        .create_checkpoint_metadata_only(&executor, "accounts", &[Path::new(path)])
        .await
        .expect("metadata-only capture");
    let result = manager.rollback(&executor, &id).await.expect("rollback");

    assert!(
        result.rollback_success,
        "a row with no bytes by design has nothing missing: {:?}",
        result.rollback_files
    );
}

/// A checkpoint written before `content_absence` existed still verifies.
///
/// The digest hashes the field only when it is present, emitting nothing at all
/// otherwise: no tag byte, no length prefix. That is what lets a row written by
/// an earlier release, which has no such column and reads back as `None`, hash
/// to exactly what it hashed then. Any unconditional byte for the field would
/// silently invalidate every checkpoint already on disk, and the failure would
/// surface as a signature refusal on a database nobody had touched.
///
/// The old database is produced rather than described: the column is dropped,
/// which is the state `init_db` migrates from, and reopening it runs the same
/// idempotent `ALTER TABLE` a real upgrade runs.
#[tokio::test]
async fn a_checkpoint_written_before_the_column_existed_still_verifies() {
    use hardener_common::executor::FileMetadata;

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("legacy.db");
    let key_path = dir.path().join("legacy.key");
    let path = "/etc/sysctl.d/99-hardener.conf";

    let executor = MockExecutor::new()
        .with_file(path, "kernel.kptr_restrict = 2\n")
        .with_file_metadata(
            path,
            "kernel.kptr_restrict = 2\n",
            FileMetadata {
                exists: true,
                is_file: true,
                is_dir: false,
                mode: 0o100644,
                size: 0,
                uid: 0,
                gid: 0,
            },
        );

    let id = {
        let pool = crate::db::init_db(Some(&db_path)).await.expect("init_db");
        let signer = CheckpointSigner::new_with_path(&key_path).expect("signer");
        let manager = CheckpointManager::new_with_signer(pool, signer).expect("manager");
        manager
            .create_checkpoint(&executor, "before-the-column", &[Path::new(path)])
            .await
            .expect("capture")
    };

    // Make it a pre-migration database. The signature was computed over a row
    // whose absence is `None`, which contributes nothing, so removing the column
    // must leave the digest identical rather than merely close.
    {
        let pool = crate::db::init_db(Some(&db_path)).await.expect("reopen");
        sqlx::query("ALTER TABLE file_states DROP COLUMN content_absence")
            .execute(&pool)
            .await
            .expect("drop the column to produce a pre-migration database");
        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('file_states') WHERE name = 'content_absence'",
        )
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(remaining, 0, "the fixture must actually lack the column");
        pool.close().await;
    }

    // Reopening runs the migration, exactly as an upgrade would.
    let pool = crate::db::init_db(Some(&db_path)).await.expect("migrate");
    let restored: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('file_states') WHERE name = 'content_absence'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(restored, 1, "init_db must add the column back");

    let signer = CheckpointSigner::new_with_path(&key_path).expect("signer");
    let manager = CheckpointManager::new_with_signer(pool, signer).expect("manager");
    manager.verify_checkpoint(&id).await.expect(
        "a checkpoint written before the column existed must still verify after \
         the migration, or upgrading refuses every checkpoint already on disk",
    );
}

/// The digest a row with no recorded absence produces is byte-for-byte the one
/// the algorithm produced before the field existed.
///
/// The round-trip test above cannot see this, and that is worth stating rather
/// than leaving as a gap: it writes and verifies with the same build, so a field
/// hashed unconditionally would be hashed unconditionally on both sides and
/// agree with itself. Hashing `None` as a tag byte instead of as nothing passes
/// that test and silently refuses every checkpoint already on disk.
///
/// So the old algorithm is reimplemented here as an oracle, in the order the
/// real one uses, and the two are compared. It is a second copy on purpose:
/// its whole value is being written independently of the code it checks.
#[test]
fn a_row_with_no_recorded_absence_hashes_exactly_as_it_did_before_the_field() {
    use ring::digest::{Context as DigestContext, SHA256};

    let id = CheckpointId::new("cp-1".to_string());
    let state = |absence: Option<ContentAbsence>| FileState {
        file_path: "/etc/sysctl.d/99-hardener.conf".to_string(),
        file_content: Some(b"kernel.kptr_restrict = 2\n".to_vec()),
        file_permissions: 0o100644,
        file_owner_uid: 0,
        file_owner_gid: 0,
        file_link_target: None,
        file_content_absence: absence,
    };

    // The pre-field algorithm, verbatim: no branch for the absence at all.
    let mut oracle = DigestContext::new(&SHA256);
    oracle.update(id.as_str().as_bytes());
    oracle.update(b"legacy");
    oracle.update(&7i64.to_be_bytes());
    oracle.update(b"root");
    let row = state(None);
    oracle.update(row.file_path.as_bytes());
    oracle.update(row.file_content.as_ref().expect("content"));
    oracle.update(&row.file_permissions.to_be_bytes());
    oracle.update(&row.file_owner_uid.to_be_bytes());
    oracle.update(&row.file_owner_gid.to_be_bytes());
    let expected = oracle.finish().as_ref().to_vec();

    assert_eq!(
        CheckpointManager::generate_digest(&id, "legacy", 7, "root", &[state(None)]),
        expected,
        "a row that records no absence must contribute nothing to the digest, or \
         every checkpoint signed before the field existed stops verifying"
    );

    // And the field must still be capable of changing the digest, or recording
    // it would be decoration.
    assert_ne!(
        CheckpointManager::generate_digest(
            &id,
            "legacy",
            7,
            "root",
            &[state(Some(ContentAbsence::ReadFailed))]
        ),
        expected,
        "a recorded absence must reach the signature"
    );
    assert_ne!(
        CheckpointManager::generate_digest(
            &id,
            "legacy",
            7,
            "root",
            &[state(Some(ContentAbsence::ByDesign))]
        ),
        CheckpointManager::generate_digest(
            &id,
            "legacy",
            7,
            "root",
            &[state(Some(ContentAbsence::ReadFailed))]
        ),
        "the two absences must be distinguishable to the signature as well"
    );
}

/// The tag bytes a recorded absence contributes are the exact bytes they were,
/// not merely distinct ones.
///
/// The test above asserts that the two absences differ from each other and from
/// `None`, and that is not the same promise. Renaming `digest_tag`'s `b"d"` and
/// `b"f"` to anything else at all, `b"by_design"` and `b"read_failed"` for
/// instance, which is the obvious tidy-up for making them match `as_column`,
/// keeps all three of those assertions true and **silently stops every
/// checkpoint signed since the field existed from verifying.** Measured, not
/// supposed: with `b"d"` changed to `b"D"`, `hardener-state` passes 113 of 113.
///
/// So the expected digests are built here independently, in the order the real
/// algorithm uses, with the tag written out as a literal. A second copy on
/// purpose, the same way the pre-field oracle above is.
#[test]
fn the_absence_tag_bytes_are_pinned_and_not_merely_distinct() {
    use ring::digest::{Context as DigestContext, SHA256};

    let id = CheckpointId::new("cp-1".to_string());
    let state = |absence: Option<ContentAbsence>| FileState {
        file_path: "/etc/sysctl.d/99-hardener.conf".to_string(),
        file_content: Some(b"kernel.kptr_restrict = 2\n".to_vec()),
        file_permissions: 0o100644,
        file_owner_uid: 0,
        file_owner_gid: 0,
        file_link_target: None,
        file_content_absence: absence,
    };

    let oracle_with_tag = |tag: &[u8]| {
        let mut oracle = DigestContext::new(&SHA256);
        oracle.update(id.as_str().as_bytes());
        oracle.update(b"legacy");
        oracle.update(&7i64.to_be_bytes());
        oracle.update(b"root");
        let row = state(None);
        oracle.update(row.file_path.as_bytes());
        oracle.update(row.file_content.as_ref().expect("content"));
        oracle.update(&row.file_permissions.to_be_bytes());
        oracle.update(&row.file_owner_uid.to_be_bytes());
        oracle.update(&row.file_owner_gid.to_be_bytes());
        oracle.update(tag);
        oracle.finish().as_ref().to_vec()
    };

    assert_eq!(
        CheckpointManager::generate_digest(
            &id,
            "legacy",
            7,
            "root",
            &[state(Some(ContentAbsence::ByDesign))]
        ),
        oracle_with_tag(b"d"),
        "ByDesign must contribute exactly b\"d\". Changing it is not a rename: \
         every checkpoint that recorded a by-design absence was signed over this \
         byte, and a different one makes all of them fail verification on a \
         database nobody touched."
    );
    assert_eq!(
        CheckpointManager::generate_digest(
            &id,
            "legacy",
            7,
            "root",
            &[state(Some(ContentAbsence::ReadFailed))]
        ),
        oracle_with_tag(b"f"),
        "ReadFailed must contribute exactly b\"f\", for the same reason."
    );
}

#[tokio::test]
async fn deleting_a_checkpoint_that_exists_removes_it() {
    let exec = MockExecutor::new().with_file("/etc/sysctl.conf", "kernel.kptr_restrict = 1\n");
    let manager = test_manager().await;
    let id = manager
        .create_checkpoint(&exec, "t", &[std::path::Path::new("/etc/sysctl.conf")])
        .await
        .expect("create_checkpoint");

    manager
        .delete_checkpoint(&id)
        .await
        .expect("deleting a checkpoint that exists succeeds");

    assert!(
        manager.get_checkpoint(&id).await.is_err(),
        "the checkpoint must be gone after a successful delete"
    );

    // The file rows go with it. Asserting only on the metadata row leaves the
    // `file_states` delete free to be removed entirely, which would leak every
    // captured file of every deleted checkpoint while this test stayed green.
    let orphans: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM file_states WHERE checkpoint_id = ?")
            .bind(id.as_str())
            .fetch_one(&manager.db_pool)
            .await
            .expect("the file_states rows are countable");
    assert_eq!(
        orphans, 0,
        "a deleted checkpoint must leave none of its file rows behind"
    );
}

#[tokio::test]
async fn deleting_a_checkpoint_that_never_existed_is_an_error() {
    let manager = test_manager().await;

    let result = manager
        .delete_checkpoint(&CheckpointId::new("cp_0_doesnotexist"))
        .await;

    // `DELETE ... WHERE` matching nothing is a successful statement, so the
    // database cannot tell these two outcomes apart on its own. Reporting
    // success here is a claim that a checkpoint was removed, which is what the
    // desktop reads to decide it need not retry against the system database.
    assert!(
        result.is_err(),
        "a delete that removed nothing must not report that it removed something"
    );
}

/// Strands a checkpoint's file rows by removing only its metadata row.
///
/// This is deliberately done the one way it can actually happen. The schema
/// declares `FOREIGN KEY(checkpoint_id) REFERENCES checkpoints(id)` and
/// `init_db` sets `PRAGMA foreign_keys = ON`, so on a connection this tool
/// opened the delete below is refused outright and no orphan can be made. The
/// pragma is per connection and SQLite defaults it OFF, so an operator poking
/// the database with `sqlite3` has it off and the same delete succeeds. That is
/// the scenario the repair exists for, and it is what this reproduces.
async fn strand_file_rows(manager: &CheckpointManager, id: &CheckpointId) {
    let mut conn = manager
        .db_pool
        .acquire()
        .await
        .expect("a connection of our own");
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await
        .expect("the pragma is settable, as it is for any external client");
    sqlx::query("DELETE FROM checkpoints WHERE id = ?")
        .bind(id.as_str())
        .execute(&mut *conn)
        .await
        .expect("the metadata row goes, leaving its file rows behind");
}

async fn seeded_orphan(manager: &CheckpointManager) -> CheckpointId {
    let exec = MockExecutor::new().with_file("/etc/sysctl.conf", "kernel.kptr_restrict = 1\n");
    let id = manager
        .create_checkpoint(
            &exec,
            "stranded",
            &[std::path::Path::new("/etc/sysctl.conf")],
        )
        .await
        .expect("create_checkpoint");
    strand_file_rows(manager, &id).await;
    id
}

#[tokio::test]
async fn a_healthy_database_reports_no_orphans() {
    let exec = MockExecutor::new().with_file("/etc/sysctl.conf", "kernel.kptr_restrict = 1\n");
    let manager = test_manager().await;
    manager
        .create_checkpoint(&exec, "intact", &[std::path::Path::new("/etc/sysctl.conf")])
        .await
        .expect("create_checkpoint");

    let found = manager
        .orphaned_file_states()
        .await
        .expect("the count reads");

    // The positive control for the two tests below: a checkpoint whose metadata
    // row is present must never be counted, or the repair would delete the file
    // rows of every live checkpoint.
    assert_eq!(found.rows, 0, "an intact checkpoint owns its file rows");
    assert_eq!(found.checkpoints, 0, "and belongs to no stranded id");
}

#[tokio::test]
async fn file_rows_whose_checkpoint_is_gone_are_counted() {
    let manager = test_manager().await;
    seeded_orphan(&manager).await;

    let found = manager
        .orphaned_file_states()
        .await
        .expect("the count reads");

    assert_eq!(found.rows, 1, "the stranded file row is found");
    assert_eq!(
        found.checkpoints, 1,
        "and is attributed to one absent checkpoint"
    );
}

#[tokio::test]
async fn removing_orphans_leaves_a_live_checkpoint_alone() {
    let exec = MockExecutor::new().with_file("/etc/login.defs", "PASS_MAX_DAYS 90\n");
    let manager = test_manager().await;
    seeded_orphan(&manager).await;
    let live = manager
        .create_checkpoint(&exec, "live", &[std::path::Path::new("/etc/login.defs")])
        .await
        .expect("create_checkpoint");

    let removed = manager
        .remove_orphaned_file_states()
        .await
        .expect("the removal runs");

    assert_eq!(removed, 1, "only the stranded row is removed");
    assert_eq!(
        manager
            .orphaned_file_states()
            .await
            .expect("the count reads")
            .rows,
        0,
        "nothing orphaned is left behind"
    );
    // The half that matters: a repair that also emptied a live checkpoint would
    // satisfy every assertion above while destroying the thing being repaired.
    let (_, files) = manager
        .get_checkpoint(&live)
        .await
        .expect("the live checkpoint survives");
    assert_eq!(files.len(), 1, "its captured file row is untouched");
}

/// The guard must ask the host the write lands on, not the host running the tool.
///
/// `rollback_target_refusal` called `Path::is_symlink` and `Path::canonicalize`,
/// both `std::fs` syscalls against the controller's own filesystem, while
/// `file_state.file_path` names a path on the target. Both remote rollback
/// paths, single-host and per-host fleet, reach it with an `SshExecutor` active,
/// where the path does not exist on the controller at all: `is_symlink` answered
/// false for every remote row, and the prefix allowlist became the whole check.
///
/// So a row captured as a regular file, whose remote path is now a symlink
/// pointing outside the allowlist, was admitted and the restore followed it,
/// writing a captured copy into a directory this tool never modifies. The
/// identical local case is refused, and was throughout.
///
/// The second file is what makes the skip observable. With the symlinked row
/// alone every path is refused, `restorable.is_empty()` aborts the run, and
/// "nothing was written through the link" then holds because nothing was written
/// at all, which is an assertion no mutation can turn red.
#[tokio::test]
async fn a_remote_path_that_became_an_out_of_bounds_symlink_is_refused() {
    use hardener_common::executor::CommandOutput;

    let ok = || CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    let followed = "/etc/x/sshd_config";
    let plain = "/etc/x/login.defs";
    let exec = MockExecutor::new()
        .remote()
        .with_directory("/etc/x")
        .with_file(followed, "captured\n")
        .with_file(plain, "captured\n")
        .with_command_program("chmod", ok())
        .with_command_program("chown", ok());
    let manager = test_manager_with_etc_x().await;

    let id = manager
        .create_checkpoint(&exec, "remote", &[Path::new(followed), Path::new(plain)])
        .await
        .expect("create_checkpoint");

    // The target host changed after the capture, which is the whole condition:
    // registered here rather than at construction so the row above is recorded
    // as the regular file it was, without a `file_link_target` to exempt it.
    exec.add_symlink(followed, "/usr/lib/systemd/system/sshd.service");

    let result = manager.rollback(&exec, &id).await.expect("rollback");

    let entry = |p: &str| {
        result
            .rollback_files
            .iter()
            .find(|f| f.restore_path == p)
            .unwrap_or_else(|| panic!("{p} missing from the result"))
    };
    let refused = entry(followed);
    assert!(
        !refused.restore_success,
        "a remote path standing as a symlink out of the allowlist must not be written"
    );
    assert!(
        refused
            .restore_error
            .as_deref()
            .unwrap_or_default()
            .contains("resolves outside"),
        "the refusal must say why, got: {:?}",
        refused.restore_error
    );
    assert!(
        !exec
            .log()
            .files_written
            .iter()
            .any(|(p, _)| p == Path::new(followed)),
        "nothing may be written through the link, got: {:?}",
        exec.log().files_written
    );
    assert!(
        entry(plain).restore_success,
        "the row that is still a regular file must be restored, got: {:?}",
        entry(plain).restore_error
    );
}

/// The other direction of the same defect, and it is silent.
///
/// A symlink the *controller* happens to hold at an allow-listed path, resolving
/// outside the allowlist, refused a remote rollback of that path, with a message
/// naming a path the operator reads as the remote's. The target host knows
/// nothing about it. Here the remote holds an ordinary file and the controller
/// holds a link to `/etc`, so the pre-fix guard refuses the only restorable row
/// and `restorable.is_empty()` aborts the whole rollback.
#[tokio::test]
async fn a_symlink_on_the_controller_does_not_refuse_a_remote_rollback() {
    use hardener_common::executor::CommandOutput;

    let ok = || CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_path_buf();
    let path = root.join("sshd_config");
    let path_str = path.to_string_lossy().into_owned();
    // The controller's own filesystem, which the target has never heard of.
    std::os::unix::fs::symlink("/etc", &path).expect("symlink");

    let exec = MockExecutor::new()
        .remote()
        .with_directory(&root.to_string_lossy())
        .with_file(&path_str, "captured\n")
        .with_command_program("chmod", ok())
        .with_command_program("chown", ok());
    let manager = test_manager_with_allowlist(vec![root.to_string_lossy().into_owned()]).await;

    let id = manager
        .create_checkpoint(&exec, "remote", &[path.as_path()])
        .await
        .expect("create_checkpoint");

    let result = manager
        .rollback(&exec, &id)
        .await
        .expect("a link on the controller must not refuse a rollback of the remote");

    assert!(
        result.rollback_success,
        "the remote row is an ordinary file and must be restored, got: {:?}",
        result.rollback_files
    );
    assert!(
        exec.log()
            .files_written
            .iter()
            .any(|(p, _)| p == path.as_path()),
        "the captured content must reach the target, got: {:?}",
        exec.log().files_written
    );
}

/// Issue #83, at the caller: a path the probe could not look at must not be
/// written through.
///
/// The condition is a remote host where the login user cannot traverse to an
/// allow-listed path while the write happens as root, so the probe's answer and
/// the write's reach disagree. Before the fix the guard was told "not a
/// symlink", admitted the row, and root wrote through whatever stood there.
///
/// The second file is what makes the refusal observable. With the unprobeable
/// row alone every path is refused, `restorable.is_empty()` aborts the run, and
/// "nothing was written" would then hold because nothing was written at all,
/// which is an assertion no mutation can turn red.
#[tokio::test]
async fn a_path_the_probe_cannot_answer_for_is_refused() {
    use hardener_common::executor::CommandOutput;

    let ok = || CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    let unreachable = "/etc/x/sshd_config";
    let plain = "/etc/x/login.defs";
    let exec = MockExecutor::new()
        .remote()
        .with_directory("/etc/x")
        .with_file(unreachable, "captured\n")
        .with_file(plain, "captured\n")
        .with_command_program("chmod", ok())
        .with_command_program("chown", ok());
    let manager = test_manager_with_etc_x().await;

    let id = manager
        .create_checkpoint(&exec, "remote", &[Path::new(unreachable), Path::new(plain)])
        .await
        .expect("create_checkpoint");

    // Capture succeeded as the login user; the restore is what runs as root,
    // so the probe stops being answerable only now.
    exec.add_unprobeable(unreachable);

    let result = manager.rollback(&exec, &id).await.expect("rollback");

    let entry = |p: &str| {
        result
            .rollback_files
            .iter()
            .find(|f| f.restore_path == p)
            .unwrap_or_else(|| panic!("{p} missing from the result"))
    };
    let refused = entry(unreachable);
    assert!(
        !refused.restore_success,
        "a path the probe could not answer for must not be written"
    );
    assert!(
        refused
            .restore_error
            .as_deref()
            .unwrap_or_default()
            .contains("cannot be determined"),
        "the refusal must say the probe could not tell, not that the path is a \
         symlink: got {:?}",
        refused.restore_error
    );
    assert!(
        !exec
            .log()
            .files_written
            .iter()
            .any(|(p, _)| p == Path::new(unreachable)),
        "nothing may be written to a path the guard could not judge, got: {:?}",
        exec.log().files_written
    );
    assert!(
        entry(plain).restore_success,
        "the row the probe could answer for must still be restored, got: {:?}",
        entry(plain).restore_error
    );
}

/// A row under test, recorded as an ordinary file with content.
///
/// Built here rather than captured, because the paths below are ones a capture
/// would never produce: that is the point of the guard reading them.
fn refusal_row(path: &str) -> FileState {
    FileState {
        file_path: path.to_string(),
        file_content: Some(b"captured\n".to_vec()),
        file_permissions: 0o100644,
        file_owner_uid: 0,
        file_owner_gid: 0,
        file_link_target: None,
        file_content_absence: None,
    }
}

/// Each clause of the path guard refuses on its own.
///
/// The three conditions are joined by `||`, so a row failing any one of them is
/// refused and a row failing none is admitted. Turned into `&&` the guard
/// refuses only a path that is relative **and** carries `..` **and** sits
/// outside the allowlist, which no real attack needs to be: a rollback would
/// then write through `..` out of `/etc/x` because the path was absolute. Every
/// case below fails exactly one clause, so no case can stand in for another,
/// and the admitted control is what stops a guard that refuses everything
/// passing the other three.
#[tokio::test]
async fn a_rollback_path_failing_any_one_clause_of_the_guard_is_refused() {
    let manager = test_manager_with_etc_x().await;
    let executor = MockExecutor::new();

    for (path, clause) in [
        (
            "etc/x/sshd_config",
            "it is relative, so it names nothing fixed",
        ),
        (
            "/etc/x/../../root/.ssh/authorized_keys",
            "it carries a parent-dir component and climbs out",
        ),
        (
            "/usr/lib/systemd/system/sshd.service",
            "it sits outside every allowed prefix",
        ),
    ] {
        let refusal = manager
            .rollback_target_refusal(&executor, &refusal_row(path))
            .await;
        assert!(
            refusal.is_some(),
            "`{path}` must be refused, because {clause}"
        );
        assert!(
            refusal
                .as_deref()
                .is_some_and(|reason| reason.contains(path)),
            "and the refusal must name the path it refused: {refusal:?}"
        );
    }

    assert!(
        manager
            .rollback_target_refusal(&executor, &refusal_row("/etc/x/sshd_config"))
            .await
            .is_none(),
        "the control: a path inside the allowlist with nothing wrong with it is \
         admitted, or a guard that refused everything would satisfy the three \
         assertions above"
    );
}

/// A symlink is judged by where it lands, in both directions.
///
/// The out-of-bounds half already had a test. The in-bounds half did not, and
/// without it the `within` guard on the resolved target can be forced to `false`
/// with nothing going red: every symlinked row would then be refused, including
/// the ones a rollback exists to restore, and the failure mode is a rollback
/// that silently does nothing rather than one that writes somewhere wrong.
#[tokio::test]
async fn a_symlink_resolving_inside_the_allowlist_is_still_restorable() {
    let manager = test_manager_with_etc_x().await;
    let path = "/etc/x/sshd_config";

    let inside = MockExecutor::new().with_symlink(path, "/etc/x/sshd_config.real");
    assert!(
        manager
            .rollback_target_refusal(&inside, &refusal_row(path))
            .await
            .is_none(),
        "a link whose target is inside the allowlist lands inside it, so the \
         write is as safe as writing the path directly"
    );

    let outside = MockExecutor::new().with_symlink(path, "/usr/lib/systemd/system/sshd.service");
    let refusal = manager
        .rollback_target_refusal(&outside, &refusal_row(path))
        .await;
    assert!(
        refusal
            .as_deref()
            .is_some_and(|reason| reason.contains("resolves outside")),
        "and the other direction is refused for resolving out of bounds, not \
         for some other reason: {refusal:?}"
    );
}

/// Verification must read the stored bytes, not merely find the checkpoint.
///
/// `verify_checkpoint` exists to answer whether a checkpoint has been tampered
/// with, and every caller treats `Ok(())` as "safe to restore". A body that
/// returns `Ok(())` regardless is indistinguishable from a working one unless a
/// test actually corrupts a stored row, so the tamper is the test: nothing else
/// can tell the two apart.
#[tokio::test]
async fn a_checkpoint_whose_stored_content_was_altered_fails_verification() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pool = crate::db::init_db(Some(&dir.path().join("verify.db")))
        .await
        .expect("init_db");
    let signer = CheckpointSigner::new_with_path(&dir.path().join("test.key")).expect("signer");
    let manager =
        CheckpointManager::new_with_allowlist(pool.clone(), signer, vec!["/etc/x".to_string()])
            .expect("manager");

    let path = "/etc/x/sshd_config";
    let executor = MockExecutor::new().with_file(path, "PermitRootLogin no\n");
    let id = manager
        .create_checkpoint(&executor, "verify", &[Path::new(path)])
        .await
        .expect("create_checkpoint");

    manager
        .verify_checkpoint(&id)
        .await
        .expect("the control: an untouched checkpoint verifies");

    let altered = sqlx::query("UPDATE file_states SET content = ? WHERE checkpoint_id = ?")
        .bind(b"PermitRootLogin yes\n".to_vec())
        .bind(id.as_str())
        .execute(&pool)
        .await
        .expect("tamper with the stored row");
    assert_eq!(
        altered.rows_affected(),
        1,
        "the tamper must actually land, or the refusal below proves nothing"
    );

    manager.verify_checkpoint(&id).await.expect_err(
        "altered content must fail verification, since every caller reads Ok as safe to restore",
    );
}

/// The pre-rollback snapshot does not try to read a path that is no longer a
/// file.
///
/// The guard is `exists && is_file`, and it decides whether the content is read,
/// not whether the path is recorded: a directory standing where a file was
/// still produces a row, carrying no content. As `||` the guard admits the
/// directory, `read_file` is called on it, and the whole snapshot fails, so a
/// rollback whose own safety net could not be taken refuses to proceed.
///
/// Both halves are asserted because either alone is satisfiable by the wrong
/// code: that the call succeeds, and that the row it wrote holds no content.
#[tokio::test]
async fn the_pre_rollback_snapshot_does_not_read_a_directory_standing_where_a_file_was() {
    let manager = test_manager_with_etc_x().await;
    let path = "/etc/x/sshd_config";
    let executor = MockExecutor::new().with_directory(path);

    let id = manager
        .snapshot_current_state(&executor, "pre-rollback", &[refusal_row(path)])
        .await
        .expect("a directory where a file was recorded is recorded, not read");

    let (_, file_states) = manager
        .get_checkpoint(&id)
        .await
        .expect("the snapshot checkpoint exists");
    let row = file_states
        .iter()
        .find(|state| state.file_path == path)
        .expect("the path is still recorded, since it is there");
    assert!(
        row.file_content.is_none(),
        "a directory has no content to snapshot, and a row claiming otherwise \
         would be restored over it: {row:?}"
    );
}

/// A refusal that printed nothing is still described, by its exit status.
///
/// The two arms are the whole point of the function: a command that failed
/// silently and one that explained itself must both produce a description a
/// caller can show. Collapsing the silent arm leaves the message ending in
/// nothing at all, which puts the caller back where it started.
#[tokio::test]
async fn a_silent_command_failure_is_described_by_its_exit_status() {
    use hardener_common::executor::CommandOutput;

    let failing = |stderr: &str, exit_code: i32| {
        MockExecutor::new().with_command_program(
            "chmod",
            CommandOutput {
                stdout: String::new(),
                stderr: stderr.to_string(),
                exit_code,
            },
        )
    };
    let silent = failing("   \n", 2);
    let described = restore_command_refusal(&silent, "chmod", &["0644", "/etc/x/f"], "/etc/x/f")
        .await
        .expect("a non-zero exit is a refusal");
    assert!(
        described.contains("exited 2"),
        "a failure with nothing on stderr must be named by its status: {described}"
    );

    let noisy = failing("chmod: Operation not permitted", 1);
    let described = restore_command_refusal(&noisy, "chmod", &["0644", "/etc/x/f"], "/etc/x/f")
        .await
        .expect("a non-zero exit is a refusal");
    assert!(
        described.contains("Operation not permitted"),
        "and one that explained itself keeps its own words: {described}"
    );
    assert!(
        !described.contains("exited 1"),
        "without the status crowding out the explanation: {described}"
    );

    let succeeding = MockExecutor::new().with_command_program(
        "chmod",
        CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
    );
    assert!(
        restore_command_refusal(&succeeding, "chmod", &["0644", "/etc/x/f"], "/etc/x/f")
            .await
            .is_none(),
        "the control: a command that worked is not a refusal"
    );
}
