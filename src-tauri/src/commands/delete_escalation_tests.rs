#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Tests for `system_database_denies` in [`commands`](super).
//!
//! The desktop's Delete falls back to a privileged `hardener checkpoint delete`
//! when the user database did not remove a row, which is right for a root-owned
//! checkpoint and wrong for an id that is in neither database: an unprivileged
//! user could raise an authentication dialog for an operation that cannot
//! succeed. The guard decides between those, and the only decisive answer is a
//! reachable system database that positively lacks the row.
//!
//! The path is a parameter rather than `get_system_db_path()` precisely so
//! these run the same way on a machine that has a system database and one that
//! does not.

use super::*;

#[tokio::test]
async fn a_system_database_that_is_not_there_is_a_definite_no() {
    let absent = std::env::temp_dir().join(format!(
        "hardener-no-such-system-db-{}/checkpoints.db",
        std::process::id()
    ));
    assert!(
        !absent.exists(),
        "the fixture path must genuinely be absent"
    );

    assert!(
        system_database_denies(&absent, &CheckpointId::new("cp_1_00000000")).await,
        "a desktop that has never run a privileged apply has no system database, \
         so the row is in neither and no prompt is warranted"
    );
}

#[tokio::test]
async fn a_system_database_that_cannot_be_read_is_not_an_answer() {
    // Present but not a database. Absence of an answer must not be treated as
    // a denial, or a root-owned checkpoint would become undeletable from the
    // desktop: anything short of a positive "not here" still escalates.
    let dir = std::env::temp_dir().join(format!("hardener-unreadable-db-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let garbage = dir.join("checkpoints.db");
    std::fs::write(&garbage, b"this is not a sqlite database").expect("the fixture is written");

    assert!(
        !system_database_denies(&garbage, &CheckpointId::new("cp_1_00000000")).await,
        "a database this process cannot read says nothing about the row, so the \
         privileged run must still get its chance to decide"
    );
}

/// The branch that made this guard dangerous, and the reason it uses
/// `try_exists` rather than `exists`.
///
/// `Path::exists` is `metadata(..).is_ok()`, so it answers `false` for a path it
/// may not stat, and the real system database sits under a root-owned directory
/// an unprivileged desktop often cannot search: this project's is `drwx------
/// root` on the maintainer's own machine. Treating that as "no such database"
/// would refuse every root-owned checkpoint instead of escalating for it, which
/// is worse than the prompt this guard removes.
///
/// A directory with no permissions reproduces it without root: stat on a path
/// inside it fails with `EACCES`, exactly as it does for `/var/lib`.
#[tokio::test]
async fn a_database_that_cannot_even_be_stated_is_not_a_definite_no() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("hardener-unstatable-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let inside = dir.join("checkpoints.db");
    std::fs::write(&inside, b"present but unreachable").expect("the fixture is written");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000))
        .expect("the directory is closed");

    let unstatable = inside.try_exists().is_err();
    let denies = system_database_denies(&inside, &CheckpointId::new("cp_1_00000000")).await;

    // Restore before asserting, so a failure does not leave an unreadable
    // directory behind for the next run of this test.
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        unstatable,
        "the fixture must actually be unstatable, or this test proves nothing; \
         running as root would make it statable and this assertion says so"
    );
    assert!(
        !denies,
        "a database that cannot be stated says nothing about the row, so the \
         privileged run must still get its chance rather than the delete being \
         refused outright"
    );
}

/// The decision itself, which is what the call site acts on.
///
/// The guard's polarity was previously untested: nothing called
/// `delete_checkpoint`, so inverting its `if` compiled, passed, and both
/// reintroduced the prompt-for-a-missing-id defect and made every readable
/// root-owned checkpoint undeletable. `resolve_delete` returns the decision
/// instead of acting on it, so the branch can be exercised without `pkexec`
/// ever running, and an inversion is a failing test rather than a defect
/// nobody can reach.
#[tokio::test]
async fn neither_database_holding_the_row_resolves_to_not_found() {
    let dir = std::env::temp_dir().join(format!("hardener-resolve-none-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");

    let resolution = resolve_delete(
        &dir.join("user.db"),
        &dir.join("system.db"),
        &CheckpointId::new("cp_1_00000000"),
    )
    .await;

    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        resolution,
        DeleteResolution::NotFound,
        "with both databases absent the id is in neither, and escalating could \
         only raise an authentication prompt for an operation that must fail"
    );
}

/// The direction that matters more, because getting it wrong strands data
/// rather than merely annoying someone: a system database that cannot be
/// answered for must still reach the privileged run.
#[tokio::test]
async fn a_system_database_that_cannot_be_asked_resolves_to_needing_privilege() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("hardener-resolve-eacces-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let closed = dir.join("closed");
    std::fs::create_dir_all(&closed).expect("a closed directory");
    let system_db = closed.join("checkpoints.db");
    std::fs::write(&system_db, b"present but unreachable").expect("the fixture is written");
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000))
        .expect("the directory is closed");

    let unaskable = system_db.try_exists().is_err();
    let resolution = resolve_delete(
        &dir.join("user.db"),
        &system_db,
        &CheckpointId::new("cp_1_00000000"),
    )
    .await;

    let _ = std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        unaskable,
        "the fixture must actually be unaskable, or this test proves nothing; \
         running as root would make it readable and this assertion says so"
    );
    assert_eq!(
        resolution,
        DeleteResolution::NeedsPrivilege,
        "a root-owned checkpoint must stay deletable: when the system database \
         cannot be asked, the privileged run decides rather than the desktop \
         refusing outright"
    );
}

/// The desktop's Rollback argv, which was refused by clap rather than merely
/// carrying something useless.
///
/// `--config` was appended after the `--` that shields the checkpoint id, so
/// the CLI saw a second positional and exited 2 with "unexpected argument"
/// before doing anything. Every rollback from the desktop failed that way for
/// an operator who had set a config file, and the desktop then reported a
/// parse failure rather than the reason.
#[test]
fn the_rollback_argv_ends_at_the_checkpoint_id() {
    let args = rollback_args("cp_1_00000000");

    assert_eq!(
        args,
        vec!["rollback", "--format", "json", "--", "cp_1_00000000"],
        "the id is last and behind the separator, so nothing can be appended \
         after it without becoming a positional the command does not take"
    );
    assert!(
        !args.contains(&"--config"),
        "`rollback` restores captured files and consults no policy, so there is \
         no configuration for a config path to decide"
    );
}

/// The checkpoint list had the same blind spot the delete guard shed:
/// `Path::exists` is `metadata(..).is_ok()`, so a database under a directory
/// this process may not search read as "not there". A list silently missing
/// every privileged checkpoint then looks exactly like a host that has none.
#[tokio::test]
async fn a_database_that_is_not_there_is_told_apart_from_one_that_cannot_be_read() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("hardener-reach-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");

    let mut entries = Vec::new();
    let absent = collect_checkpoints(&dir.join("no-such.db"), &mut entries).await;

    let closed = dir.join("closed");
    std::fs::create_dir_all(&closed).expect("a closed directory");
    let hidden = closed.join("checkpoints.db");
    std::fs::write(&hidden, b"present but unreachable").expect("the fixture is written");
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000))
        .expect("the directory is closed");
    let unstatable = hidden.try_exists().is_err();
    let unreadable = collect_checkpoints(&hidden, &mut entries).await;

    let _ = std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        absent,
        DatabaseReach::Absent,
        "a database that is genuinely not there leaves nothing out of the list"
    );
    assert!(
        unstatable,
        "the fixture must actually be unstatable, or the case below is not the \
         one this test is about; running as root would make it statable"
    );
    assert_eq!(
        unreadable,
        DatabaseReach::Unreadable,
        "a database that cannot be reached may hold rows this list cannot show, \
         which is a different answer from having none and is worth reporting"
    );
    assert!(entries.is_empty(), "neither case invents a checkpoint");
}

/// The de-duplication the merged list rests on, which decides what the operator
/// is shown when one id is reachable through both databases at once.
///
/// The two are not disjoint. A privileged run writes into the system database
/// while the desktop writes into the user's own, and the same rows land in both
/// whenever a database is copied between hosts or a privileged run is pointed
/// at the user's path, so this guard is the only thing standing between the
/// operator and the same checkpoint offered to them twice. Which copy survives
/// is load-bearing rather than cosmetic: the manager kept beside the row is the
/// one `get_checkpoints` asks for the verification flag and the one a later
/// operation goes through, and the two databases are signed by different keys.
///
/// One id in two databases cannot be built through the public API, which
/// generates a fresh id per write, so the fixture copies the database instead.
/// The signing key is not copied with it: each directory keeps a key of its
/// own, exactly as `/etc/linux-hardener` and the user's data directory do on a
/// real host, and a row that verifies under one of them and not the other is
/// the only thing that makes the surviving pairing observable at all.
#[tokio::test]
async fn a_checkpoint_in_both_databases_is_listed_once_and_by_the_first_of_them() {
    use hardener_core::LocalExecutor;

    let root = std::env::temp_dir().join(format!("hardener-duplicate-id-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let first = root.join("first");
    let second = root.join("second");
    let first_db = first.join("checkpoints.db");
    let second_db = second.join("checkpoints.db");

    // The pool is opened here rather than through `create_checkpoint_manager`
    // so that the copy below can be taken with the only writer known to be
    // open and idle, and so that it can be closed before the merge reopens the
    // same file.
    let pool = init_db(Some(first_db.as_path()))
        .await
        .expect("the first database is created");
    let signer = CheckpointSigner::new_with_path(&first.join("signing.key"))
        .expect("the first database gets a signing key beside it");
    let manager = CheckpointManager::new_with_signer(pool.clone(), signer)
        .expect("a manager over the first database");
    // No paths to capture, because the row itself is the whole fixture: this
    // test is about which copy of it survives the merge, not about what it
    // holds.
    let checkpoint_id = manager
        .create_checkpoint(&LocalExecutor::new(), "reachable through both", &[])
        .await
        .expect("a checkpoint is written");

    // The database journals ahead of itself, so a freshly written row usually
    // still lives in the log beside it and the database file alone is a copy of
    // an empty one. Both are taken, and taken here, while the connection that
    // wrote them sits idle: nothing can fold one into the other between the two
    // copies, so the pair the copy receives is the pair the original has. A
    // closed pool would be tidier and is not reliable, since its connections
    // are closed on threads of their own and the log is folded back whenever
    // the last of them happens to get there.
    std::fs::create_dir_all(&second).expect("a scratch directory for the copy");
    std::fs::copy(&first_db, &second_db).expect("the database is copied");
    let log = std::path::PathBuf::from(format!("{}-wal", first_db.display()));
    if log.exists() {
        std::fs::copy(
            &log,
            std::path::PathBuf::from(format!("{}-wal", second_db.display())),
        )
        .expect("the log beside it is copied too");
    }

    drop(manager);
    pool.close().await;

    let mut entries = Vec::new();
    let first_reach = collect_checkpoints(&first_db, &mut entries).await;
    let second_reach = collect_checkpoints(&second_db, &mut entries).await;

    // Opening the copy on its own answers the question the merged list cannot:
    // whether there was ever a duplicate to collapse.
    let copy = create_checkpoint_manager(&second_db)
        .await
        .expect("the copy opens");
    let listed_by_the_copy = copy
        .list_checkpoints()
        .await
        .expect("the copy lists its own rows");
    let copy_holds_only_the_shared_id = listed_by_the_copy.len() == 1
        && listed_by_the_copy[0].checkpoint_id.as_str() == checkpoint_id.as_str();

    let verified_by_the_survivor = match entries.first() {
        Some((_, manager)) => manager.verify_checkpoint(&checkpoint_id).await.is_ok(),
        None => false,
    };
    let verified_by_the_copy = copy.verify_checkpoint(&checkpoint_id).await.is_ok();

    // Restored before asserting, so a failure leaves no scratch database behind
    // for the next run to inherit.
    drop(copy);
    let _ = std::fs::remove_dir_all(&root);

    assert_eq!(
        (first_reach, second_reach),
        (DatabaseReach::Read, DatabaseReach::Read),
        "both databases must have been opened and listed, or a short list would \
         be measuring an unreadable fixture rather than the de-duplication"
    );
    assert!(
        copy_holds_only_the_shared_id,
        "the control the count below rests on: the copy has to hold that same \
         id and nothing else, since one surviving entry proves nothing at all \
         about de-duplicating a duplicate that was never there"
    );
    assert_eq!(
        entries.len(),
        1,
        "the id is reachable through both databases and the operator has one \
         checkpoint, so the list carries one row rather than the same \
         checkpoint offered to them twice"
    );
    assert!(
        verified_by_the_survivor,
        "the row that survives keeps the first database's manager, which is the \
         only one whose key signed it; the merge consults the user database \
         first, and a row paired with the wrong manager is reported unverified \
         and acted on in the wrong place"
    );
    assert!(
        !verified_by_the_copy,
        "and the copy's own manager genuinely cannot verify it, or the \
         assertion above would hold whichever database had won and would be \
         telling us nothing"
    );
}

/// The cooldown paces privileged operations, and it was armed by the guard's
/// `Drop` instead: every early return armed it, including a validation failure
/// and the delete refusal for an id that is in neither database. A stale list,
/// double-clicked, then blocked the operator's next genuine apply or rollback
/// for five seconds, having escalated nothing.
///
/// Mutates the process-wide counters, so it restores them; nothing else in this
/// binary touches them.
#[test]
fn a_run_that_escalated_nothing_does_not_pace_the_next_one() {
    use std::sync::atomic::Ordering;

    PRIVILEGED_OP_LAST_COMPLETED.store(0, Ordering::SeqCst);

    // A guard taken and dropped without a privileged subprocess running.
    drop(PrivilegedOpGuard::acquire().expect("the first acquisition succeeds"));

    let immediately_after = PrivilegedOpGuard::acquire();
    let allowed = immediately_after.is_ok();
    drop(immediately_after);

    // And the marker the privileged runner calls does still arm it.
    mark_privileged_operation_completed();
    let after_escalating = PrivilegedOpGuard::acquire();
    let refused = after_escalating.is_err();
    drop(after_escalating);

    PRIVILEGED_OP_LAST_COMPLETED.store(0, Ordering::SeqCst);

    assert!(
        allowed,
        "a run that raised no authentication prompt must not pace the next one"
    );
    assert!(
        refused,
        "while a run that did escalate still does, or the rate limit would be gone"
    );
}
