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
