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
