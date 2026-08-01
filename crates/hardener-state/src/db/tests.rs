#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`db`].
//!
//! Split out of `db.rs`. This file sits in the `db/` directory
//! beside it, so `super` still resolves to `crate::db` and every
//! import carried across unchanged, private items included.

use super::*;

#[tokio::test]
async fn checkpoints_pool_uses_wal_journal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pool = init_db(Some(&dir.path().join("checkpoints.db")))
        .await
        .expect("init checkpoints db");
    let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&pool)
        .await
        .expect("journal_mode pragma");
    assert_eq!(
        mode.to_lowercase(),
        "wal",
        "checkpoints pool must use WAL for concurrent batch capture"
    );
}

#[tokio::test]
async fn init_db_migrates_legacy_checkpoints_without_host_key() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("legacy.db");
    let opts = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&db)
        .create_if_missing(true);
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(opts)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE checkpoints (id TEXT PRIMARY KEY, name TEXT NOT NULL, \
         timestamp INTEGER NOT NULL, username TEXT NOT NULL, signature BLOB NOT NULL, \
         created_at INTEGER NOT NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO checkpoints VALUES ('cp1','n',0,'u',x'00',0)")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let pool = init_db(Some(&db)).await.unwrap();
    let host_key: String = sqlx::query_scalar("SELECT host_key FROM checkpoints WHERE id='cp1'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(host_key, "local");
}
