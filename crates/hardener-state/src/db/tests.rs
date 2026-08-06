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

/// A pool on a fresh file with no schema applied.
///
/// `init_db` is deliberately not used: these tests are about the state of a
/// database that predates it.
///
/// Foreign keys are off, which is SQLite's own default and not sqlx's. These
/// tests write single rows that reference nothing, and the parent row a real
/// insert would need says nothing about the migration under test.
async fn bare_pool(path: &std::path::Path) -> sqlx::SqlitePool {
    let opts = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .foreign_keys(false);
    sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(opts)
        .await
        .expect("open a bare pool")
}

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
    let pool = bare_pool(&db).await;
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

#[tokio::test]
async fn add_column_if_missing_adds_a_column_that_is_absent() {
    let dir = tempfile::tempdir().unwrap();
    let pool = bare_pool(&dir.path().join("t.db")).await;
    sqlx::query("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        .execute(&pool)
        .await
        .unwrap();

    add_column_if_missing(&pool, "t", "added", "added TEXT")
        .await
        .expect("adding an absent column");

    let present: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pragma_table_info('t') WHERE name = 'added'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(present, 1, "the column must exist after the call");
}

#[tokio::test]
async fn add_column_if_missing_leaves_an_existing_column_alone() {
    let dir = tempfile::tempdir().unwrap();
    let pool = bare_pool(&dir.path().join("t.db")).await;
    sqlx::query("CREATE TABLE t (id INTEGER PRIMARY KEY, added TEXT)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO t VALUES (1, 'kept')")
        .execute(&pool)
        .await
        .unwrap();

    add_column_if_missing(&pool, "t", "added", "added TEXT")
        .await
        .expect("a second call must not error");

    let value: String = sqlx::query_scalar("SELECT added FROM t WHERE id = 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(value, "kept", "an existing column must keep its data");
}

#[tokio::test]
async fn init_db_migrates_scan_findings_without_exception_key() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("legacy.db");
    let pool = bare_pool(&db).await;
    sqlx::query(
        "CREATE TABLE scan_findings (id INTEGER PRIMARY KEY AUTOINCREMENT, \
         result_id INTEGER NOT NULL, finding_id TEXT NOT NULL, category TEXT NOT NULL, \
         severity TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, \
         explanation TEXT NOT NULL, impact TEXT NOT NULL, current_value TEXT NOT NULL, \
         recommended_value TEXT NOT NULL, remediation_steps TEXT NOT NULL, \
         compliance_mappings TEXT NOT NULL, policy_exception TEXT)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO scan_findings (result_id, finding_id, category, severity, title, \
         description, explanation, impact, current_value, recommended_value, \
         remediation_steps, compliance_mappings) \
         VALUES (1,'F','kernel','high','t','d','e','i','c','r','[]','[]')",
    )
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    let pool = init_db(Some(&db))
        .await
        .expect("an old database must still open");
    let key: Option<String> =
        sqlx::query_scalar("SELECT exception_key FROM scan_findings WHERE finding_id = 'F'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        key, None,
        "a row written before the column existed reads back as no key"
    );
}

/// How many columns of `table` are named `column`.
async fn column_count(pool: &sqlx::SqlitePool, table: &str, column: &str) -> i64 {
    sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = '{column}'"
    ))
    .fetch_one(pool)
    .await
    .expect("count a column")
}

/// Inserts one row into `table`, filling in every column that demands a value.
///
/// The shape is read from the table rather than written out, because a test
/// that enumerates the migrations must not need a hand-written row per table:
/// it would then only cover the tables somebody thought of, which is the
/// weakness it exists to remove. A column that is nullable or carries a default
/// is left out, which is what makes one statement legal on any of them.
///
/// The pool must be a bare one. `init_db` turns foreign keys on, and this row
/// deliberately references nothing.
async fn insert_placeholder_row(pool: &sqlx::SqlitePool, table: &str) {
    // ponytail: assumes every table has at least one such column, which holds
    // for the whole schema. One that has none fails here as a syntax error
    // naming the table, rather than silently inserting nothing.
    let required: Vec<(String, String)> = sqlx::query_as(&format!(
        "SELECT name, type FROM pragma_table_info('{table}') \
         WHERE \"notnull\" = 1 AND dflt_value IS NULL"
    ))
    .fetch_all(pool)
    .await
    .expect("read the table shape");

    let names: Vec<&str> = required.iter().map(|(n, _)| n.as_str()).collect();
    let values: Vec<&str> = required
        .iter()
        .map(|(_, ty)| match ty.to_ascii_uppercase() {
            t if t.contains("INT") => "0",
            t if t.contains("BLOB") => "x'00'",
            _ => "'x'",
        })
        .collect();

    sqlx::query(&format!(
        "INSERT INTO {table} ({}) VALUES ({})",
        names.join(", "),
        values.join(", ")
    ))
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("insert a placeholder row into {table}: {e}"));
}

/// Every migration restores its column, and an old row reads back as the value
/// that migration promises.
///
/// The subjects come from `MIGRATIONS`, the same table `init_db` iterates, so a
/// sixth migration is covered the moment it is added and not when somebody
/// remembers to write a case. Three of the first four went untested for exactly
/// that reason: each looked obviously right, and obviously right is not a
/// property the suite can report on.
///
/// The fixture is produced rather than described. Dropping the column from a
/// current database is the state an upgrade migrates from, and reopening runs
/// the same `ALTER TABLE` a real upgrade runs.
#[tokio::test]
async fn every_migration_restores_its_column() {
    assert!(
        !MIGRATIONS.is_empty(),
        "an empty table examines no subjects, which reads exactly like finding no problems"
    );

    for migration in MIGRATIONS {
        let Migration {
            table,
            column,
            absent,
            ..
        } = *migration;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("legacy.db");

        init_db(Some(&db))
            .await
            .expect("a current database")
            .close()
            .await;

        {
            let pool = bare_pool(&db).await;
            insert_placeholder_row(&pool, table).await;
            sqlx::query(&format!("ALTER TABLE {table} DROP COLUMN {column}"))
                .execute(&pool)
                .await
                .unwrap_or_else(|e| panic!("drop {table}.{column} to age the database: {e}"));
            assert_eq!(
                column_count(&pool, table, column).await,
                0,
                "the fixture for {table}.{column} must actually lack the column"
            );
            pool.close().await;
        }

        let pool = init_db(Some(&db))
            .await
            .unwrap_or_else(|e| panic!("a database predating {table}.{column} must open: {e}"));
        assert_eq!(
            column_count(&pool, table, column).await,
            1,
            "init_db must add {table}.{column} back"
        );

        let value: Option<String> = sqlx::query_scalar(&format!("SELECT {column} FROM {table}"))
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("read {table}.{column} back: {e}"));
        assert_eq!(
            value.as_deref(),
            absent,
            "a row written before {table}.{column} existed must read back as the \
             value that migration promises"
        );
        pool.close().await;
    }
}
