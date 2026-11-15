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

    let mut conn = pool.acquire().await.unwrap();
    add_column_if_missing(&mut conn, "t", "added", "added TEXT")
        .await
        .expect("adding an absent column");
    drop(conn);

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

    let mut conn = pool.acquire().await.unwrap();
    add_column_if_missing(&mut conn, "t", "added", "added TEXT")
        .await
        .expect("a second call must not error");
    drop(conn);

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

/// A migration that fails takes the ones before it back out with it.
///
/// Every real migration succeeds, so the rollback branch has no subject among
/// them and the set is passed in. The second entry is refused by SQLite itself:
/// `ADD COLUMN` cannot introduce a `NOT NULL` column with no default, because
/// every existing row would violate it on the spot.
#[tokio::test]
async fn a_failed_migration_leaves_no_column_behind() {
    let dir = tempfile::tempdir().unwrap();
    let pool = bare_pool(&dir.path().join("partial.db")).await;
    sqlx::query("CREATE TABLE t (id INTEGER PRIMARY KEY, existing TEXT)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO t VALUES (1, 'row')")
        .execute(&pool)
        .await
        .unwrap();

    let broken = &[
        Migration {
            table: "t",
            column: "first",
            ddl: "first TEXT",
            absent: None,
        },
        Migration {
            table: "t",
            column: "second",
            ddl: "second TEXT NOT NULL",
            absent: None,
        },
    ];

    apply_migrations(&pool, broken)
        .await
        .expect_err("a column SQLite refuses to add must fail the set");

    assert_eq!(
        column_count(&pool, "t", "first").await,
        0,
        "a migration that succeeded before the failure must come back out with it, \
         or an upgrade leaves a database carrying some of its columns and not the rest"
    );
}

/// Two processes opening one database at once cannot both attempt the same
/// migration.
///
/// The interleaving is forced rather than hoped for. A second connection takes
/// the write lock and holds it, which in WAL mode leaves reads free, so a check
/// that is not itself inside that lock reads the column as absent, waits for the
/// lock to add it, and finds somebody else already did. The sleep only buys the
/// racing opener time to reach that read, which is to say it only ever helps the
/// test fail on code that has the gap. Code that takes the lock before reading
/// is blocked for the whole wait and cannot observe the stale answer at all, so
/// nothing about it passing depends on timing.
#[tokio::test]
async fn two_openers_cannot_both_attempt_one_migration() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("legacy.db");
    let migration = MIGRATIONS.last().expect("a migration to race over");

    init_db(Some(&db))
        .await
        .expect("a current database")
        .close()
        .await;

    {
        let pool = bare_pool(&db).await;
        sqlx::query(&format!(
            "ALTER TABLE {} DROP COLUMN {}",
            migration.table, migration.column
        ))
        .execute(&pool)
        .await
        .expect("age the database past the column");
        pool.close().await;
    }

    // The other process, holding the write lock across its own check and act.
    let holder_pool = bare_pool(&db).await;
    let mut holder = holder_pool.acquire().await.expect("a held connection");
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *holder)
        .await
        .expect("take the write lock");

    let racing = {
        let db = db.clone();
        tokio::spawn(async move { init_db(Some(&db)).await.map(|_| ()) })
    };
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    sqlx::query(&format!(
        "ALTER TABLE {} ADD COLUMN {}",
        migration.table, migration.ddl
    ))
    .execute(&mut *holder)
    .await
    .expect("the other process adds the column");
    sqlx::query("COMMIT")
        .execute(&mut *holder)
        .await
        .expect("the other process commits");
    drop(holder);
    holder_pool.close().await;

    racing
        .await
        .expect("the racing task ran to completion")
        .expect(
            "an opener that lost the race must still open the database rather than \
             refusing it with a duplicate column",
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

// ---------------------------------------------------------------------------
// A database written by the SQLite that 1.9.1 shipped
// ---------------------------------------------------------------------------
//
// The checkpoint database is the only copy of the files rollback restores, so
// a SQLite upgrade that misread a file an older release wrote would take
// rollback away with it, possibly on a host where a bad SSH or PAM change has
// already locked the operator out. Every other test in this file builds its
// database with whatever SQLite this build links, which can never notice that.
//
// The fixtures under `tests/fixtures/` were written once, on 2026-11-15, by
// hardener-state at ccc62e6 (sqlx 0.8.6, libsqlite3-sys 0.30.1, bundled SQLite
// 3.46.0): `init_db` on a fresh path, then [`insert_engine_fixture_rows`].
// `engine-1.9.1.db` was copied after the pool closed, so SQLite had already
// folded the write-ahead log into it. `engine-1.9.1-wal.db` and its `-wal` were
// copied while the pool was still open, so the rows live only in the log, the
// state a killed process leaves behind, and reading them goes through the WAL
// frame reader that RUSTSEC-2026-0459 is about (#188).
//
// Never regenerate them with a newer SQLite: they are worth something only
// because a different engine wrote them.

/// The checkpoint the fixtures hold.
const FIXTURE_CHECKPOINT_ID: &str = "5d2c1a8e-1880-4c1b-9a59-0459c0de0188";
const FIXTURE_TIMESTAMP: i64 = 1_794_700_000;
const FIXTURE_SSHD_CONFIG: &str = "# Written by the engine fixture\n\
    Include /etc/ssh/sshd_config.d/*.conf\n\
    PermitRootLogin prohibit-password\n\
    PasswordAuthentication no\n\
    KbdInteractiveAuthentication no\n\
    UsePAM yes\n";
/// Long enough to spill onto overflow pages at the default 4096-byte page.
const FIXTURE_LARGE_LEN: usize = 12_000;

/// The large file's bytes: every value of a byte, in an order no page
/// boundary lines up with.
fn fixture_large_content() -> Vec<u8> {
    (0..FIXTURE_LARGE_LEN)
        .map(|i| ((i * 31 + 7) % 251) as u8)
        .collect()
}

/// `(file_path, content, permissions)` of each file state, in insertion order.
/// The third records a path that was absent at capture time, as capture does:
/// no content and permissions 0.
fn fixture_file_states() -> Vec<(&'static str, Option<Vec<u8>>, i64)> {
    vec![
        (
            "/etc/ssh/sshd_config",
            Some(FIXTURE_SSHD_CONFIG.as_bytes().to_vec()),
            0o600,
        ),
        (
            "/var/lib/fixture/large.bin",
            Some(fixture_large_content()),
            0o644,
        ),
        ("/etc/ssh/sshd_config.d/10-absent.conf", None, 0),
    ]
}

/// The rows the fixtures were written with. Kept here, and run against this
/// build's own SQLite by `engine_fixture_rows_read_back_on_this_engine`, so the
/// recipe and the checks below cannot drift apart.
async fn insert_engine_fixture_rows(pool: &sqlx::SqlitePool) {
    let signature: Vec<u8> = (0u8..64).collect();
    sqlx::query(
        "INSERT INTO checkpoints \
         (id, name, timestamp, username, signature, created_at, host_key) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(FIXTURE_CHECKPOINT_ID)
    .bind("before ssh hardening")
    .bind(FIXTURE_TIMESTAMP)
    .bind("root")
    .bind(signature)
    .bind(FIXTURE_TIMESTAMP)
    .bind("local")
    .execute(pool)
    .await
    .expect("insert the fixture checkpoint");

    for (path, content, permissions) in fixture_file_states() {
        sqlx::query(
            "INSERT INTO file_states \
             (checkpoint_id, file_path, content, permissions, owner_uid, owner_gid) \
             VALUES (?, ?, ?, ?, 0, 0)",
        )
        .bind(FIXTURE_CHECKPOINT_ID)
        .bind(path)
        .bind(content)
        .bind(permissions)
        .execute(pool)
        .await
        .expect("insert a fixture file state");
    }
}

/// Holds `pool` to every row [`insert_engine_fixture_rows`] wrote, byte for
/// byte, and to a clean integrity check.
async fn assert_engine_fixture_rows(pool: &sqlx::SqlitePool) {
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(pool)
        .await
        .expect("run the integrity check");
    assert_eq!(integrity, "ok", "the database must pass SQLite's own check");

    let checkpoint: (String, i64, String, Vec<u8>, String) = sqlx::query_as(
        "SELECT name, timestamp, username, signature, host_key \
         FROM checkpoints WHERE id = ?",
    )
    .bind(FIXTURE_CHECKPOINT_ID)
    .fetch_one(pool)
    .await
    .expect("the fixture checkpoint must still be there");
    assert_eq!(
        checkpoint,
        (
            "before ssh hardening".to_string(),
            FIXTURE_TIMESTAMP,
            "root".to_string(),
            (0u8..64).collect::<Vec<u8>>(),
            "local".to_string(),
        ),
        "the checkpoint row must read back unchanged"
    );

    let states: Vec<(String, Option<Vec<u8>>, i64)> = sqlx::query_as(
        "SELECT file_path, content, permissions FROM file_states \
         WHERE checkpoint_id = ? ORDER BY id",
    )
    .bind(FIXTURE_CHECKPOINT_ID)
    .fetch_all(pool)
    .await
    .expect("read the fixture file states");
    let expected: Vec<(String, Option<Vec<u8>>, i64)> = fixture_file_states()
        .into_iter()
        .map(|(path, content, mode)| (path.to_string(), content, mode))
        .collect();
    assert_eq!(
        states, expected,
        "every file state, the content rollback restores included, must read \
         back byte for byte"
    );
}

/// Writes `files` (name, bytes) into a fresh directory and returns it with the
/// path of the database among them.
fn materialise_fixture(files: &[(&str, &[u8])]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    for (name, bytes) in files {
        std::fs::write(dir.path().join(name), bytes).expect("write a fixture file");
    }
    let db = dir.path().join("checkpoints.db");
    (dir, db)
}

/// Opens a fixture the way the CLI does, checks it, then writes to it and
/// checks again, since an upgraded binary goes on to add checkpoints to the
/// file an older one left.
async fn open_and_check_fixture(db: &std::path::Path) {
    let pool = init_db(Some(db))
        .await
        .expect("a database 1.9.1 wrote must open under this engine");
    assert_engine_fixture_rows(&pool).await;

    sqlx::query(
        "INSERT INTO checkpoints \
         (id, name, timestamp, username, signature, created_at, host_key) \
         VALUES ('after-the-upgrade', 'later', 1, 'root', x'00', 1, 'local')",
    )
    .execute(&pool)
    .await
    .expect("this engine must be able to write to the old file");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM checkpoints")
        .fetch_one(&pool)
        .await
        .expect("count checkpoints");
    assert_eq!(count, 2, "the old row and the new one must both be there");
    assert_engine_fixture_rows(&pool).await;
    pool.close().await;
}

#[tokio::test]
async fn engine_fixture_rows_read_back_on_this_engine() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pool = init_db(Some(&dir.path().join("checkpoints.db")))
        .await
        .expect("init a fresh database");
    insert_engine_fixture_rows(&pool).await;
    assert_engine_fixture_rows(&pool).await;
    pool.close().await;
}

/// The first 16 bytes of every SQLite database file.
const SQLITE_HEADER: &[u8] = b"SQLite format 3\0";

/// The first four bytes of a write-ahead log: the magic number, big-endian,
/// whose last bit only records the byte order of its checksums.
fn is_wal_magic(bytes: &[u8]) -> bool {
    matches!(bytes.get(..4), Some([0x37, 0x7f, 0x06, 0x82 | 0x83]))
}

#[tokio::test]
async fn a_checkpoint_database_written_by_1_9_1_reads_back() {
    let main: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/engine-1.9.1.db"
    ));
    assert!(
        main.starts_with(SQLITE_HEADER),
        "the fixture must be a SQLite database, not a placeholder"
    );

    let (_dir, db) = materialise_fixture(&[("checkpoints.db", main)]);
    open_and_check_fixture(&db).await;
}

#[tokio::test]
async fn a_write_ahead_log_left_by_1_9_1_reads_back() {
    let main: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/engine-1.9.1-wal.db"
    ));
    let log: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/engine-1.9.1-wal.db-wal"
    ));
    assert!(
        main.starts_with(SQLITE_HEADER) && is_wal_magic(log),
        "the fixture must be a SQLite database and a write-ahead log"
    );

    // The fixture is only worth its name while the rows are in the log and not
    // in the main file. Opened alone, read-only, the main file must not have
    // them, or a regenerated fixture has quietly stopped testing the log.
    let (_alone_dir, alone) = materialise_fixture(&[("checkpoints.db", main)]);
    let alone_pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&alone)
                .read_only(true),
        )
        .await
        .expect("open the main file alone");
    let rows_without_log: std::result::Result<i64, sqlx::Error> =
        sqlx::query_scalar("SELECT COUNT(*) FROM file_states")
            .fetch_one(&alone_pool)
            .await;
    assert!(
        !matches!(rows_without_log, Ok(n) if n > 0),
        "the main file alone must not hold the rows, got {rows_without_log:?}"
    );
    alone_pool.close().await;

    let (_dir, db) = materialise_fixture(&[("checkpoints.db", main), ("checkpoints.db-wal", log)]);
    open_and_check_fixture(&db).await;
}
