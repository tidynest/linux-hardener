//! Database operations for checkpoint storage.
//!
//! Uses SQLite to store checkpoint metadata and file states.

use hardener_common::error::{HardeningError, Result};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePool, SqlitePoolOptions,
};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default location for the checkpoint database.
const DEFAULT_DB_PATH: &str = "/var/lib/linux-hardener/checkpoints.db";

/// SQL schema for the checkpoint database.
const SCHEMA: &str = r#"
    CREATE TABLE IF NOT EXISTS checkpoints (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        username TEXT NOT NULL,
        signature BLOB NOT NULL,
        created_at INTEGER NOT NULL,
        host_key TEXT NOT NULL DEFAULT 'local'
    );

    CREATE TABLE IF NOT EXISTS file_states (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        checkpoint_id TEXT NOT NULL,
        file_path TEXT NOT NULL,
        content BLOB,
        permissions INTEGER,
        owner_uid INTEGER,
        owner_gid INTEGER,
        link_target TEXT,
        content_absence TEXT,
        FOREIGN KEY(checkpoint_id) REFERENCES checkpoints(id)
    );

    CREATE INDEX IF NOT EXISTS idx_checkpoint_timestamp ON checkpoints(timestamp);
    CREATE INDEX IF NOT EXISTS idx_file_states_checkpoint ON file_states(checkpoint_id);

    -- GUI scan history tables (separate from CLI, which remains stateless)
    CREATE TABLE IF NOT EXISTS scan_sessions (
        id TEXT PRIMARY KEY,
        started_at INTEGER NOT NULL,
        completed_at INTEGER,
        total_findings INTEGER NOT NULL DEFAULT 0,
        total_plugins INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'running'
    );

    CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        plugin_id TEXT NOT NULL,
        success INTEGER NOT NULL,
        duration_us INTEGER NOT NULL,
        error_message TEXT,
        unchecked_json TEXT,
        FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS scan_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        result_id INTEGER NOT NULL,
        finding_id TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        explanation TEXT NOT NULL,
        impact TEXT NOT NULL,
        current_value TEXT NOT NULL,
        recommended_value TEXT NOT NULL,
        remediation_steps TEXT NOT NULL,
        compliance_mappings TEXT NOT NULL,
        policy_exception TEXT,
        exception_key TEXT,
        exception_declined TEXT,
        FOREIGN KEY(result_id) REFERENCES scan_results(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_scan_sessions_started ON scan_sessions(started_at DESC);
    CREATE INDEX IF NOT EXISTS idx_scan_results_session ON scan_results(session_id);
    CREATE INDEX IF NOT EXISTS idx_scan_findings_result ON scan_findings(result_id);
    "#;

/// Adds `column` to `table` when it is not already there.
///
/// Every column reaching this is nullable or carries a default, so a row
/// written before it existed reads back as the absent value rather than making
/// the database unreadable.
///
/// `table`, `column` and `ddl` are formatted into the statement rather than
/// bound, because SQLite does not accept a bound identifier in DDL. The sole
/// caller passes them from [`MIGRATIONS`], whose entries are string literals,
/// and this function is private to the module, so no operator input reaches it.
///
/// The check and the act are only safe together, so this takes a connection
/// rather than a pool: [`apply_migrations`] holds the write lock around it, and
/// a pool would be free to run the two statements on different connections.
async fn add_column_if_missing(
    conn: &mut SqliteConnection,
    table: &str,
    column: &str,
    ddl: &str,
) -> Result<()> {
    let present: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = '{column}'"
    ))
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| HardeningError::Database(e.to_string()))?;

    if present == 0 {
        sqlx::query(&format!("ALTER TABLE {table} ADD COLUMN {ddl}"))
            .execute(&mut *conn)
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))?;
    }

    Ok(())
}

/// Applies every entry in [`MIGRATIONS`] under one write lock.
///
/// `BEGIN IMMEDIATE` takes that lock before the first `pragma_table_info` read
/// rather than at the first write, which is what closes the gap between
/// deciding a column is absent and adding it. Without it, two processes opening
/// the same database on the first run after an upgrade could both read the
/// column as absent and both attempt the `ALTER TABLE`, and the loser refused to
/// open the database at all with `duplicate column name`. A plain `BEGIN` is
/// deferred in SQLite and would leave exactly that gap open.
///
/// The whole set runs inside one transaction, so a database is never left
/// carrying some of an upgrade's columns and not the rest.
///
/// The set is a parameter rather than [`MIGRATIONS`] read directly, so that the
/// rollback can be tested: it needs a migration that fails, and every real one
/// succeeds.
async fn apply_migrations(pool: &SqlitePool, migrations: &[Migration]) -> Result<()> {
    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *conn)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

    let mut applied = Ok(());
    for migration in migrations {
        applied =
            add_column_if_missing(&mut conn, migration.table, migration.column, migration.ddl)
                .await;
        if applied.is_err() {
            break;
        }
    }

    // The closing statement runs whichever way the loop went, so a failed
    // migration releases the lock rather than holding it until the pool drops.
    let closing = if applied.is_ok() {
        "COMMIT"
    } else {
        "ROLLBACK"
    };
    sqlx::query(closing)
        .execute(&mut *conn)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

    applied
}

/// One column added to a table that predates it.
///
/// A table rather than a run of calls, so a test can enumerate the migrations
/// instead of naming them. Adding a sixth entry here puts it under
/// `every_migration_restores_its_column` immediately, with nobody having
/// written a case for it, which is the only kind of case that gets missed.
struct Migration {
    /// Table the column belongs to.
    table: &'static str,
    /// Column name, spelled as `pragma_table_info` reports it.
    column: &'static str,
    /// The fragment following `ALTER TABLE <table> ADD COLUMN`.
    ///
    /// It repeats `column` because SQLite needs the name inside the DDL too. A
    /// disagreement between the two is caught by `test_init_db_idempotent`: the
    /// guard would keep reading the column as absent and the second
    /// `ALTER TABLE` would fail as a duplicate.
    ddl: &'static str,
    /// What a row written before the column existed reads back as, where `None`
    /// is SQL NULL.
    ///
    /// The migration itself has no use for this. It records the promise each
    /// comment below makes in a form the enumerating test can check, so that a
    /// migration which silently changes what an old row means fails rather than
    /// passing on the column merely existing.
    #[cfg_attr(not(test), allow(dead_code))]
    absent: Option<&'static str>,
}

/// Every in-place column migration, applied in order by [`init_db`].
const MIGRATIONS: &[Migration] = &[
    // A checkpoint database written before host keys existed belongs to the
    // machine it sits on, which is what the default records.
    Migration {
        table: "checkpoints",
        column: "host_key",
        ddl: "host_key TEXT NOT NULL DEFAULT 'local'",
        absent: Some("local"),
    },
    // A scan result written before this column existed recorded no unchecked
    // checks, and NULL reads back as exactly that.
    Migration {
        table: "scan_results",
        column: "unchecked_json",
        ddl: "unchecked_json TEXT",
        absent: None,
    },
    // A scan result written before this column existed ran its plugin, and
    // NULL reads back as exactly that: not skipped. A row that did not run
    // stores the reason here instead, so a session read back from history
    // can say why a plugin is absent rather than infer it.
    Migration {
        table: "scan_results",
        column: "skipped_reason",
        ddl: "skipped_reason TEXT",
        absent: None,
    },
    // A checkpoint taken before this column existed leaves it NULL, which
    // reads back as "not a symlink" and restores exactly as it did before, so
    // an existing checkpoint keeps working rather than becoming unreadable.
    Migration {
        table: "file_states",
        column: "link_target",
        ddl: "link_target TEXT",
        absent: None,
    },
    // A checkpoint taken before this column existed leaves it NULL, which
    // reads back as "not recorded" rather than as either answer, because such
    // a row genuinely cannot say whether its missing content was deliberate or
    // the result of a read it could not make.
    Migration {
        table: "file_states",
        column: "content_absence",
        ddl: "content_absence TEXT",
        absent: None,
    },
    // A finding stored before this column existed carries no key, and NULL
    // reads back as exactly that. It is indistinguishable from a finding an
    // exception could not be about, and needs to be: both mean there is no
    // offer to make, and a rescan replaces the row.
    Migration {
        table: "scan_findings",
        column: "exception_key",
        ddl: "exception_key TEXT",
        absent: None,
    },
    // A finding stored before this column existed carries no declined
    // exception, and NULL reads back as exactly that: NotConfigured. That is
    // the honest reading, because nothing at the time could have recorded a
    // decline, and a rescan replaces the row.
    Migration {
        table: "scan_findings",
        column: "exception_declined",
        ddl: "exception_declined TEXT",
        absent: None,
    },
];

/// Initialises the database connection pool.
///
/// Creates the database file if it doesn't exist and applies the schema.
///
/// # Arguments
/// * `db_path` - Optional custom database path. Uses DEFAULT_DB_PATH if None.
///
/// # Errors
/// Returns an error if the database cannot be created or connected to.
pub async fn init_db(db_path: Option<&Path>) -> Result<SqlitePool> {
    let path = db_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DB_PATH));

    // Create parent directory if it doesn't exist (idempotent)
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(HardeningError::System)?;
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        let _ = std::fs::set_permissions(parent, perms);
    }

    // Configure SQLite connection
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .busy_timeout(Duration::from_secs(5))
        .journal_mode(SqliteJournalMode::Wal);

    // Create connection pool
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

    // Execute schema to create tables
    sqlx::query(SCHEMA)
        .execute(&pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

    // Bring a database written by an earlier release up to the schema above.
    // Each entry says what an old row reads back as; see [`MIGRATIONS`].
    apply_migrations(&pool, MIGRATIONS).await?;

    // Foreign key enforcement
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

    // Restrict DB file permissions after creation
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(&path, Permissions::from_mode(0o600))
        .map_err(HardeningError::System)?;

    Ok(pool)
}

#[cfg(test)]
mod tests;
