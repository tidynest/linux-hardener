//! Database operations for checkpoint storage.
//!
//! Use SQLite to store checkpoint metadata and file states.

use hardener_common::error::{HardeningError, Result};
use sqlx::sqlite::{
    SqliteConnectOptions,
    SqlitePool,
    SqlitePoolOptions,
};
use std::path::{
    Path,
    PathBuf,
};

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
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS file_states (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        checkpoint_id INTEGER NOT NULL,
        file_path TEXT NOT NULL,
        content BLOB,
        permissions INTEGER,
        owner_uid INTEGER,
        owner_gid INTEGER,
        FOREIGN KEY(checkpoint_id) REFERENCES checkpoints(id)
    );

    CREATE INDEX IF NOT EXISTS idx_checkpoint_timestamp ON checkpoints(timestamp);
    CREATE INDEX IF NOT EXISTS idx_file_states_checkpoint ON file_states(checkpoint_id);
    "#;

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

    // Create parent directory if it doesn't exist
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| HardeningError::System(e))?;
    }

    // Configure SQLite connection
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true);

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

    Ok(pool)
}

