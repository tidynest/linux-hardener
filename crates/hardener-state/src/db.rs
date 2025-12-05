//! Database operations for checkpoint storage.
//!
//! Use SQLite to store checkpoint metadata and file states.

use hardener_common::error::{HardeningError, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::path::{Path, PathBuf};

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
        FOREIGN KEY(result_id) REFERENCES scan_results(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_scan_sessions_started ON scan_sessions(started_at DESC);
    CREATE INDEX IF NOT EXISTS idx_scan_results_session ON scan_results(session_id);
    CREATE INDEX IF NOT EXISTS idx_scan_findings_result ON scan_findings(result_id);
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
        std::fs::create_dir_all(parent).map_err(HardeningError::System)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_init_db_creates_database() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let pool = init_db(Some(&db_path)).await.unwrap();

        assert!(db_path.exists());

        // Verify tables exist by querying them
        let result: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM checkpoints")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(result.0, 0);

        let result: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM file_states")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(result.0, 0);

        pool.close().await;
    }

    #[tokio::test]
    async fn test_init_db_creates_parent_directory() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("subdir").join("nested").join("test.db");

        let pool = init_db(Some(&db_path)).await.unwrap();

        assert!(db_path.exists());
        assert!(db_path.parent().unwrap().exists());

        pool.close().await;
    }

    #[tokio::test]
    async fn test_init_db_idempotent() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        // Initialize twice - should not fail
        let pool1 = init_db(Some(&db_path)).await.unwrap();
        pool1.close().await;

        let pool2 = init_db(Some(&db_path)).await.unwrap();
        pool2.close().await;
    }

    #[tokio::test]
    async fn test_init_db_schema_tables_exist() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let pool = init_db(Some(&db_path)).await.unwrap();

        // Test checkpoints table structure by inserting a row
        let result = sqlx::query(
            "INSERT INTO checkpoints (id, name, timestamp, username, signature, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind("test-id")
        .bind("test checkpoint")
        .bind(1234567890_i64)
        .bind("testuser")
        .bind(vec![0u8; 64])
        .bind(1234567890_i64)
        .execute(&pool)
        .await;

        assert!(result.is_ok());

        pool.close().await;
    }
}
