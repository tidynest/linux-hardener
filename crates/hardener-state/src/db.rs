//! Database operations for checkpoint storage.
//!
//! Uses SQLite to store checkpoint metadata and file states.

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
        checkpoint_id TEXT NOT NULL,
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
