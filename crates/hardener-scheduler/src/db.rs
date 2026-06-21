//! SQLite storage for scan history.
//!
//! Provides persistent storage for scheduled scan sessions, findings,
//! and notification delivery tracking.

use chrono::{DateTime, Utc};
use hardener_common::error::{HardeningError, Result};
use hardener_common::types::Severity;
use serde::{Deserialize, Serialize};
use sqlx::{
    FromRow, SqlitePool, query_as,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use std::cmp::Ordering;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

/// Manages scan history persistence in SQLite.
pub struct ScanHistoryManager {
    pool: SqlitePool,
}

impl ScanHistoryManager {
    /// Creates a new manager, initialising the database schema if needed.
    pub async fn new(db_path: &Path) -> Result<ScanHistoryManager> {
        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                HardeningError::Database(format!("Failed to create directory: {}", e))
            })?;
        }

        let db_url = format!("sqlite:{}?mode=rwc", db_path.display());
        let options = SqliteConnectOptions::from_str(&db_url)
            .map_err(|e| HardeningError::Database(e.to_string()))?
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))?;

        let manager = ScanHistoryManager { pool };
        manager.init_schema().await?;
        Ok(manager)
    }

    /// Initialises database tables if they don't exist.
    async fn init_schema(&self) -> Result<()> {
        sqlx::query(SCHEMA_SQL)
            .execute(&self.pool)
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))?;
        Ok(())
    }

    /// Creates a new scan session, returning its ID.
    pub async fn create_session(
        &self,
        trigger_type: &str,
        host: &str,
        plugins: &[String],
    ) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().timestamp();
        let plugins_json =
            serde_json::to_string(plugins).map_err(|e| HardeningError::Database(e.to_string()))?;

        sqlx::query(
            "INSERT INTO scan_sessions (id, started_at, status, trigger_type, host_identifier, plugins_scanned)
            VALUES ( ?, ?, 'running', ?, ?, ?)",
        )
        .bind(&id)
        .bind(now)
        .bind(trigger_type)
        .bind(host)
        .bind(&plugins_json)
        .execute(&self.pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

        Ok(id)
    }

    /// Marks a session as completed and stores its findings.
    pub async fn complete_session(
        &self,
        session_id: &str,
        findings: &[ScanFinding],
        json_path: Option<&str>,
        hash: Option<&str>,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let counts = SeverityCounts::from_findings(findings);

        // Update session
        sqlx::query(
            "UPDATE scan_sessions SET
                completed_at = ?, status = 'completed',
                total_findings = ?, critical_count = ?, high_count = ?,
                medium_count = ?, low_count = ?, info_count = ?,
                json_file_path = ?, hash = ?
            WHERE id = ?",
        )
        .bind(now)
        .bind(counts.total as i32)
        .bind(counts.critical as i32)
        .bind(counts.high as i32)
        .bind(counts.medium as i32)
        .bind(counts.low as i32)
        .bind(counts.info as i32)
        .bind(json_path)
        .bind(hash)
        .bind(session_id)
        .execute(&self.pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

        // Insert findings
        for finding in findings {
            self.insert_finding(session_id, finding).await?;
        }

        Ok(())
    }

    /// Marks a session as failed with an error message.
    pub async fn fail_session(&self, session_id: &str, error: &str) -> Result<()> {
        let now = Utc::now().timestamp();
        sqlx::query(
            "UPDATE scan_sessions SET completed_at = ?, status = 'failed', error_message = ?
             WHERE id = ?",
        )
        .bind(now)
        .bind(error)
        .bind(session_id)
        .execute(&self.pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;
        Ok(())
    }

    /// Retrieves a session by ID.
    pub async fn get_session(&self, session_id: &str) -> Result<Option<ScanSession>> {
        sqlx::query_as::<_, ScanSession>("SELECT * FROM scan_sessions WHERE id = ?")
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))
    }

    /// Lists sessions matching the given filter.
    pub async fn list_sessions(&self, filter: &SessionFilter) -> Result<Vec<ScanSession>> {
        let mut sql = String::from("SELECT * FROM scan_sessions WHERE 1=1");

        if filter.host.is_some() {
            sql.push_str(" AND host_identifier = ?");
        }
        if filter.status.is_some() {
            sql.push_str(" AND status = ?");
        }
        if filter.since.is_some() {
            sql.push_str(" AND started_at >= ?");
        }
        if filter.until.is_some() {
            sql.push_str(" AND started_at <= ?");
        }

        sql.push_str(" ORDER BY started_at DESC, rowid DESC");

        if filter.limit.is_some() {
            sql.push_str(" LIMIT ?");
        }

        let mut query = query_as::<_, ScanSession>(&sql);

        if let Some(ref host) = filter.host {
            query = query.bind(host);
        }
        if let Some(ref status) = filter.status {
            query = query.bind(status);
        }
        if let Some(since) = filter.since {
            query = query.bind(since.timestamp());
        }
        if let Some(until) = filter.until {
            query = query.bind(until.timestamp());
        }
        if let Some(limit) = filter.limit {
            query = query.bind(limit);
        }

        query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))
    }

    /// Returns the host's most recent completed session that is not `exclude_id`
    /// (i.e. the one before the just-completed scan), if any.
    ///
    /// Assumes the caller passes the just-completed (newest) scan as `exclude_id`:
    /// it reads only the two newest completed sessions, so "previous" is correct
    /// as long as `exclude_id` is one of them.
    pub async fn previous_completed_session(
        &self,
        host: &str,
        exclude_id: &str,
    ) -> Result<Option<ScanSession>> {
        let filter = SessionFilter {
            host: Some(host.to_string()),
            status: Some("completed".to_string()),
            limit: Some(2),
            ..Default::default()
        };
        let sessions = self.list_sessions(&filter).await?;
        Ok(sessions.into_iter().find(|s| s.id != exclude_id))
    }

    /// Retrieves findings for a session.
    pub async fn get_findings(&self, session_id: &str) -> Result<Vec<ScanFindingRow>> {
        sqlx::query_as::<_, ScanFindingRow>(
            "SELECT * FROM scan_findings WHERE session_id = ? ORDER BY id",
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))
    }

    /// Logs a notification attempt.
    pub async fn log_notification(
        &self,
        session_id: &str,
        channel: &str,
        status: &str,
        error: Option<&str>,
    ) -> Result<()> {
        let now = if status == "sent" {
            Some(Utc::now().timestamp())
        } else {
            None
        };

        sqlx::query(
            "INSERT INTO notification_log (
                session_id,
                channel,
                status,
                sent_at,
                error_message)
            VALUES (?, ?, ?, ?, ?)",
        )
        .bind(session_id)
        .bind(channel)
        .bind(status)
        .bind(now)
        .bind(error)
        .execute(&self.pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;
        Ok(())
    }

    /// Deletes sessions older than the retention period.
    /// Returns the number of deleted sessions.
    pub async fn cleanup(&self, retention_days: u32, retention_count: u32) -> Result<u32> {
        let deleted = if retention_days > 0 {
            let cutoff = Utc::now().timestamp() - (retention_days as i64 * 86400);
            sqlx::query("DELETE FROM scan_sessions WHERE started_at < ?")
                .bind(cutoff)
                .execute(&self.pool)
                .await
                .map_err(|e| HardeningError::Database(e.to_string()))?
                .rows_affected()
        } else if retention_count > 0 {
            // Keep only the most recent N sessions
            sqlx::query(
                "DELETE FROM scan_sessions WHERE id NOT IN (
                SELECT id FROM scan_sessions ORDER BY started_at DESC LIMIT ?
            )",
            )
            .bind(retention_count)
            .execute(&self.pool)
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))?
            .rows_affected()
        } else {
            0
        };

        Ok(deleted as u32)
    }

    /// Inserts a single finding into the database.
    async fn insert_finding(&self, session_id: &str, finding: &ScanFinding) -> Result<()> {
        let compliance_json = finding
            .compliance_mappings
            .as_ref()
            .map(|c| serde_json::to_string(c).unwrap_or_default());

        sqlx::query(
            "INSERT INTO scan_findings
               (session_id, plugin_id, finding_id, severity, title, description,
                current_value, recommended_value, category, compliance_mappings)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(session_id)
        .bind(&finding.plugin_id)
        .bind(&finding.finding_id)
        .bind(&finding.severity)
        .bind(&finding.title)
        .bind(&finding.description)
        .bind(&finding.current_value)
        .bind(&finding.recommended_value)
        .bind(&finding.category)
        .bind(&compliance_json)
        .execute(&self.pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;
        Ok(())
    }
}

/// SQL schema for scan history tables.
const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS scan_sessions (
    id TEXT PRIMARY KEY,
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    status TEXT NOT NULL DEFAULT 'running',
    trigger_type TEXT NOT NULL,
    host_identifier TEXT NOT NULL,
    plugins_scanned TEXT NOT NULL,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    error_message TEXT,
    json_file_path TEXT,
    hash TEXT
);

CREATE TABLE IF NOT EXISTS scan_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    current_value TEXT,
    recommended_value TEXT,
    category TEXT,
    compliance_mappings TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE
CASCADE
);

CREATE TABLE IF NOT EXISTS notification_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    status TEXT NOT NULL,
    sent_at INTEGER,
    error_message TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE
CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_started ON
    scan_sessions(started_at DESC);
    CREATE INDEX IF NOT EXISTS idx_sessions_status ON scan_sessions(status);
    CREATE INDEX IF NOT EXISTS idx_sessions_host ON
    scan_sessions(host_identifier);
    CREATE INDEX IF NOT EXISTS idx_findings_session ON
    scan_findings(session_id);
    CREATE INDEX IF NOT EXISTS idx_notifications_session ON
    notification_log(session_id);
"#;

/// A scan sessions record from the database.
#[derive(Clone, Debug, FromRow, Deserialize, Serialize)]
pub struct ScanSession {
    pub id: String,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    pub status: String,
    pub trigger_type: String,
    pub host_identifier: String,
    pub plugins_scanned: String,
    pub total_findings: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub info_count: i32,
    pub error_message: Option<String>,
    pub json_file_path: Option<String>,
    pub hash: Option<String>,
}

impl ScanSession {
    /// Severity counts as a priority-ordered tuple (critical first).
    pub fn severity_tuple(&self) -> SeverityTuple {
        (
            self.critical_count as i64,
            self.high_count as i64,
            self.medium_count as i64,
            self.low_count as i64,
            self.info_count as i64,
        )
    }

    /// Returns the session start time as a DateTime.
    pub fn started_at_utc(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.started_at, 0).unwrap_or_default()
    }

    /// Returns the session completion time as a DateTime, if completed.
    pub fn completed_at_utc(&self) -> Option<DateTime<Utc>> {
        self.completed_at
            .and_then(|ts| DateTime::from_timestamp(ts, 0))
    }

    /// Returns the list of scanned plugins.
    pub fn plugins(&self) -> Vec<String> {
        serde_json::from_str(&self.plugins_scanned).unwrap_or_default()
    }
}

/// A finding to be stored (input structure).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanFinding {
    pub plugin_id: String,
    pub finding_id: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub current_value: Option<String>,
    pub recommended_value: Option<String>,
    pub category: Option<String>,
    pub compliance_mappings: Option<Vec<String>>,
}

/// A finding row from the database.
#[derive(Clone, Debug, Deserialize, FromRow, Serialize)]
pub struct ScanFindingRow {
    pub id: i64,
    pub session_id: String,
    pub plugin_id: String,
    pub finding_id: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub current_value: Option<String>,
    pub recommended_value: Option<String>,
    pub category: Option<String>,
    pub compliance_mappings: Option<String>,
}

/// Filter criteria for querying sessions.
#[derive(Clone, Debug, Default)]
pub struct SessionFilter {
    pub host: Option<String>,
    pub status: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub limit: Option<u32>,
}

/// Severity counts for a set of findings.
#[derive(Clone, Debug, Default)]
pub struct SeverityCounts {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SeverityCounts {
    pub fn from_findings(findings: &[ScanFinding]) -> SeverityCounts {
        let mut counts = SeverityCounts {
            total: findings.len(),
            ..Default::default()
        };
        for f in findings {
            match f.severity.to_lowercase().as_str() {
                "critical" => counts.critical += 1,
                "high" => counts.high += 1,
                "medium" => counts.medium += 1,
                "low" => counts.low += 1,
                _ => counts.info += 1,
            }
        }
        counts
    }
}

/// Severity counts as a priority-ordered tuple: (critical, high, medium, low, info).
/// Lexicographic comparison of two tuples reflects security priority — a single
/// new critical outranks any number of lower-severity changes.
pub type SeverityTuple = (i64, i64, i64, i64, i64);

/// Zeroes the counts below `floor`, keeping only severities at or above it.
/// `Info` keeps everything; `Critical` keeps only the critical count.
pub fn above_floor(t: SeverityTuple, floor: Severity) -> SeverityTuple {
    let (c, h, m, l, i) = t;
    match floor {
        Severity::Critical => (c, 0, 0, 0, 0),
        Severity::High => (c, h, 0, 0, 0),
        Severity::Medium => (c, h, m, 0, 0),
        Severity::Low => (c, h, m, l, 0),
        Severity::Info => (c, h, m, l, i),
    }
}

/// Direction the posture moved between two scans, by severity priority: fewer or
/// less-severe findings is "better".
pub fn trend_direction(prev: SeverityTuple, cur: SeverityTuple) -> &'static str {
    match cur.cmp(&prev) {
        Ordering::Less => "better",
        Ordering::Greater => "worse",
        Ordering::Equal => "same",
    }
}

/// Returns true when `cur` is a worse posture than `prev`: more or higher-severity
/// findings, by the tuple's severity priority. Callers pre-zero both with
/// `above_floor` to ignore severities below a threshold.
pub fn is_worse(prev: SeverityTuple, cur: SeverityTuple) -> bool {
    cur > prev
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn create_and_retrieve_session() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let manager = ScanHistoryManager::new(&db_path).await.unwrap();

        let id = manager
            .create_session("daemon", "localhost", &["kernel".into(), "ssh".into()])
            .await
            .unwrap();

        let session = manager.get_session(&id).await.unwrap().unwrap();
        assert_eq!(session.status, "running");
        assert_eq!(session.host_identifier, "localhost");
        assert_eq!(session.plugins(), vec!["kernel", "ssh"]);
    }

    #[tokio::test]
    async fn complete_session_with_findings() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let manager = ScanHistoryManager::new(&db_path).await.unwrap();

        let id = manager
            .create_session("systemd", "server1", &[])
            .await
            .unwrap();

        let findings = vec![
            ScanFinding {
                plugin_id: "kernel".into(),
                finding_id: "K001".into(),
                severity: "high".into(),
                title: "Test finding".into(),
                description: None,
                current_value: None,
                recommended_value: None,
                category: None,
                compliance_mappings: None,
            },
            ScanFinding {
                plugin_id: "ssh".into(),
                finding_id: "S001".into(),
                severity: "critical".into(),
                title: "SSH issue".into(),
                description: Some("Details".into()),
                current_value: None,
                recommended_value: None,
                category: None,
                compliance_mappings: Some(vec!["CIS-1.1".into()]),
            },
        ];

        manager
            .complete_session(&id, &findings, Some("/tmp/scan.json"), None)
            .await
            .unwrap();

        let session = manager.get_session(&id).await.unwrap().unwrap();
        assert_eq!(session.status, "completed");
        assert_eq!(session.total_findings, 2);
        assert_eq!(session.critical_count, 1);
        assert_eq!(session.high_count, 1);

        let stored_findings = manager.get_findings(&id).await.unwrap();
        assert_eq!(stored_findings.len(), 2);
    }

    #[tokio::test]
    async fn fail_session_records_error() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let manager = ScanHistoryManager::new(&db_path).await.unwrap();

        let id = manager
            .create_session("daemon", "localhost", &[])
            .await
            .unwrap();

        manager
            .fail_session(&id, "Connection refused")
            .await
            .unwrap();

        let session = manager.get_session(&id).await.unwrap().unwrap();
        assert_eq!(session.status, "failed");
        assert_eq!(session.error_message, Some("Connection refused".into()));
    }

    #[tokio::test]
    async fn list_sessions_with_filter() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let manager = ScanHistoryManager::new(&db_path).await.unwrap();

        manager
            .create_session("daemon", "host1", &[])
            .await
            .unwrap();
        manager
            .create_session("daemon", "host2", &[])
            .await
            .unwrap();
        manager
            .create_session("systemd", "host1", &[])
            .await
            .unwrap();

        let filter = SessionFilter {
            host: Some("host1".into()),
            ..Default::default()
        };

        let sessions = manager.list_sessions(&filter).await.unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[tokio::test]
    async fn notification_logging() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let manager = ScanHistoryManager::new(&db_path).await.unwrap();

        let id = manager
            .create_session("daemon", "localhost", &[])
            .await
            .unwrap();

        manager
            .log_notification(&id, "email", "sent", None)
            .await
            .unwrap();
        manager
            .log_notification(&id, "webhook:slack", "failed", Some("Timeout"))
            .await
            .unwrap();
        // Notifications are logged - no assertion needed, just verify no error
    }

    #[test]
    fn above_floor_zeroes_sub_floor_levels() {
        let t = (1, 2, 3, 4, 5); // critical, high, medium, low, info
        assert_eq!(above_floor(t, Severity::Critical), (1, 0, 0, 0, 0));
        assert_eq!(above_floor(t, Severity::High), (1, 2, 0, 0, 0));
        assert_eq!(above_floor(t, Severity::Medium), (1, 2, 3, 0, 0));
        assert_eq!(above_floor(t, Severity::Low), (1, 2, 3, 4, 0));
        assert_eq!(above_floor(t, Severity::Info), (1, 2, 3, 4, 5));
    }

    #[test]
    fn trend_direction_uses_severity_priority() {
        // Fewer criticals is better, even when lower severities rise.
        assert_eq!(trend_direction((1, 0, 0, 0, 0), (0, 5, 5, 5, 5)), "better");
        // A single new critical is worse, even when everything else drops.
        assert_eq!(trend_direction((0, 9, 9, 9, 9), (1, 0, 0, 0, 0)), "worse");
        assert_eq!(trend_direction((2, 1, 0, 0, 0), (2, 1, 0, 0, 0)), "same");
    }

    #[test]
    fn is_worse_follows_severity_priority() {
        assert!(is_worse((0, 0, 0, 0, 0), (1, 0, 0, 0, 0))); // a new critical
        assert!(!is_worse((1, 0, 0, 0, 0), (0, 9, 9, 9, 9))); // fewer criticals is not worse
        assert!(!is_worse((2, 1, 0, 0, 0), (2, 1, 0, 0, 0))); // unchanged
    }

    #[test]
    fn severity_tuple_reads_session_counts() {
        let mut s = ScanSession {
            id: "x".into(),
            started_at: 0,
            completed_at: None,
            status: "completed".into(),
            trigger_type: "batch".into(),
            host_identifier: "h".into(),
            plugins_scanned: String::new(),
            total_findings: 0,
            critical_count: 1,
            high_count: 2,
            medium_count: 3,
            low_count: 4,
            info_count: 5,
            error_message: None,
            json_file_path: None,
            hash: None,
        };
        assert_eq!(s.severity_tuple(), (1, 2, 3, 4, 5));
        s.critical_count = 0;
        assert_eq!(s.severity_tuple(), (0, 2, 3, 4, 5));
    }

    #[tokio::test]
    async fn pool_uses_wal_journal_mode() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("wal.db");
        let manager = ScanHistoryManager::new(&db_path).await.unwrap();
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&manager.pool)
            .await
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal", "history pool must use WAL");
    }

    #[tokio::test]
    async fn previous_completed_session_returns_prior() {
        let dir = tempdir().unwrap();
        let manager = ScanHistoryManager::new(&dir.path().join("t.db"))
            .await
            .unwrap();

        // Single completed session: nothing precedes it.
        let first = manager.create_session("schedule", "h", &[]).await.unwrap();
        manager
            .complete_session(&first, &[], None, None)
            .await
            .unwrap();
        assert!(
            manager
                .previous_completed_session("h", &first)
                .await
                .unwrap()
                .is_none()
        );

        // A second session: excluding it returns the other one (the prior scan).
        // With exactly two sessions this is deterministic regardless of any
        // started_at tie — there is only one candidate left after the exclusion.
        let second = manager.create_session("schedule", "h", &[]).await.unwrap();
        manager
            .complete_session(&second, &[], None, None)
            .await
            .unwrap();
        let prev = manager
            .previous_completed_session("h", &second)
            .await
            .unwrap()
            .expect("has a previous");
        assert_eq!(prev.id, first);
    }
}
