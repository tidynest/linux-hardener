//! Scan history manager for GUI scan persistence.
//!
//! Handles storing and retrieving scan results from the database.
//! The CLI remains stateless; this is used exclusively by the Tauri GUI.

use crate::scan_history::{ScanSession, ScanSessionId, ScanStatus};
use hardener_common::error::{HardeningError, Result};
use hardener_types::{
    ComplianceMapping, Finding, FindingCategory, FindingPolicyException, PluginId, ScanResult,
    Severity,
};
use sqlx::{Row, SqlitePool};
use std::time::{SystemTime, UNIX_EPOCH};

/// Manages scan history persistence for the GUI.
///
/// Provides CRUD operations for scan sessions and their results.
/// Follows the same pattern as `CheckpointManager`.
pub struct ScanHistoryManager {
    /// Database connection pool.
    db_pool: SqlitePool,
}

impl ScanHistoryManager {
    /// Creates a new ScanHistoryManager with the given database pool.
    pub fn new(db_pool: SqlitePool) -> ScanHistoryManager {
        Self { db_pool }
    }

    /// Starts a new scan session and returns its ID.
    ///
    /// Creates a session record with status 'running'.
    pub async fn start_session(&self) -> Result<ScanSessionId> {
        let session_id = ScanSessionId::generate();
        let started_at = current_timestamp();

        sqlx::query(
            "INSERT INTO scan_sessions (id, started_at, status)
             VALUES (?, ?, ?)",
        )
        .bind(session_id.as_str())
        .bind(started_at)
        .bind(ScanStatus::Running.as_str())
        .execute(&self.db_pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

        Ok(session_id)
    }

    /// Stores scan results for a session.
    ///
    /// Persists all plugin results and their findings to the database.
    pub async fn store_results(
        &self,
        session_id: &ScanSessionId,
        results: &[ScanResult],
    ) -> Result<()> {
        for result in results {
            // Insert scan_results row
            let result_row = sqlx::query(
                "INSERT INTO scan_results (session_id, plugin_id, success, duration_us, error_message)
                 VALUES (?, ?, ?, ?, ?)
                 RETURNING id",
            )
            .bind(session_id.as_str())
            .bind(result.scan_plugin_id.as_str())
            .bind(result.scan_success)
            .bind(result.scan_duration_us as i64)
            .bind(&result.scan_error)
            .fetch_one(&self.db_pool)
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))?;

            let result_id: i64 = result_row.get("id");

            // Insert findings for this result
            for finding in &result.scan_findings {
                let remediation_json = serde_json::to_string(&finding.finding_remediation_steps)
                    .unwrap_or_else(|_| "[]".to_string());

                let compliance_json = serde_json::to_string(&finding.finding_compliance)
                    .unwrap_or_else(|_| "[]".to_string());

                let policy_exception_json = finding
                    .finding_policy_exception
                    .as_ref()
                    .and_then(|e| serde_json::to_string(e).ok());

                sqlx::query(
                    "INSERT INTO scan_findings (
                        result_id, finding_id, category, severity, title, description,
                        explanation, impact, current_value, recommended_value,
                        remediation_steps, compliance_mappings, policy_exception
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(result_id)
                .bind(&finding.finding_id)
                .bind(category_to_str(&finding.finding_category))
                .bind(severity_to_str(&finding.finding_severity))
                .bind(&finding.finding_title)
                .bind(&finding.finding_description)
                .bind(&finding.finding_explanation)
                .bind(&finding.finding_impact)
                .bind(&finding.finding_current_value)
                .bind(&finding.finding_recommended_value)
                .bind(&remediation_json)
                .bind(&compliance_json)
                .bind(&policy_exception_json)
                .execute(&self.db_pool)
                .await
                .map_err(|e| HardeningError::Database(e.to_string()))?;
            }
        }

        Ok(())
    }

    /// Completes a session with the given status.
    ///
    /// Updates the session with completion timestamp and counts.
    pub async fn complete_session(
        &self,
        session_id: &ScanSessionId,
        status: ScanStatus,
        total_findings: i32,
        total_plugins: i32,
    ) -> Result<()> {
        let completed_at = current_timestamp();

        sqlx::query(
            "UPDATE scan_sessions
             SET completed_at = ?, status = ?, total_findings = ?, total_plugins = ?
             WHERE id = ?",
        )
        .bind(completed_at)
        .bind(status.as_str())
        .bind(total_findings)
        .bind(total_plugins)
        .bind(session_id.as_str())
        .execute(&self.db_pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

        Ok(())
    }

    /// Retrieves the most recent completed scan session with all results.
    ///
    /// Returns None if no completed scans exist.
    pub async fn get_latest_scan(&self) -> Result<Option<(ScanSession, Vec<ScanResult>)>> {
        // Get the latest completed session
        let session_row = sqlx::query(
            "SELECT id, started_at, completed_at, total_findings, total_plugins, status
             FROM scan_sessions
             WHERE status = 'completed'
             ORDER BY started_at DESC
             LIMIT 1",
        )
        .fetch_optional(&self.db_pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

        let session_row = match session_row {
            Some(row) => row,
            None => return Ok(None),
        };

        let session = ScanSession {
            session_id: ScanSessionId::new(session_row.get::<String, _>("id")),
            session_started_at: session_row.get("started_at"),
            session_completed_at: session_row.get("completed_at"),
            session_total_findings: session_row.get("total_findings"),
            session_total_plugins: session_row.get("total_plugins"),
            session_status: ScanStatus::parse(session_row.get("status")),
        };

        // Get all results for this session
        let results = self.get_session_results(&session.session_id).await?;

        Ok(Some((session, results)))
    }

    /// Retrieves all scan results for a given session.
    async fn get_session_results(&self, session_id: &ScanSessionId) -> Result<Vec<ScanResult>> {
        let result_rows = sqlx::query(
            "SELECT id, plugin_id, success, duration_us, error_message
             FROM scan_results
             WHERE session_id = ?",
        )
        .bind(session_id.as_str())
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

        let mut results = Vec::new();

        for row in result_rows {
            let result_id: i64 = row.get("id");
            let findings = self.get_result_findings(result_id).await?;

            results.push(ScanResult {
                scan_plugin_id: PluginId::new(row.get::<String, _>("plugin_id")),
                scan_success: row.get("success"),
                scan_findings: findings,
                scan_duration_us: row.get::<i64, _>("duration_us") as u64,
                scan_error: row.get("error_message"),
            });
        }

        Ok(results)
    }

    /// Retrieves all findings for a given scan result.
    async fn get_result_findings(&self, result_id: i64) -> Result<Vec<Finding>> {
        let finding_rows = sqlx::query(
            "SELECT finding_id, category, severity, title, description, explanation,
                    impact, current_value, recommended_value, remediation_steps,
                    compliance_mappings, policy_exception
             FROM scan_findings
             WHERE result_id = ?",
        )
        .bind(result_id)
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

        let mut findings = Vec::new();

        for row in finding_rows {
            let remediation_steps: Vec<String> =
                serde_json::from_str(row.get("remediation_steps")).unwrap_or_default();

            let compliance: Vec<ComplianceMapping> =
                serde_json::from_str(row.get("compliance_mappings")).unwrap_or_default();

            let policy_exception: Option<FindingPolicyException> = row
                .get::<Option<String>, _>("policy_exception")
                .and_then(|s| serde_json::from_str(&s).ok());

            findings.push(Finding {
                finding_id: row.get("finding_id"),
                finding_category: str_to_category(row.get("category")),
                finding_severity: str_to_severity(row.get("severity")),
                finding_title: row.get("title"),
                finding_description: row.get("description"),
                finding_explanation: row.get("explanation"),
                finding_impact: row.get("impact"),
                finding_current_value: row.get("current_value"),
                finding_recommended_value: row.get("recommended_value"),
                finding_remediation_steps: remediation_steps,
                finding_compliance: compliance,
                finding_policy_exception: policy_exception,
            });
        }

        Ok(findings)
    }

    /// Lists recent scan sessions (metadata only, no results).
    pub async fn list_sessions(&self, limit: i32) -> Result<Vec<ScanSession>> {
        let rows = sqlx::query(
            "SELECT id, started_at, completed_at, total_findings, total_plugins, status
             FROM scan_sessions
             ORDER BY started_at DESC
             LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(ScanSession {
                session_id: ScanSessionId::new(row.get::<String, _>("id")),
                session_started_at: row.get("started_at"),
                session_completed_at: row.get("completed_at"),
                session_total_findings: row.get("total_findings"),
                session_total_plugins: row.get("total_plugins"),
                session_status: ScanStatus::parse(row.get("status")),
            });
        }

        Ok(sessions)
    }

    /// Deletes old sessions beyond the retention limit.
    ///
    /// Keeps the most recent `keep_count` sessions and deletes the rest.
    /// Returns the number of sessions deleted.
    pub async fn cleanup_old_sessions(&self, keep_count: i32) -> Result<i32> {
        // Get IDs of sessions to keep
        let keep_rows = sqlx::query(
            "SELECT id FROM scan_sessions
             ORDER BY started_at DESC
             LIMIT ?",
        )
        .bind(keep_count)
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

        let keep_ids: Vec<String> = keep_rows.iter().map(|r| r.get("id")).collect();

        if keep_ids.is_empty() {
            return Ok(0);
        }

        // Build placeholders for IN clause
        let placeholders: Vec<&str> = keep_ids.iter().map(|_| "?").collect();
        let in_clause = placeholders.join(", ");

        // Delete sessions not in keep list (CASCADE will delete results and findings)
        let query = format!("DELETE FROM scan_sessions WHERE id NOT IN ({})", in_clause);

        let mut query_builder = sqlx::query(&query);
        for id in &keep_ids {
            query_builder = query_builder.bind(id);
        }

        let result = query_builder
            .execute(&self.db_pool)
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))?;

        Ok(result.rows_affected() as i32)
    }
}

/// Returns current Unix timestamp in seconds.
fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Converts FindingCategory to database string.
fn category_to_str(category: &FindingCategory) -> &'static str {
    match category {
        FindingCategory::Audit => "audit",
        FindingCategory::Authentication => "authentication",
        FindingCategory::Cryptography => "cryptography",
        FindingCategory::FileSystem => "filesystem",
        FindingCategory::Kernel => "kernel",
        FindingCategory::MandatoryAccessControl => "mac",
        FindingCategory::Network => "network",
        FindingCategory::Services => "services",
    }
}

/// Parses FindingCategory from database string.
fn str_to_category(s: &str) -> FindingCategory {
    match s {
        "audit" => FindingCategory::Audit,
        "authentication" => FindingCategory::Authentication,
        "cryptography" => FindingCategory::Cryptography,
        "filesystem" => FindingCategory::FileSystem,
        "kernel" => FindingCategory::Kernel,
        "mac" => FindingCategory::MandatoryAccessControl,
        "network" => FindingCategory::Network,
        "services" => FindingCategory::Services,
        _ => FindingCategory::Services, // Default fallback
    }
}

/// Converts Severity to database string.
fn severity_to_str(severity: &Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// Parses Severity from database string.
fn str_to_severity(s: &str) -> Severity {
    match s {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Info, // Default fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::init_db;
    use tempfile::tempdir;

    async fn create_test_manager() -> (ScanHistoryManager, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let pool = init_db(Some(&db_path)).await.unwrap();
        (ScanHistoryManager::new(pool), dir)
    }

    #[tokio::test]
    async fn test_start_session() {
        let (manager, _dir) = create_test_manager().await;

        let session_id = manager.start_session().await.unwrap();
        assert!(session_id.as_str().starts_with("scan_"));
    }

    #[tokio::test]
    async fn test_store_and_retrieve_results() {
        let (manager, _dir) = create_test_manager().await;

        // Start a session
        let session_id = manager.start_session().await.unwrap();

        // Create test results
        let results = vec![ScanResult {
            scan_plugin_id: PluginId::new("test_plugin"),
            scan_success: true,
            scan_findings: vec![Finding {
                finding_id: "TEST-001".to_string(),
                finding_category: FindingCategory::Kernel,
                finding_severity: Severity::High,
                finding_title: "Test Finding".to_string(),
                finding_description: "A test finding".to_string(),
                finding_explanation: "This is a test".to_string(),
                finding_impact: "None".to_string(),
                finding_current_value: "bad".to_string(),
                finding_recommended_value: "good".to_string(),
                finding_remediation_steps: vec!["Step 1".to_string()],
                finding_compliance: vec![],
                finding_policy_exception: None,
            }],
            scan_duration_us: 1000,
            scan_error: None,
        }];

        // Store results
        manager.store_results(&session_id, &results).await.unwrap();

        // Complete the session
        manager
            .complete_session(&session_id, ScanStatus::Completed, 1, 1)
            .await
            .unwrap();

        // Retrieve and verify
        let (session, retrieved_results) = manager.get_latest_scan().await.unwrap().unwrap();

        assert_eq!(session.session_status, ScanStatus::Completed);
        assert_eq!(session.session_total_findings, 1);
        assert_eq!(retrieved_results.len(), 1);
        assert_eq!(retrieved_results[0].scan_findings.len(), 1);
        assert_eq!(retrieved_results[0].scan_findings[0].finding_id, "TEST-001");
    }

    #[tokio::test]
    async fn test_list_sessions() {
        let (manager, _dir) = create_test_manager().await;

        // Create multiple sessions
        for _ in 0..3 {
            let session_id = manager.start_session().await.unwrap();
            manager
                .complete_session(&session_id, ScanStatus::Completed, 0, 0)
                .await
                .unwrap();
        }

        let sessions = manager.list_sessions(10).await.unwrap();
        assert_eq!(sessions.len(), 3);
    }

    #[tokio::test]
    async fn test_cleanup_old_sessions() {
        let (manager, _dir) = create_test_manager().await;

        // Create 5 sessions
        for _ in 0..5 {
            let session_id = manager.start_session().await.unwrap();
            manager
                .complete_session(&session_id, ScanStatus::Completed, 0, 0)
                .await
                .unwrap();
        }

        // Keep only 2
        let deleted = manager.cleanup_old_sessions(2).await.unwrap();
        assert_eq!(deleted, 3);

        let remaining = manager.list_sessions(10).await.unwrap();
        assert_eq!(remaining.len(), 2);
    }
}
