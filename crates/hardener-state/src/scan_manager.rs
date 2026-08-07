//! Scan history manager for GUI scan persistence.
//!
//! Handles storing and retrieving scan results from the database.
//! The CLI remains stateless; this is used exclusively by the Tauri GUI.

use crate::scan_history::{ScanSession, ScanSessionId, ScanStatus};
use hardener_common::error::{HardeningError, Result};
use hardener_types::{
    ComplianceMapping, ExceptionOutcome, Finding, FindingCategory, FindingExceptionDeclined,
    FindingPolicyException, PluginId, ScanResult, Severity, UncheckedCheck,
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
        let mut tx = self
            .db_pool
            .begin()
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))?;

        for result in results {
            // Insert scan_results row
            let unchecked_json = if result.scan_unchecked.is_empty() {
                None
            } else {
                serde_json::to_string(&result.scan_unchecked).ok()
            };

            let result_row = sqlx::query(
                "INSERT INTO scan_results (session_id, plugin_id, success, duration_us, error_message, unchecked_json)
                 VALUES (?, ?, ?, ?, ?, ?)
                 RETURNING id",
            )
            .bind(session_id.as_str())
            .bind(result.scan_plugin_id.as_str())
            .bind(result.scan_success)
            .bind(result.scan_duration_us as i64)
            .bind(&result.scan_error)
            .bind(unchecked_json)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))?;

            let result_id: i64 = result_row.get("id");

            // Insert findings for this result
            for finding in &result.scan_findings {
                let remediation_json = serde_json::to_string(&finding.finding_remediation_steps)
                    .unwrap_or_else(|_| "[]".to_string());

                let compliance_json = serde_json::to_string(&finding.finding_compliance)
                    .unwrap_or_else(|_| "[]".to_string());

                // Applied and Declined are mutually exclusive outcomes, so each
                // takes its own column: an applied exception excuses the finding
                // from its compliance control, and a declined one is a live
                // violation that still carries the reason it did not apply.
                let (policy_exception_json, exception_declined_json) =
                    match &finding.finding_exception {
                        ExceptionOutcome::NotConfigured => (None, None),
                        ExceptionOutcome::Applied(applied) => {
                            (serde_json::to_string(applied).ok(), None)
                        }
                        ExceptionOutcome::Declined(declined) => {
                            (None, serde_json::to_string(declined).ok())
                        }
                    };

                sqlx::query(
                    "INSERT INTO scan_findings (
                        result_id, finding_id, category, severity, title, description,
                        explanation, impact, current_value, recommended_value,
                        remediation_steps, compliance_mappings, policy_exception,
                        exception_key, exception_declined
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                .bind(&finding.finding_exception_key)
                .bind(&exception_declined_json)
                .execute(&mut *tx)
                .await
                .map_err(|e| HardeningError::Database(e.to_string()))?;
            }
        }

        tx.commit()
            .await
            .map_err(|e| HardeningError::Database(e.to_string()))?;

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

    /// Marks a session as failed.
    ///
    /// A failed session always carries zeroed totals: forwards to
    /// `complete_session` with `ScanStatus::Failed` and `0, 0`.
    pub async fn fail_session(&self, session_id: &ScanSessionId) -> Result<()> {
        self.complete_session(session_id, ScanStatus::Failed, 0, 0)
            .await
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
             ORDER BY started_at DESC, rowid DESC
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
    pub async fn get_session_results(&self, session_id: &ScanSessionId) -> Result<Vec<ScanResult>> {
        let result_rows = sqlx::query(
            "SELECT id, plugin_id, success, duration_us, error_message, unchecked_json
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

            let unchecked: Vec<UncheckedCheck> = row
                .get::<Option<String>, _>("unchecked_json")
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|e| {
                    HardeningError::Database(format!(
                        "Corrupted unchecked_json for result {result_id}: {e}"
                    ))
                })?
                .unwrap_or_default();

            results.push(ScanResult {
                scan_plugin_id: PluginId::new(row.get::<String, _>("plugin_id")),
                scan_success: row.get("success"),
                scan_findings: findings,
                scan_unchecked: unchecked,
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
                    compliance_mappings, policy_exception, exception_key, exception_declined
             FROM scan_findings
             WHERE result_id = ?",
        )
        .bind(result_id)
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| HardeningError::Database(e.to_string()))?;

        let mut findings = Vec::new();

        for row in finding_rows {
            let raw_remediation: &str = row.get("remediation_steps");
            let remediation_steps: Vec<String> =
                serde_json::from_str(raw_remediation).map_err(|e| {
                    HardeningError::Database(format!(
                        "Corrupted remediation_steps JSON for result {result_id}: {e}"
                    ))
                })?;

            let raw_compliance: &str = row.get("compliance_mappings");
            let compliance: Vec<ComplianceMapping> =
                serde_json::from_str(raw_compliance).map_err(|e| {
                    HardeningError::Database(format!(
                        "Corrupted compliance_mappings JSON for result {result_id}: {e}"
                    ))
                })?;

            let policy_exception: Option<FindingPolicyException> = row
                .get::<Option<String>, _>("policy_exception")
                .map(|s| {
                    serde_json::from_str(&s).map_err(|e| {
                        HardeningError::Database(format!(
                            "Corrupted policy_exception JSON for result {result_id}: {e}"
                        ))
                    })
                })
                .transpose()?;

            let exception_declined: Option<FindingExceptionDeclined> = row
                .get::<Option<String>, _>("exception_declined")
                .map(|s| {
                    serde_json::from_str(&s).map_err(|e| {
                        HardeningError::Database(format!(
                            "Corrupted exception_declined JSON for result {result_id}: {e}"
                        ))
                    })
                })
                .transpose()?;

            // Both columns populated is a row that construction cannot produce.
            // Read it as Declined, never Applied: Applied excuses a finding
            // from its compliance control, and no corrupt row should buy that.
            // Declined is live and carries the reason, so it is the safe read.
            //
            // Named apart from the field on purpose: a local spelled
            // `finding_exception` would let clippy::redundant_field_names push
            // the struct literal below toward shorthand, but
            // validate_persisted_finding_fields.py only recognises the
            // literal `finding_exception: value` form.
            let exception_outcome = match (exception_declined, policy_exception) {
                (Some(declined), _) => ExceptionOutcome::Declined(declined),
                (None, Some(applied)) => ExceptionOutcome::Applied(applied),
                (None, None) => ExceptionOutcome::NotConfigured,
            };

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
                finding_exception: exception_outcome,
                finding_exception_key: row.get("exception_key"),
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
fn str_to_category(category: &str) -> FindingCategory {
    match category {
        "audit" => FindingCategory::Audit,
        "authentication" => FindingCategory::Authentication,
        "cryptography" => FindingCategory::Cryptography,
        "filesystem" => FindingCategory::FileSystem,
        "kernel" => FindingCategory::Kernel,
        "mac" => FindingCategory::MandatoryAccessControl,
        "network" => FindingCategory::Network,
        "services" => FindingCategory::Services,
        other => {
            tracing::warn!("Unknown finding category in database: {other:?}");
            FindingCategory::Services
        }
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
        other => {
            tracing::warn!("Unknown severity in database: {other:?}");
            Severity::Info
        }
    }
}
