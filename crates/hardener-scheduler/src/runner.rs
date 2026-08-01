//! Scan execution runner for scheduled scanning.
//!
//! Orchestrates plugin scans, persists results to the database,
//! and exports JSON files.

use crate::{
    config::SchedulerConfig,
    db::{ScanFinding, ScanHistoryManager, ScanSession, SeverityCounts, SeverityTuple},
    json_store::JsonStore,
    notification::dispatcher::NotificationDispatcher,
};
use hardener_common::{
    error::{HardeningError, Result},
    types::Severity,
};
use hardener_core::{ConfigLoader, Context, HardenerConfig, PluginManager, ScanResult};
use serde::Serialize;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// The plugin ids a scan will actually cover, narrowed to what the config
/// enables.
///
/// The session row naming a scan's plugins is written before any plugin runs,
/// so it must be derived from the rule the scan itself obeys. Anything looser
/// files a history row claiming plugins that never ran, and their absent
/// findings then read as a clean result.
fn scannable_plugins(selected: Vec<String>, config: &HardenerConfig) -> Vec<String> {
    selected
        .into_iter()
        .filter(|id| config.is_plugin_enabled(id))
        .collect()
}

/// Trigger source for a scan session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TriggerType {
    /// Triggered by the cron scheduler daemon.
    Scheduled,
    /// Triggered manually via CLI command.
    Manual,
    /// Triggered by systemd user.
    Systemd,
}

impl TriggerType {
    /// Returns the string representation for database storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            TriggerType::Scheduled => "scheduled",
            TriggerType::Manual => "manual",
            TriggerType::Systemd => "systemd",
        }
    }
}

/// Context describing how a scan regressed against the host's previous scan.
#[derive(Clone, Debug, Serialize)]
pub struct RegressionInfo {
    /// Start time of the previous (better) scan.
    pub previous_started_at: i64,
    /// Total findings in the previous scan.
    pub previous_total: i32,
    /// Change in each severity vs the previous scan (positive = worse).
    pub delta_critical: i64,
    pub delta_high: i64,
    pub delta_medium: i64,
    pub delta_low: i64,
}

impl RegressionInfo {
    /// Builds the delta between a previous session and the current summary.
    pub fn new(previous: &ScanSession, current: &ScanSummary) -> RegressionInfo {
        RegressionInfo {
            previous_started_at: previous.started_at,
            previous_total: previous.total_findings,
            delta_critical: current.critical_count as i64 - previous.critical_count as i64,
            delta_high: current.high_count as i64 - previous.high_count as i64,
            delta_medium: current.medium_count as i64 - previous.medium_count as i64,
            delta_low: current.low_count as i64 - previous.low_count as i64,
        }
    }
}

/// Summary of a completed scan for notification purposes.
#[derive(Clone, Debug, Serialize)]
pub struct ScanSummary {
    /// Database session ID.
    pub session_id: String,
    /// Host that was scanned.
    pub host: String,
    /// Plugins that were scanned.
    pub plugins_scanned: Vec<String>,
    /// Total findings after severity filtering.
    pub total_findings: usize,
    /// Breakdown by severity.
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    /// Path to JSON export file.
    pub json_path: Option<String>,
    /// SHA-256 hash of JSON file.
    pub json_hash: Option<String>,
    /// Whether any plugins failed during scan.
    pub had_errors: bool,
    /// Regression context, set only when this scan regressed against the previous one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regression: Option<RegressionInfo>,
}

impl ScanSummary {
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
}

/// Executes scans and persists results.
///
/// Coordinates between the plugin system, database storage,
/// and JSON file exports.
pub struct ScanRunner {
    /// Database manager for scan history.
    db: Arc<ScanHistoryManager>,
    /// JSON file store for exports.
    json_store: Arc<JsonStore>,
    /// Minimum severity to include in results.
    min_severity: Severity,
    /// Plugins to scan (empty = all).
    plugins: Vec<String>,
    /// Host identifier for this system.
    host: String,
    /// Notification dispatcher (optional)
    dispatcher: Option<NotificationDispatcher>,
}

/// JSON export file structure.
#[derive(Clone, Debug, Serialize)]
struct JsonExport {
    host: String,
    timestamp: chrono::DateTime<chrono::Utc>,
    min_severity: String,
    plugins_scanned: Vec<String>,
    total_findings: usize,
    findings: Vec<ScanFinding>,
    plugin_errors: Vec<PluginError>,
}

/// Plugin error record for JSON export.
#[derive(Clone, Debug, Serialize)]
struct PluginError {
    id: String,
    error: String,
}

impl ScanRunner {
    /// Creates a new ScanRunner from scheduler configuration.
    ///
    /// # Arguments
    /// * `config` - Scheduler configuration with storage paths and filters
    /// * `db` - Initialised database manager
    /// * `json_store` - Initialised JSON file store
    pub fn new(
        config: &SchedulerConfig,
        db: Arc<ScanHistoryManager>,
        json_store: Arc<JsonStore>,
    ) -> ScanRunner {
        let host = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "localhost".to_string());

        ScanRunner {
            db: Arc::clone(&db),
            json_store,
            min_severity: Self::parse_severity(&config.min_severity),
            plugins: config.plugins.clone(),
            host,
            dispatcher: Some(NotificationDispatcher::new(&config.notifications, db)),
        }
    }

    /// Creates a ScanRunner with explicit parameters (for testing)
    pub fn with_params(
        db: Arc<ScanHistoryManager>,
        json_store: Arc<JsonStore>,
        min_severity: Severity,
        plugins: Vec<String>,
        host: String,
    ) -> ScanRunner {
        ScanRunner {
            db,
            json_store,
            min_severity,
            plugins,
            host,
            dispatcher: None,
        }
    }

    /// Parses severity string to enum, defaulting to Medium.
    fn parse_severity(s: &str) -> Severity {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            "info" => Severity::Info,
            _ => {
                warn!("Unknown severity '{}', defaulting to Medium", s);
                Severity::Medium
            }
        }
    }

    /// Executes a full scan cycle.
    ///
    /// 1. Creates a database session
    /// 2. Runs plugin scans via PluginManager
    /// 3. Filters findings by severity
    /// 4. Exports results to JSON
    /// 5. Completes the database session
    ///
    /// # Arguments
    /// * `plugin_manager` - Configured plugin manager with resolved dependencies
    /// * `ctx` - Execution context for plugins
    /// * `trigger` - What initiated this scan
    ///
    /// # Returns
    /// Summary of the scan results for notification purposes.
    pub async fn run(
        &self,
        plugin_manager: &PluginManager,
        ctx: &Context,
        trigger: TriggerType,
    ) -> Result<ScanSummary> {
        info!("Starting {} scan on host '{}'", trigger.as_str(), self.host);

        // Loaded before the session row is written, because the config decides
        // which plugins run and that row records which plugins a scan covered.
        // No HardenerConfig is threaded through the scheduler yet, so this
        // loads the same on-disk sources the CLI honours. The daemon keeps
        // running on a load failure rather than stopping scheduled scans, but
        // it must say so: plugins consume the config now, so a silent fallback
        // would scan the raw baseline while appearing to honour the operator's
        // directives and exceptions.
        let hardener_config = ConfigLoader::new().load().unwrap_or_else(|e| {
            warn!("Config load failed, scanning the secure baseline instead: {e}");
            Default::default()
        });

        // Determines which plugins to scan
        let selected: Vec<String> = if self.plugins.is_empty() {
            plugin_manager
                .execution_order()
                .map_err(|e| HardeningError::Plugin(e.to_string()))?
                .into_iter()
                .map(|id| id.to_string())
                .collect()
        } else {
            self.plugins.clone()
        };
        let plugins_to_scan = scannable_plugins(selected, &hardener_config);

        // Create database session
        let session_id = self
            .db
            .create_session(trigger.as_str(), &self.host, &plugins_to_scan)
            .await?;

        debug!("Created scan session {}", session_id);
        let scan_results = match plugin_manager.execute_scan(ctx, &hardener_config).await {
            Ok(results) => results,
            Err(e) => {
                error!("Scan execution failed: {}", e);
                self.db.fail_session(&session_id, &e.to_string()).await?;
                return Err(HardeningError::Plugin(e.to_string()));
            }
        };

        // Check for plugin errors
        let had_errors = scan_results.iter().any(|r| !r.scan_success);
        if had_errors {
            warn!("Some plugin(s) reported errors during scan");
        }

        // Convert and filter findings
        let findings = self.process_findings(&scan_results);

        info!(
            "Scan complete: {} findings (filtered from {} total)",
            findings.len(),
            scan_results
                .iter()
                .map(|r| r.scan_findings.len())
                .sum::<usize>(),
        );

        // Build summary counts
        let summary = self.build_summary(&session_id, &plugins_to_scan, &findings, had_errors);

        // Export to JSON
        let (json_path, json_hash) = self
            .json_store
            .write(
                &session_id,
                &self.build_json_export(&scan_results, &findings),
            )
            .await?;

        debug!("Exported JSON to: {}", json_path);

        // Complete database session
        self.db
            .complete_session(&session_id, &findings, Some(&json_path), Some(&json_hash))
            .await?;

        info!(
            "Session {} completed: {} findings, {} critical, {} high, {} medium, {} low",
            session_id,
            summary.total_findings,
            summary.critical_count,
            summary.high_count,
            summary.medium_count,
            summary.low_count,
        );

        // Dispatch notifications
        let final_summary = ScanSummary {
            json_path: Some(json_path.clone()),
            json_hash: Some(json_hash.clone()),
            ..summary
        };

        if let Some(ref dispatcher) = self.dispatcher {
            // Best-effort: a history-lookup failure must never fail the scan.
            let previous = match self
                .db
                .previous_completed_session(&self.host, &session_id)
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    warn!("Regression lookup failed (continuing): {}", e);
                    None
                }
            };
            let results = dispatcher.dispatch(&final_summary, previous.as_ref()).await;
            let success_count = results.iter().filter(|r| r.success).count();
            let fail_count = results.len() - success_count;
            if !results.is_empty() {
                info!(
                    "Notifications: {} sent, {} failed",
                    success_count, fail_count
                );
            }
        }

        Ok(final_summary)
    }

    /// Converts plugin findings to database format with severity filtering.
    fn process_findings(&self, scan_results: &[ScanResult]) -> Vec<ScanFinding> {
        scan_results
            .iter()
            .flat_map(|result| {
                result.scan_findings.iter().filter_map(|finding| {
                    // Filter by minimum severity
                    if finding.finding_severity < self.min_severity {
                        return None;
                    }

                    Some(ScanFinding {
                        plugin_id: result.scan_plugin_id.to_string(),
                        finding_id: finding.finding_id.clone(),
                        severity: finding.finding_severity.to_string(),
                        title: finding.finding_title.clone(),
                        description: Some(finding.finding_description.clone()),
                        current_value: Some(finding.finding_current_value.clone()),
                        recommended_value: Some(finding.finding_recommended_value.clone()),
                        category: Some(finding.finding_category.to_string()),
                        compliance_mappings: if finding.finding_compliance.is_empty() {
                            None
                        } else {
                            Some(
                                finding
                                    .finding_compliance
                                    .iter()
                                    .map(|c| {
                                        format!(
                                            "{}:{}",
                                            c.compliance_framework, c.compliance_control_id
                                        )
                                    })
                                    .collect(),
                            )
                        },
                    })
                })
            })
            .collect()
    }

    /// Builds a summary with severity counts.
    fn build_summary(
        &self,
        session_id: &str,
        plugins: &[String],
        findings: &[ScanFinding],
        had_errors: bool,
    ) -> ScanSummary {
        let counts = SeverityCounts::from_findings(findings);

        ScanSummary {
            session_id: session_id.to_string(),
            host: self.host.clone(),
            plugins_scanned: plugins.to_vec(),
            total_findings: counts.total,
            critical_count: counts.critical,
            high_count: counts.high,
            medium_count: counts.medium,
            low_count: counts.low,
            info_count: counts.info,
            json_path: None,
            json_hash: None,
            had_errors,
            regression: None,
        }
    }

    /// Builds the JSON export payload.
    fn build_json_export(
        &self,
        scan_results: &[ScanResult],
        findings: &[ScanFinding],
    ) -> JsonExport {
        JsonExport {
            host: self.host.clone(),
            timestamp: chrono::Utc::now(),
            min_severity: self.min_severity.to_string(),
            plugins_scanned: scan_results
                .iter()
                .map(|r| r.scan_plugin_id.to_string())
                .collect(),
            total_findings: findings.len(),
            findings: findings.to_vec(),
            plugin_errors: scan_results
                .iter()
                .filter(|r| !r.scan_success)
                .map(|r| PluginError {
                    id: r.scan_plugin_id.to_string(),
                    error: r.scan_error.clone().unwrap_or_default(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests;
