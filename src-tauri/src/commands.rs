use hardener_common::types::{ComplianceFramework, PluginId};
use hardener_compliance::{
    ComplianceReport, OutputFormat, ReportConfig, ReportGenerator, Scenario,
};
use hardener_core::{ApplyResult, Context, ScanResult};
use hardener_plugins::create_plugin_registry;
use hardener_state::{init_db, CheckpointId, CheckpointManager, ScanHistoryManager, ScanStatus};
use serde::Serialize;
use tracing::error;

/// Checkpoint information returned to the frontend.
#[derive(Clone, Debug, Serialize)]
pub struct CheckpointInfo {
    pub checkpoint_id: String,
    pub checkpoint_name: String,
    pub checkpoint_created: String,
    pub checkpoint_user: String,
}

/// Formats a Unix timestamp as a human-readable string.
fn format_timestamp(timestamp: i64) -> String {
    use std::time::{Duration, UNIX_EPOCH};

    let datetime = UNIX_EPOCH + Duration::from_secs(timestamp as u64);
    // Simple ISO-like format
    format!("{:?}", datetime)
}

/// Returns the path to the user-local database.
fn get_db_path() -> std::path::PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("linux-hardener")
        .join("checkpoints.db")
}

/// Creates a CheckpointManager with database connection.
///
/// Uses a user-local database path to avoid requiring root for reads.
async fn create_checkpoint_manager() -> Result<CheckpointManager, String> {
    let db_path = get_db_path();

    let pool = init_db(Some(db_path.as_path()))
        .await
        .map_err(|e| e.to_string())?;

    CheckpointManager::new(pool).map_err(|e| e.to_string())
}

/// Creates a ScanHistoryManager with database connection.
///
/// Uses the same database as checkpoints for scan history persistence.
async fn create_scan_history_manager() -> Result<ScanHistoryManager, String> {
    let db_path = get_db_path();

    let pool = init_db(Some(db_path.as_path()))
        .await
        .map_err(|e| e.to_string())?;

    Ok(ScanHistoryManager::new(pool))
}

/// Executes a security scan across all enabled plugins.
///
/// Persists results to the database for GUI state restoration.
/// Returns a vector of scan results, one per plugin.
#[tauri::command]
pub async fn run_scan() -> Result<Vec<ScanResult>, String> {
    // Create scan history manager for persistence
    let history_manager = create_scan_history_manager().await?;

    // Start a new scan session
    let session_id = history_manager
        .start_session()
        .await
        .map_err(|e| e.to_string())?;

    let ctx = Context::new();
    let registry = create_plugin_registry();

    let mut results = Vec::new();

    // Get list of all plugin metadata
    let plugin_list = registry.list().map_err(|e| e.to_string())?;

    for metadata in plugin_list {
        // Retrieve the actual plugin
        if let Ok(Some(plugin)) = registry.get(&metadata.plugin_id) {
            match plugin.scan(&ctx).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    error!("Scan failed for plugin {}: {}", metadata.plugin_id, e);
                }
            }
        }
    }

    // Calculate totals for the session
    let total_findings: i32 = results.iter().map(|r| r.scan_findings.len() as i32).sum();
    let total_plugins = results.len() as i32;

    // Persist results to database
    if let Err(e) = history_manager.store_results(&session_id, &results).await {
        error!("Failed to persist scan results: {}", e);
        // Continue anyway - return results even if persistence fails
    }

    // Complete the session
    if let Err(e) = history_manager
        .complete_session(&session_id, ScanStatus::Completed, total_findings, total_plugins)
        .await
    {
        error!("Failed to complete scan session: {}", e);
    }

    Ok(results)
}

/// Applies hardening changes for the specified plugins
///
/// Takes a list of plugin IDs to apply and returns the results
#[tauri::command]
pub async fn run_apply(plugin_ids: Vec<String>) -> Result<Vec<ApplyResult>, String> {
    let mut ctx = Context::new();
    let registry = create_plugin_registry();
    let config = hardener_core::Config;

    let mut results = Vec::new();

    for plugin_id_str in plugin_ids {
        let plugin_id = PluginId::new(&plugin_id_str);

        if let Ok(Some(plugin)) = registry.get(&plugin_id) {
            match plugin.apply(&mut ctx, &config).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    error!("Apply failed for plugin {}: {}", plugin_id_str, e);

                    results.push(ApplyResult {
                        apply_plugin_id: plugin_id,
                        apply_success: false,
                        apply_changes: vec![],
                        apply_checkpoint_id: None,
                        apply_error: Some(e.to_string()),
                    });
                }
            }
        }
    }

    Ok(results)
}

/// Rolls back to a previous checkpoint.
///
/// Takes a checkpoint ID and restores the system state to that point.
#[tauri::command]
pub async fn run_rollback(checkpoint_id: String) -> Result<bool, String> {
    let manager = create_checkpoint_manager().await?;
    let id = CheckpointId::new(checkpoint_id);

    manager.rollback(&id).await.map_err(|e| e.to_string())?;

    Ok(true)
}

/// Retrieves a list of all available checkpoints.
///
/// Returns checkpoint information for display in the UI.
#[tauri::command]
pub async fn get_checkpoints() -> Result<Vec<CheckpointInfo>, String> {
    let manager = create_checkpoint_manager().await?;

    let checkpoints = manager
        .list_checkpoints()
        .await
        .map_err(|e| e.to_string())?;

    Ok(checkpoints
        .into_iter()
        .map(|cp| CheckpointInfo {
            checkpoint_id: cp.checkpoint_id.as_str().to_string(),
            checkpoint_name: cp.checkpoint_name,
            checkpoint_created: format_timestamp(cp.checkpoint_timestamp),
            checkpoint_user: cp.checkpoint_username,
        })
        .collect())
}

/// Generates compliance reports for the specified frameworks.
///
/// Takes a list of framework names and returns compliance reports.
#[tauri::command]
pub async fn generate_compliance_report(
    frameworks: Vec<String>,
) -> Result<Vec<ComplianceReport>, String> {
    // First run a scan to get findings
    let ctx = Context::new();
    let registry = create_plugin_registry();

    let mut all_findings = Vec::new();
    let plugin_list = registry.list().map_err(|e| e.to_string())?;

    for metadata in plugin_list {
        if let Ok(Some(plugin)) = registry.get(&metadata.plugin_id) {
            if let Ok(result) = plugin.scan(&ctx).await {
                all_findings.extend(result.scan_findings);
            }
        }
    }

    // Parse framework names into ComplianceFramework enum
    let parsed_frameworks: Vec<ComplianceFramework> = frameworks
        .iter()
        .filter_map(|f| match f.to_uppercase().as_str() {
            "CIS" => Some(ComplianceFramework::CIS),
            "STIG" => Some(ComplianceFramework::STIG),
            "NIST" => Some(ComplianceFramework::NIST),
            "PCIDSS" | "PCI-DSS" | "PCI" => Some(ComplianceFramework::PCIDSS),
            "HIPAA" => Some(ComplianceFramework::HIPAA),
            "GDPR" => Some(ComplianceFramework::GDPR),
            _ => None,
        })
        .collect();

    // Create report config with custom frameworks
    let config = ReportConfig {
        scenario: Scenario::Custom(parsed_frameworks),
        formats: vec![OutputFormat::Text],
        output_dir: None,
    };

    // Generate reports
    let generator = ReportGenerator::new(config);
    let reports = generator.generate(&all_findings);

    Ok(reports)
}

/// Retrieves the most recent scan results from the database.
///
/// Used to restore GUI state on app startup or page refresh.
/// Returns None if no completed scans exist.
#[tauri::command]
pub async fn get_latest_scan() -> Result<Option<Vec<ScanResult>>, String> {
    let history_manager = create_scan_history_manager().await?;

    match history_manager.get_latest_scan().await {
        Ok(Some((_, results))) => Ok(Some(results)),
        Ok(None) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
